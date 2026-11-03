"""Interview pipeline (SPEC §4.3): transcribe, extract, verify claims.

``transcribe_interview`` calls Muse Voice Transcribe with diarization
and normalizes the response (per
https://dev.meta.ai/docs/speech-to-text: ``turns`` carry ``turnId``,
``startMs``, ``endMs``, ``transcript``, and ``speaker`` labels such as
A/B; total length is ``audioDurationMs``). ``extract_claims`` has Muse
Wonder pull verbatim security claims from target-side speakers, then
code verifies each claim against its turn with the SOC 2 quote
normalizer. Not yet wired into the orchestrator.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from pe_risk_key.analyzers.schemas import interview_claims_schema
from pe_risk_key.analyzers.soc2 import normalize_quote, verify_quote
from pe_risk_key.providers import (
    WONDER_USD_PER_MTOK,
    Mode,
    ModelClient,
    estimate_token_cost_usd,
    estimate_transcription_cost_usd,
)

ROOT = Path(__file__).resolve().parents[3]
CACHE_DIR = ROOT / ".cache" / "transcripts"

MAX_CLAIM_CHARS = 500

CLAIM_SYSTEM_PROMPT = """You extract security claims from an interview transcript. Rules:
1. A claim is a factual assertion by a target-side speaker about the company's security controls, incidents, or assurance.
2. Questions from the diligence lead are never claims. Do not extract them.
3. Only extract claims spoken by one of the target speakers listed with the transcript.
4. Quote the speaker verbatim for every text field; never paraphrase or invent text. Keep text under 500 characters.
5. claim_type: control_exists (a control is in place), control_coverage (scope or frequency of a control), incident_history (a past incident or its handling), third_party_assurance (audits, reports, vendor assurance), process_maturity (how run or mature a process is)."""


def _format_timestamp(seconds: float) -> str:
    """Turn-start seconds as MM:SS (matches the digest timestamp pattern)."""
    total = max(0, int(seconds))
    return f"{total // 60:02d}:{total % 60:02d}"


def _parse_segments(response: dict[str, Any]) -> list[dict[str, Any]]:
    """Raw diarized turns in response order; raises on a malformed turn."""
    segments = []
    turns = response.get("turns", [])
    if not isinstance(turns, list):
        raise ValueError("Transcription response has no turns list.")
    for index, raw in enumerate(turns):
        if not isinstance(raw, dict):
            raise ValueError(f"Turn {index} is not an object: {raw!r}.")
        label = raw.get("speaker")
        start_ms = raw.get("startMs", 0)
        text = raw.get("transcript")
        if not isinstance(label, str) or not label.strip():
            raise ValueError(f"Turn {index} has no speaker label: {raw!r}.")
        if not isinstance(start_ms, (int, float)):
            raise ValueError(f"Turn {index} has no startMs: {raw!r}.")
        if not isinstance(text, str) or not text.strip():
            raise ValueError(f"Turn {index} has no transcript: {raw!r}.")
        segments.append(
            {
                "speaker_label": label.strip(),
                "start": _format_timestamp(start_ms / 1000),
                "text": text.strip(),
            }
        )
    return segments


def _duration_seconds(response: dict[str, Any]) -> float:
    """Audio length from audioDurationMs, else the last turn end."""
    total_ms = response.get("audioDurationMs")
    if isinstance(total_ms, (int, float)):
        return max(0.0, float(total_ms) / 1000)
    ends = [
        raw.get("endMs")
        for raw in response.get("turns", [])
        if isinstance(raw, dict) and isinstance(raw.get("endMs"), (int, float))
    ]
    return max(0.0, max(ends) / 1000) if ends else 0.0


def _apply_speaker_names(
    segments: list[dict[str, Any]], speaker_names: list[str] | None
) -> list[dict[str, Any]]:
    """Map names onto diarized labels in order of first appearance."""
    names = list(speaker_names or [])
    label_order: list[str] = []
    for segment in segments:
        if segment["speaker_label"] not in label_order:
            label_order.append(segment["speaker_label"])
    mapping = {
        label: (names[index] if index < len(names) else None)
        for index, label in enumerate(label_order)
    }
    return [
        {
            "turn_index": index,
            "speaker_label": segment["speaker_label"],
            "speaker_name": mapping[segment["speaker_label"]],
            "start": segment["start"],
            "text": segment["text"],
        }
        for index, segment in enumerate(segments)
    ]


def transcribe_interview(
    path: str | Path,
    interview_id: str,
    speaker_names: list[str] | None = None,
    mode: Mode = "standard",
) -> dict[str, Any]:
    """Transcribe audio with diarization; cache by file sha256.

    Returns ``{interview_id, sha256, duration_seconds, turns, usage,
    estimated_cost_usd, cached}``. ``turns`` holds ``{turn_index,
    speaker_label, speaker_name, start, text}`` with ``start`` as MM:SS.
    """
    file_path = Path(path)
    sha256 = hashlib.sha256(file_path.read_bytes()).hexdigest()
    cache_path = CACHE_DIR / f"{sha256}.json"
    if cache_path.exists():
        cached = json.loads(cache_path.read_text(encoding="utf-8"))
        return {
            "interview_id": interview_id,
            "sha256": sha256,
            "duration_seconds": cached["duration_seconds"],
            "turns": _apply_speaker_names(cached["segments"], speaker_names),
            "usage": {"audio_hours": 0.0},
            "estimated_cost_usd": 0.0,
            "cached": True,
        }
    client = ModelClient(role="transcription", mode=mode)
    response = client.transcribe(file_path)
    segments = _parse_segments(response)
    duration = _duration_seconds(response)
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    cache_path.write_text(
        json.dumps(
            {"duration_seconds": duration, "segments": segments}, indent=2
        ),
        encoding="utf-8",
    )
    hours = duration / 3600
    return {
        "interview_id": interview_id,
        "sha256": sha256,
        "duration_seconds": duration,
        "turns": _apply_speaker_names(segments, speaker_names),
        "usage": {"audio_hours": round(hours, 6)},
        "estimated_cost_usd": estimate_transcription_cost_usd(duration),
        "cached": False,
    }


def extract_claims(
    transcript: dict[str, Any],
    target_speakers: list[str],
    mode: Mode = "standard",
) -> dict[str, Any]:
    """Extract verbatim target-side claims; verify each against its turn.

    Returns ``{claims, dropped_unquoted, dropped_not_target, usage,
    estimated_cost_usd}``. ``claims`` holds ``{claim_index, speaker,
    turn_index, timestamp, text, claim_type}`` with the timestamp taken
    from the turn.
    """
    turns = transcript.get("turns", [])
    targets = list(target_speakers)
    lines = [
        f"[{turn['start']}] "
        f"{turn.get('speaker_name') or turn['speaker_label']}: "
        f"{turn['text']}"
        for turn in turns
    ]
    client = ModelClient(role="claim_extraction", mode=mode)
    result = client.chat_json(
        [
            {"role": "system", "content": CLAIM_SYSTEM_PROMPT},
            {
                "role": "user",
                "content": (
                    f"Target speakers: {', '.join(targets)}.\n"
                    f"Transcript:\n" + "\n".join(lines)
                ),
            },
        ],
        schema=interview_claims_schema(),
        schema_name="interview_claims",
        reasoning_effort="medium",
    )
    claims: list[dict[str, Any]] = []
    dropped_unquoted: list[dict[str, Any]] = []
    dropped_not_target: list[dict[str, Any]] = []
    for raw in result.get("claims", []):
        index = raw.get("turn_index")
        if (
            not isinstance(raw, dict)
            or not isinstance(index, int)
            or isinstance(index, bool)
            or not 0 <= index < len(turns)
        ):
            dropped_not_target.append(
                {"reason": "bad_turn_index", "claim": raw}
            )
            continue
        turn = turns[index]
        speaker = turn.get("speaker_name")
        if speaker not in targets:
            dropped_not_target.append(
                {
                    "reason": "not_target_speaker",
                    "turn_index": index,
                    "speaker": speaker,
                }
            )
            continue
        verified, diagnostics = verify_quote(
            raw.get("text"),
            normalize_quote(turn["text"]),
            max_chars=MAX_CLAIM_CHARS,
        )
        if verified is None:
            dropped_unquoted.append(
                {
                    "turn_index": index,
                    "speaker": speaker,
                    "text": raw.get("text"),
                    **diagnostics,
                }
            )
            continue
        claims.append(
            {
                "claim_index": len(claims),
                "speaker": speaker,
                "turn_index": index,
                "timestamp": turn["start"],
                "text": verified[:MAX_CLAIM_CHARS],
                "claim_type": raw.get("claim_type"),
            }
        )
    usage = dict(client.total_usage)
    return {
        "claims": claims,
        "dropped_unquoted": dropped_unquoted,
        "dropped_not_target": dropped_not_target,
        "usage": usage,
        "estimated_cost_usd": estimate_token_cost_usd(
            usage, WONDER_USD_PER_MTOK
        ),
    }
