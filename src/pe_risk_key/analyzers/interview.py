"""Interview pipeline (SPEC §4.3): transcribe, extract, verify claims.

``transcribe_interview`` calls Muse Voice Transcribe with diarization
and normalizes the response (per
https://dev.meta.ai/docs/speech-to-text: ``turns`` carry ``turnId``,
``startMs``, ``endMs``, ``transcript``, and ``speaker`` labels such as
A/B; total length is ``audioDurationMs``). Parsing is tolerant: empty
turns are skipped, a labelless turn inherits the previous label, and
consecutive same-speaker turns merge. ``extract_claims`` has Muse
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
4. Copy claim text verbatim from a single turn; never paraphrase or invent text. Keep text under 500 characters. Split a multi-sentence answer into separate claims only when each sentence is a distinct assertion.
5. claim_type: control_exists (a control is in place), control_coverage (scope or frequency of a control), incident_history (a past incident or its handling), third_party_assurance (audits, reports, vendor assurance), process_maturity (how run or mature a process is).
6. Transcript lines are labeled [turn N | speaker | MM:SS]; use them for context only.
7. Extract one claim per distinct control or topic per answer; keep a multi-sentence answer about the same topic as one claim. Statements about the availability of assurance documents (bridge letters, pen test reports, SOC reports) are claims of type third_party_assurance."""


def _locate_claim(
    text: Any, turns: list[dict[str, Any]]
) -> tuple[int, dict[str, Any], str] | None:
    """First turn whose text contains the claim: (index, turn, verified)."""
    for turn in turns:
        verified, _ = verify_quote(
            text,
            normalize_quote(turn["text"]),
            max_chars=MAX_CLAIM_CHARS,
        )
        if verified is not None:
            return turn["turn_index"], turn, verified
    return None


def _format_timestamp(seconds: float) -> str:
    """Turn-start seconds as MM:SS (matches the digest timestamp pattern)."""
    total = max(0, int(seconds))
    return f"{total // 60:02d}:{total % 60:02d}"


def _parse_segments(
    response: dict[str, Any],
) -> tuple[list[dict[str, Any]], dict[str, int]]:
    """Normalize diarized turns; tolerant of real output.

    Skips empty transcripts, lets a labelless turn inherit the previous
    kept label ("unknown" when first), and merges consecutive turns from
    the same speaker. Returns (segments, diagnostics).
    """
    segments: list[dict[str, Any]] = []
    skipped_empty = 0
    speaker_inferred = 0
    turns = response.get("turns", [])
    if not isinstance(turns, list):
        raise ValueError("Transcription response has no turns list.")
    for index, raw in enumerate(turns):
        if not isinstance(raw, dict):
            raise ValueError(f"Turn {index} is not an object: {raw!r}.")
        text = raw.get("transcript", "")
        if not isinstance(text, str):
            raise ValueError(f"Turn {index} has no transcript text: {raw!r}.")
        if not text.strip():
            skipped_empty += 1
            continue
        label = raw.get("speaker")
        if not isinstance(label, str) or not label.strip():
            label = segments[-1]["speaker_label"] if segments else "unknown"
            speaker_inferred += 1
        else:
            label = label.strip()
        start_ms = raw.get("startMs", 0)
        end_ms = raw.get("endMs", start_ms)
        if not isinstance(start_ms, (int, float)) or not isinstance(
            end_ms, (int, float)
        ):
            raise ValueError(f"Turn {index} has bad timestamps: {raw!r}.")
        if segments and segments[-1]["speaker_label"] == label:
            segments[-1]["text"] += " " + text.strip()
            segments[-1]["end"] = _format_timestamp(end_ms / 1000)
        else:
            segments.append(
                {
                    "speaker_label": label,
                    "start": _format_timestamp(start_ms / 1000),
                    "end": _format_timestamp(end_ms / 1000),
                    "text": text.strip(),
                }
            )
    return segments, {
        "skipped_empty": skipped_empty,
        "speaker_inferred": speaker_inferred,
    }


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
            "end": segment.get("end", segment["start"]),
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
    estimated_cost_usd, cached, skipped_empty, speaker_inferred}``.
    ``turns`` holds ``{turn_index, speaker_label, speaker_name, start,
    end, text}`` with ``start``/``end`` as MM:SS. The raw API response
    is saved to ``<sha256>.raw.json`` beside the cache entry before
    parsing, for inspection.
    """
    file_path = Path(path)
    sha256 = hashlib.sha256(file_path.read_bytes()).hexdigest()
    cache_path = CACHE_DIR / f"{sha256}.json"
    if cache_path.exists():
        cached = json.loads(cache_path.read_text(encoding="utf-8"))
        duration = cached["duration_seconds"]
        return {
            "interview_id": interview_id,
            "sha256": sha256,
            "duration_seconds": duration,
            "turns": _apply_speaker_names(cached["segments"], speaker_names),
            "usage": {
                # Entries cached before usage was stored derive it
                # from the duration so the cost line stays truthful.
                "audio_hours": cached.get(
                    "audio_hours", round(duration / 3600, 6)
                ),
                "cached": True,
                "first_run_cost_usd": cached.get(
                    "estimated_cost_usd",
                    estimate_transcription_cost_usd(duration),
                ),
            },
            "estimated_cost_usd": 0.0,
            "cached": True,
            "skipped_empty": cached.get("skipped_empty", 0),
            "speaker_inferred": cached.get("speaker_inferred", 0),
        }
    client = ModelClient(role="transcription", mode=mode)
    response = client.transcribe(file_path)
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    (CACHE_DIR / f"{sha256}.raw.json").write_text(
        json.dumps(response, indent=2), encoding="utf-8"
    )
    segments, diagnostics = _parse_segments(response)
    duration = _duration_seconds(response)
    hours = duration / 3600
    cache_path.write_text(
        json.dumps(
            {
                "duration_seconds": duration,
                "segments": segments,
                "audio_hours": round(hours, 6),
                "estimated_cost_usd": estimate_transcription_cost_usd(
                    duration
                ),
                **diagnostics,
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    return {
        "interview_id": interview_id,
        "sha256": sha256,
        "duration_seconds": duration,
        "turns": _apply_speaker_names(segments, speaker_names),
        "usage": {"audio_hours": round(hours, 6)},
        "estimated_cost_usd": estimate_transcription_cost_usd(duration),
        "cached": False,
        **diagnostics,
    }


def extract_claims(
    transcript: dict[str, Any],
    target_speakers: list[str],
    mode: Mode = "standard",
) -> dict[str, Any]:
    """Extract verbatim target-side claims; locate each turn in code.

    The model returns only text and claim_type. Each claim is searched
    across target-speaker turns; turn_index, timestamp, and speaker come
    from the containing turn. Claims found only in non-target turns drop
    as not_target_speaker; claims found nowhere drop as unquoted.

    Returns ``{claims, dropped_unquoted, dropped_not_target, usage,
    estimated_cost_usd}``. ``claims`` holds ``{claim_index, speaker,
    turn_index, timestamp, text, claim_type, context_question}`` where
    context_question is the nearest preceding non-target turn's text
    (the prompting question), or None. It stays in run artifacts; the
    digest claim carries only the four schema fields.
    """
    turns = transcript.get("turns", [])
    targets = list(target_speakers)
    lines = [
        f"[turn {turn['turn_index']} | "
        f"{turn.get('speaker_name') or turn['speaker_label']} | "
        f"{turn['start']}]: {turn['text']}"
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
    target_turns = [
        turn for turn in turns if turn.get("speaker_name") in targets
    ]
    other_turns = [
        turn for turn in turns if turn.get("speaker_name") not in targets
    ]
    target_text = " ".join(
        normalize_quote(turn["text"]) for turn in target_turns
    )
    for raw in result.get("claims", []):
        text = raw.get("text") if isinstance(raw, dict) else None
        claim_type = raw.get("claim_type") if isinstance(raw, dict) else None
        found = _locate_claim(text, target_turns)
        if found is not None:
            index, turn, verified = found
            question = None
            for back in range(index - 1, -1, -1):
                if turns[back].get("speaker_name") not in targets:
                    question = turns[back]["text"]
                    break
            claims.append(
                {
                    "claim_index": len(claims),
                    "speaker": turn.get("speaker_name"),
                    "turn_index": index,
                    "timestamp": turn["start"],
                    "text": verified,
                    "claim_type": claim_type,
                    "context_question": question,
                }
            )
            continue
        other = _locate_claim(text, other_turns)
        if other is not None:
            index, turn, verified = other
            dropped_not_target.append(
                {
                    "reason": "not_target_speaker",
                    "turn_index": index,
                    "speaker": turn.get("speaker_name"),
                    "text": verified,
                }
            )
            continue
        _, diagnostics = verify_quote(
            text, target_text, max_chars=MAX_CLAIM_CHARS
        )
        dropped_unquoted.append(
            {"text": text, "reason": "unquoted", **diagnostics}
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
