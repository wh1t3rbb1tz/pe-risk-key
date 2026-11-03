"""Tests for pe_risk_key.analyzers.interview (mocked model). No network."""

import copy
import json
import re
import wave
from pathlib import Path

import pytest

import pe_risk_key.analyzers.interview as interview_module
from pe_risk_key.analyzers.interview import extract_claims, transcribe_interview

TIMESTAMP_RE = re.compile(r"^[0-9]{2}:[0-9]{2}$")

LEAD = "Diligence Lead"
CTO = "Dana Reyes (CTO)"

TRANSCRIBE_RESPONSE = {
    "sessionId": "abc123",
    "transcript": "Full transcript.",
    "audioDurationMs": 65000,
    "turns": [
        {
            "turnId": 1,
            "startMs": 0,
            "endMs": 5000,
            "transcript": "What controls protect production data?",
            "speaker": "B",
        },
        {
            "turnId": 2,
            "startMs": 5700,
            "endMs": 20000,
            "transcript": (
                "We enforce MFA for all administrative access "
                "to production."
            ),
            "speaker": "A",
        },
        {
            "turnId": 3,
            "startMs": 20700,
            "endMs": 30000,
            "transcript": "How often are access reviews performed?",
            "speaker": "B",
        },
        {
            "turnId": 4,
            "startMs": 30500,
            "endMs": 65000,
            "transcript": (
                "We review access quarterly and revoke terminated "
                "employees within one business day."
            ),
            "speaker": "A",
        },
    ],
}


class _ScriptedInterviewClient:
    transcribe_response = {}
    transcribe_calls: list = []
    extraction = {}
    chat_calls: list = []

    def __init__(self, role, mode="standard", **kwargs):
        assert role in ("transcription", "claim_extraction"), role
        self.total_usage = {
            "prompt_tokens": 500,
            "completion_tokens": 100,
            "cached_tokens": 0,
        }

    def transcribe(self, audio, **kwargs):
        type(self).transcribe_calls.append(audio)
        return copy.deepcopy(type(self).transcribe_response)

    def chat_json(
        self, messages, *, schema, schema_name, reasoning_effort=None
    ):
        type(self).chat_calls.append(
            {"messages": messages, "schema_name": schema_name}
        )
        assert "claims" in schema["properties"]
        assert "claim_type" in schema["properties"]["claims"]["items"][
            "properties"
        ]
        return copy.deepcopy(type(self).extraction)


@pytest.fixture
def interview_env(monkeypatch, tmp_path):
    _ScriptedInterviewClient.transcribe_response = TRANSCRIBE_RESPONSE
    _ScriptedInterviewClient.transcribe_calls = []
    _ScriptedInterviewClient.extraction = {}
    _ScriptedInterviewClient.chat_calls = []
    monkeypatch.setattr(
        interview_module, "ModelClient", _ScriptedInterviewClient
    )
    monkeypatch.setattr(
        interview_module, "CACHE_DIR", tmp_path / "transcripts"
    )
    audio = tmp_path / "interview.wav"
    with wave.open(str(audio), "wb") as wav:
        wav.setnchannels(1)
        wav.setsampwidth(2)
        wav.setframerate(16000)
        wav.writeframes(b"\x00\x00" * 16000)
    return audio


def _claim(turn_index, text, claim_type="control_exists", speaker=CTO):
    return {
        "speaker": speaker,
        "turn_index": turn_index,
        "text": text,
        "claim_type": claim_type,
    }


def test_label_to_name_mapping_in_first_appearance_order(interview_env):
    transcript = transcribe_interview(
        interview_env, "iv_1", speaker_names=[LEAD, CTO]
    )
    assert transcript["interview_id"] == "iv_1"
    assert transcript["duration_seconds"] == 65.0
    assert transcript["cached"] is False
    assert [
        (turn["speaker_label"], turn["speaker_name"])
        for turn in transcript["turns"]
    ] == [("B", LEAD), ("A", CTO), ("B", LEAD), ("A", CTO)]
    assert [turn["turn_index"] for turn in transcript["turns"]] == [0, 1, 2, 3]
    assert [turn["start"] for turn in transcript["turns"]] == [
        "00:00",
        "00:05",
        "00:20",
        "00:30",
    ]
    assert transcript["usage"] == {"audio_hours": round(65 / 3600, 6)}
    assert transcript["estimated_cost_usd"] == pytest.approx(65 / 3600 * 0.18)


def test_transcript_cache_hit_makes_no_call(interview_env, monkeypatch):
    first = transcribe_interview(
        interview_env, "iv_1", speaker_names=[LEAD, CTO]
    )
    assert len(_ScriptedInterviewClient.transcribe_calls) == 1
    second = transcribe_interview(
        interview_env, "iv_2", speaker_names=[LEAD, CTO]
    )
    assert len(_ScriptedInterviewClient.transcribe_calls) == 1
    assert second["cached"] is True
    assert second["interview_id"] == "iv_2"
    assert second["turns"] == first["turns"]
    assert second["estimated_cost_usd"] == 0.0


def test_questions_from_lead_are_never_claims(interview_env):
    transcript = transcribe_interview(
        interview_env, "iv_1", speaker_names=[LEAD, CTO]
    )
    _ScriptedInterviewClient.extraction = {
        "claims": [
            _claim(1, "We enforce MFA for all administrative access to production."),
            _claim(0, "What controls protect production data?", speaker=LEAD),
        ]
    }
    result = extract_claims(transcript, [CTO])
    assert [claim["claim_index"] for claim in result["claims"]] == [0]
    assert result["claims"][0]["speaker"] == CTO
    assert result["claims"][0]["turn_index"] == 1
    assert result["claims"][0]["timestamp"] == "00:05"
    assert result["dropped_not_target"] == [
        {"reason": "not_target_speaker", "turn_index": 0, "speaker": LEAD}
    ]
    assert result["dropped_unquoted"] == []


def test_fabricated_claim_dropped(interview_env):
    transcript = transcribe_interview(
        interview_env, "iv_1", speaker_names=[LEAD, CTO]
    )
    _ScriptedInterviewClient.extraction = {
        "claims": [
            _claim(3, "We encrypt every database with AES-256."),
        ]
    }
    result = extract_claims(transcript, [CTO])
    assert result["claims"] == []
    (drop,) = result["dropped_unquoted"]
    assert drop["turn_index"] == 3
    assert drop["speaker"] == CTO
    assert drop["similarity_ratio"] >= 0.0


def test_claim_timestamp_format_and_claim_type_enum(interview_env):
    transcript = transcribe_interview(
        interview_env, "iv_1", speaker_names=[LEAD, CTO]
    )
    for turn in transcript["turns"]:
        assert TIMESTAMP_RE.match(turn["start"]), turn["start"]
    _ScriptedInterviewClient.extraction = {
        "claims": [
            _claim(
                3,
                "We review access quarterly and revoke terminated "
                "employees within one business day.",
                claim_type="control_coverage",
            )
        ]
    }
    result = extract_claims(transcript, [CTO])
    (claim,) = result["claims"]
    assert claim["timestamp"] == "00:30"
    assert TIMESTAMP_RE.match(claim["timestamp"])
    assert claim["claim_type"] == "control_coverage"
    schema = json.loads(
        (
            Path(__file__).resolve().parents[1] / "digest.schema.json"
        ).read_text(encoding="utf-8")
    )
    enum = schema["$defs"]["contradiction"]["properties"]["claim"][
        "properties"
    ]["claim_type"]["enum"]
    assert claim["claim_type"] in enum
