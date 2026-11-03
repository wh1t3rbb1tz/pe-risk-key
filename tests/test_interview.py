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
        item_props = schema["properties"]["claims"]["items"]["properties"]
        assert set(item_props) == {"text", "claim_type"}
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


def _claim(text, claim_type="control_exists", **extra):
    return {"text": text, "claim_type": claim_type, **extra}


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
    assert second["usage"] == {
        "audio_hours": first["usage"]["audio_hours"],
        "cached": True,
        "first_run_cost_usd": first["estimated_cost_usd"],
    }


def test_questions_from_lead_are_never_claims(interview_env):
    transcript = transcribe_interview(
        interview_env, "iv_1", speaker_names=[LEAD, CTO]
    )
    _ScriptedInterviewClient.extraction = {
        "claims": [
            _claim("We enforce MFA for all administrative access to production."),
            _claim("What controls protect production data?"),
        ]
    }
    result = extract_claims(transcript, [CTO])
    assert [claim["claim_index"] for claim in result["claims"]] == [0]
    assert result["claims"][0]["speaker"] == CTO
    assert result["claims"][0]["turn_index"] == 1
    assert result["claims"][0]["timestamp"] == "00:05"
    assert result["dropped_not_target"] == [
        {
            "reason": "not_target_speaker",
            "turn_index": 0,
            "speaker": LEAD,
            "text": "What controls protect production data?",
        }
    ]
    assert result["dropped_unquoted"] == []


def test_fabricated_claim_dropped(interview_env):
    transcript = transcribe_interview(
        interview_env, "iv_1", speaker_names=[LEAD, CTO]
    )
    _ScriptedInterviewClient.extraction = {
        "claims": [
            _claim("We encrypt every database with AES-256."),
        ]
    }
    result = extract_claims(transcript, [CTO])
    assert result["claims"] == []
    assert result["dropped_not_target"] == []
    (drop,) = result["dropped_unquoted"]
    assert drop["reason"] == "unquoted"
    assert drop["text"] == "We encrypt every database with AES-256."
    assert drop["similarity_ratio"] >= 0.0


def test_wrong_model_turn_index_lands_on_located_turn(interview_env):
    transcript = transcribe_interview(
        interview_env, "iv_1", speaker_names=[LEAD, CTO]
    )
    _ScriptedInterviewClient.extraction = {
        "claims": [
            _claim(
                "We review access quarterly and revoke terminated "
                "employees within one business day.",
                turn_index=0,
                speaker=LEAD,
            )
        ]
    }
    result = extract_claims(transcript, [CTO])
    (claim,) = result["claims"]
    assert claim["turn_index"] == 3
    assert claim["timestamp"] == "00:30"
    assert claim["speaker"] == CTO
    assert result["dropped_unquoted"] == []
    assert result["dropped_not_target"] == []
    user_content = _ScriptedInterviewClient.chat_calls[0]["messages"][1][
        "content"
    ]
    assert "[turn 3 | Dana Reyes (CTO) | 00:30]:" in user_content
    assert "[turn 0 | Diligence Lead | 00:00]:" in user_content


def test_claim_timestamp_format_and_claim_type_enum(interview_env):
    transcript = transcribe_interview(
        interview_env, "iv_1", speaker_names=[LEAD, CTO]
    )
    for turn in transcript["turns"]:
        assert TIMESTAMP_RE.match(turn["start"]), turn["start"]
    _ScriptedInterviewClient.extraction = {
        "claims": [
            _claim(
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


# Real turn shape observed from live Voice Transcribe output: empty
# transcript and no speaker label.
REAL_EMPTY_TURN = {
    "turnId": 4,
    "startMs": 30220,
    "endMs": 30380,
    "transcript": "",
}


def _response_with(turns):
    return {
        "sessionId": "live",
        "transcript": "Full transcript.",
        "audioDurationMs": 65000,
        "turns": turns,
    }


def test_real_empty_turn_shape_skipped(interview_env):
    _ScriptedInterviewClient.transcribe_response = _response_with(
        [
            {
                "turnId": 1,
                "startMs": 0,
                "endMs": 5000,
                "transcript": "Hello.",
                "speaker": "A",
            },
            dict(REAL_EMPTY_TURN),
            {
                "turnId": 5,
                "startMs": 31000,
                "endMs": 35000,
                "transcript": "Still here.",
                "speaker": "A",
            },
        ]
    )
    transcript = transcribe_interview(
        interview_env, "iv_live", speaker_names=[CTO]
    )
    assert transcript["skipped_empty"] == 1
    assert transcript["speaker_inferred"] == 0
    # Consecutive A turns merge across the skipped empty turn.
    (turn,) = transcript["turns"]
    assert turn["text"] == "Hello. Still here."
    assert turn["start"] == "00:00"
    assert turn["end"] == "00:35"


def test_missing_label_inherited_from_previous_turn(interview_env):
    _ScriptedInterviewClient.transcribe_response = _response_with(
        [
            {
                "turnId": 1,
                "startMs": 0,
                "endMs": 5000,
                "transcript": "A question?",
                "speaker": "B",
            },
            {
                "turnId": 2,
                "startMs": 5000,
                "endMs": 9000,
                "transcript": "Another question, no label.",
            },
        ]
    )
    transcript = transcribe_interview(
        interview_env, "iv_live", speaker_names=[LEAD]
    )
    assert transcript["skipped_empty"] == 0
    assert transcript["speaker_inferred"] == 1
    (turn,) = transcript["turns"]
    assert turn["speaker_label"] == "B"
    assert turn["speaker_name"] == LEAD
    assert turn["text"] == "A question? Another question, no label."


def test_first_turn_without_label_is_unknown(interview_env):
    _ScriptedInterviewClient.transcribe_response = _response_with(
        [
            {
                "turnId": 1,
                "startMs": 0,
                "endMs": 5000,
                "transcript": "No label on the first turn.",
            },
        ]
    )
    transcript = transcribe_interview(interview_env, "iv_live")
    assert transcript["speaker_inferred"] == 1
    (turn,) = transcript["turns"]
    assert turn["speaker_label"] == "unknown"
    assert turn["speaker_name"] is None


def test_consecutive_same_speaker_turns_merge(interview_env):
    _ScriptedInterviewClient.transcribe_response = _response_with(
        [
            {
                "turnId": 1,
                "startMs": 0,
                "endMs": 5000,
                "transcript": "First part.",
                "speaker": "A",
            },
            {
                "turnId": 2,
                "startMs": 5000,
                "endMs": 65000,
                "transcript": "Second part.",
                "speaker": "A",
            },
            {
                "turnId": 3,
                "startMs": 65000,
                "endMs": 70000,
                "transcript": "Another speaker.",
                "speaker": "B",
            },
        ]
    )
    transcript = transcribe_interview(
        interview_env, "iv_live", speaker_names=[CTO, LEAD]
    )
    assert [turn["text"] for turn in transcript["turns"]] == [
        "First part. Second part.",
        "Another speaker.",
    ]
    assert transcript["turns"][0]["start"] == "00:00"
    assert transcript["turns"][0]["end"] == "01:05"
    assert transcript["turns"][1]["start"] == "01:05"


def test_raw_response_saved_before_parsing(interview_env):
    transcript = transcribe_interview(
        interview_env, "iv_live", speaker_names=[LEAD, CTO]
    )
    raw_path = (
        interview_module.CACHE_DIR / f"{transcript['sha256']}.raw.json"
    )
    raw = json.loads(raw_path.read_text(encoding="utf-8"))
    assert raw["audioDurationMs"] == 65000
    assert len(raw["turns"]) == 4


def test_claim_carries_preceding_lead_question(interview_env):
    transcript = transcribe_interview(
        interview_env, "iv_1", speaker_names=[LEAD, CTO]
    )
    _ScriptedInterviewClient.extraction = {
        "claims": [
            _claim("We enforce MFA for all administrative access to production."),
            _claim(
                "We review access quarterly and revoke terminated "
                "employees within one business day."
            ),
        ]
    }
    result = extract_claims(transcript, [CTO])
    assert [c["context_question"] for c in result["claims"]] == [
        "What controls protect production data?",
        "How often are access reviews performed?",
    ]


def test_claim_in_first_turn_has_no_context_question(interview_env):
    transcript = transcribe_interview(
        interview_env, "iv_1", speaker_names=[LEAD, CTO]
    )
    _ScriptedInterviewClient.extraction = {
        "claims": [_claim("What controls protect production data?")]
    }
    result = extract_claims(transcript, [LEAD])
    (claim,) = result["claims"]
    assert claim["turn_index"] == 0
    assert claim["context_question"] is None
