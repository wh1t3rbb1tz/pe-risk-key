"""Tests for pe_risk_key.engine.narrative (mocked model). No network."""

import copy

import pytest

import pe_risk_key.engine.narrative as narrative_module
from pe_risk_key.engine.narrative import (
    generate_narrative,
    render_ic_memo,
    validate_narrative,
)


class _ScriptedNarrativeClient:
    outputs: list = []
    calls: list = []

    def __init__(self, role, mode="standard", **kwargs):
        assert role == "narrative", role
        self.total_usage = {
            "prompt_tokens": 200,
            "completion_tokens": 50,
            "cached_tokens": 0,
        }

    def chat_json(
        self, messages, *, schema, schema_name, reasoning_effort=None
    ):
        type(self).calls.append(
            {"messages": messages, "schema_name": schema_name}
        )
        assert reasoning_effort == "medium"
        return copy.deepcopy(type(self).outputs.pop(0))


@pytest.fixture
def narrative_env(monkeypatch):
    _ScriptedNarrativeClient.outputs = []
    _ScriptedNarrativeClient.calls = []
    monkeypatch.setattr(
        narrative_module, "ModelClient", _ScriptedNarrativeClient
    )
    return _ScriptedNarrativeClient


def _payload():
    return {
        "target": {"name": "Acme", "domain": "acme.example"},
        "overall": {
            "score": 72.5,
            "rating": "C",
            "confidence": "medium",
            "deal_signal": "proceed_with_conditions",
            "rating_caps_applied": ["CAP-CRIT"],
        },
        "function_scores": [
            {"function": "PR", "score": 60.0, "assessed": True}
        ],
        "findings": [
            {
                "finding_id": "F-001",
                "title": "DMARC not enforced",
                "severity": "high",
                "confidence": "high",
                "deal_impact": "Spoofing risk.",
                "evidence": [{"excerpt": "No DMARC record published."}],
                "remediation": {
                    "summary": "Enforce DMARC.",
                    "cost_low_usd": 8000,
                    "cost_high_usd": 30000,
                    "effort_weeks": 8,
                },
            }
        ],
        "contradictions": [
            {
                "contradiction_id": "C-001",
                "claim": {"text": "DMARC is enforced."},
                "verdict": "contradicted",
                "severity": "high",
                "evidence_refs": ["F-001"],
                "explanation": "Finding contradicts the claim.",
            }
        ],
        "remediation_plan": {
            "items": [
                {
                    "action": "Enforce DMARC.",
                    "finding_ids": ["F-001"],
                    "window": "days_31_60",
                    "cost_low_usd": 8000,
                    "cost_high_usd": 30000,
                    "owner_role": "Security Engineering",
                }
            ],
            "total_cost_low_usd": 8000,
            "total_cost_high_usd": 30000,
        },
        "soc2_summary": None,
        "limitations": ["No SOC 2 report provided."],
    }


def _good_output():
    return {
        "executive_summary": (
            "Rating C reflects one critical gap [F-001]. "
            "The score is 72.5. Management statements conflict "
            "with evidence [C-001]."
        ),
        "key_questions_for_management": [
            f"Question {index} about controls [F-001]?" for index in range(5)
        ],
        "deal_recommendations": [
            {
                "type": "closing_condition",
                "text": "Require DMARC enforcement before close.",
                "basis_ids": ["F-001"],
            }
        ],
    }


def test_uncited_risk_sentence_triggers_regeneration(narrative_env):
    bad = _good_output()
    bad["executive_summary"] = "There is a critical security gap."
    narrative_env.outputs = [bad, _good_output()]
    result = generate_narrative(_payload())
    assert result["valid"] is True
    assert result["regenerated"] is True
    assert len(narrative_env.calls) == 2
    assert "Rating C reflects" in result["narrative"]["executive_summary"]
    retry_messages = narrative_env.calls[1]["messages"]
    assert "uncited risk sentence" in retry_messages[-1]["content"]


def test_unknown_id_fails_twice_and_is_kept(narrative_env):
    bad = _good_output()
    bad["executive_summary"] = "A serious gap remains [F-999]."
    narrative_env.outputs = [bad, bad]
    result = generate_narrative(_payload())
    assert result["valid"] is False
    assert result["regenerated"] is True
    assert any("F-999" in e for e in result["validation_errors"])
    assert "[F-999]" in result["narrative"]["executive_summary"]


def test_number_not_in_input_is_flagged(narrative_env):
    bad = _good_output()
    bad["executive_summary"] = "Costs run to 50000 with a gap [F-001]."
    narrative_env.outputs = [bad, bad]
    result = generate_narrative(_payload())
    assert result["valid"] is False
    assert any("50000" in e for e in result["validation_errors"])


def test_validate_accepts_grounded_numbers():
    errors = validate_narrative(
        _good_output(),
        finding_ids={"F-001"},
        contradiction_ids={"C-001"},
        input_numbers={"72.5", "8000", "30000", "001"},
    )
    assert errors == []


def test_memo_renders(narrative_env):
    narrative_env.outputs = [_good_output()]
    result = generate_narrative(_payload())
    digest = {
        "target": {"name": "Acme", "domain": "acme.example"},
        "overall": {
            "score": 72.5,
            "rating": "C",
            "confidence": "medium",
            "deal_signal": "proceed_with_conditions",
            "rating_caps_applied": ["CAP-CRIT"],
        },
        "findings": _payload()["findings"],
        "contradictions": _payload()["contradictions"],
        "narrative": result["narrative"],
        "deal_recommendations": result["deal_recommendations"],
        "remediation_plan": {
            "items": [
                {
                    "action": "Enforce DMARC.",
                    "finding_ids": ["F-001"],
                    "window": "days_31_60",
                    "cost_low_usd": 8000,
                    "cost_high_usd": 30000,
                    "owner_role": "Security Engineering",
                },
                {
                    "action": "Later hardening.",
                    "finding_ids": ["F-002"],
                    "window": "post_100",
                    "cost_low_usd": 1000,
                    "cost_high_usd": 2000,
                    "owner_role": "IT Ops",
                },
            ]
        },
        "limitations": ["No SOC 2 report provided."],
    }
    memo = render_ic_memo(digest)
    assert "# IC Memo: Acme (acme.example)" in memo
    assert "## Executive summary" in memo
    assert "Rating C reflects" in memo
    assert "| F-001 | high | DMARC not enforced |" in memo
    assert "C-001 [contradicted/high]" in memo
    assert "## 100-day plan" in memo
    assert "Days 31-60" in memo
    assert "Later hardening." not in memo
    assert "[closing_condition]" in memo
    assert "No SOC 2 report provided." in memo
