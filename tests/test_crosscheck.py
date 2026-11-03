"""Tests for pe_risk_key.engine.crosscheck (mocked model). No network."""

import copy

import pytest

import pe_risk_key.engine.crosscheck as crosscheck_module
from pe_risk_key.engine.crosscheck import crosscheck_claims


class _ScriptedCrosscheckClient:
    verdicts: list = []
    calls: list = []

    def __init__(self, role, mode="standard", **kwargs):
        assert role == "crosscheck", role
        self.total_usage = {
            "prompt_tokens": 500,
            "completion_tokens": 100,
            "cached_tokens": 0,
        }

    def chat_json(
        self, messages, *, schema, schema_name, reasoning_effort=None
    ):
        type(self).calls.append(
            {"messages": messages, "schema_name": schema_name}
        )
        assert schema["properties"]["verdicts"]["items"]["properties"][
            "verdict"
        ]["enum"] == ["contradicted", "unsupported", "supported"]
        return {"verdicts": copy.deepcopy(type(self).verdicts)}


@pytest.fixture
def crosscheck_env(monkeypatch):
    _ScriptedCrosscheckClient.verdicts = []
    _ScriptedCrosscheckClient.calls = []
    monkeypatch.setattr(
        crosscheck_module, "ModelClient", _ScriptedCrosscheckClient
    )
    return _ScriptedCrosscheckClient


def _finding(finding_id, severity, evidence_ids):
    return {
        "finding_id": finding_id,
        "title": f"Title of {finding_id}.",
        "severity": severity,
        "evidence": [
            {
                "evidence_id": evidence_id,
                "excerpt": f"Excerpt of {evidence_id}.",
            }
            for evidence_id in evidence_ids
        ],
    }


FINDINGS = [
    _finding("F-001", "high", ["E-001"]),
    _finding("F-002", "critical", ["E-002", "E-003"]),
]

POOL = [
    {
        "evidence_id": evidence_id,
        "source_type": "document",
        "locator": f"locator-{evidence_id}",
        "excerpt": f"Excerpt of {evidence_id}.",
    }
    for evidence_id in ("E-001", "E-002", "E-003", "E-004")
]


def _claim(index, text, claim_type="control_exists"):
    return {
        "claim_index": index,
        "speaker": "Dana Reyes (CTO)",
        "turn_index": index,
        "timestamp": f"00:0{index}",
        "text": text,
        "claim_type": claim_type,
        "context_question": "What about this control?",
    }


def _verdict(index, verdict, refs, explanation="Why."):
    return {
        "claim_index": index,
        "verdict": verdict,
        "evidence_refs": refs,
        "explanation": explanation,
    }


def test_unknown_refs_dropped_and_deduped(crosscheck_env):
    crosscheck_env.verdicts = [
        _verdict(
            0,
            "contradicted",
            ["F-001", "F-999", "E-001", "E-999", "F-001", 42, "XYZ"],
        )
    ]
    (contradiction,) = crosscheck_claims(
        [_claim(0, "DMARC is enforced.")], FINDINGS, POOL
    )["contradictions"]
    assert contradiction["evidence_refs"] == ["F-001", "E-001"]
    assert contradiction["verdict"] == "contradicted"


def test_refless_verdicts_downgrade_to_unsupported(crosscheck_env):
    crosscheck_env.verdicts = [
        _verdict(0, "contradicted", ["F-999"]),
        _verdict(1, "supported", []),
    ]
    contradictions = crosscheck_claims(
        [_claim(0, "First."), _claim(1, "Second.")], FINDINGS, POOL
    )["contradictions"]
    assert [c["verdict"] for c in contradictions] == [
        "unsupported",
        "unsupported",
    ]
    assert contradictions[0]["evidence_refs"] == []


def test_contradicted_severity_is_highest_linked(crosscheck_env):
    crosscheck_env.verdicts = [
        _verdict(0, "contradicted", ["F-001", "E-003"]),
        _verdict(1, "contradicted", ["E-002"]),
    ]
    contradictions = crosscheck_claims(
        [_claim(0, "First."), _claim(1, "Second.")], FINDINGS, POOL
    )["contradictions"]
    assert contradictions[0]["severity"] == "critical"
    assert contradictions[1]["severity"] == "critical"


def test_contradicted_pool_only_ref_is_medium(crosscheck_env):
    crosscheck_env.verdicts = [_verdict(0, "contradicted", ["E-004"])]
    (contradiction,) = crosscheck_claims(
        [_claim(0, "Claim.")], FINDINGS, POOL
    )["contradictions"]
    assert contradiction["verdict"] == "contradicted"
    assert contradiction["severity"] == "medium"


def test_supported_is_info_and_unsupported_scales_by_type(
    crosscheck_env,
):
    crosscheck_env.verdicts = [
        _verdict(0, "supported", ["E-004"]),
        _verdict(1, "unsupported", []),
        _verdict(2, "unsupported", []),
        _verdict(3, "unsupported", []),
    ]
    contradictions = crosscheck_claims(
        [
            _claim(0, "Backups are immutable."),
            _claim(1, "MFA everywhere.", "control_exists"),
            _claim(2, "Never breached.", "incident_history"),
            _claim(3, "Quarterly reviews.", "control_coverage"),
        ],
        FINDINGS,
        POOL,
    )["contradictions"]
    assert [c["severity"] for c in contradictions] == [
        "info",
        "low",
        "medium",
        "medium",
    ]


def test_ids_in_claim_order_with_embedded_claim(crosscheck_env):
    crosscheck_env.verdicts = [
        _verdict(1, "supported", ["E-004"]),
        _verdict(0, "contradicted", ["F-001"]),
    ]
    contradictions = crosscheck_claims(
        [_claim(0, "First claim."), _claim(1, "Second claim.")],
        FINDINGS,
        POOL,
    )["contradictions"]
    assert [c["contradiction_id"] for c in contradictions] == [
        "C-001",
        "C-002",
    ]
    assert contradictions[0]["claim"] == {
        "speaker": "Dana Reyes (CTO)",
        "timestamp": "00:00",
        "text": "First claim.",
        "claim_type": "control_exists",
    }


def test_missing_duplicate_and_ranged_verdicts(crosscheck_env):
    crosscheck_env.verdicts = [
        _verdict(0, "supported", ["E-004"]),
        _verdict(0, "contradicted", ["F-002"]),
        _verdict(9, "contradicted", ["F-002"]),
        "not-a-verdict",
    ]
    contradictions = crosscheck_claims(
        [_claim(0, "First."), _claim(1, "Second.")], FINDINGS, POOL
    )["contradictions"]
    assert contradictions[0]["verdict"] == "supported"
    assert contradictions[1]["verdict"] == "unsupported"
    assert (
        contradictions[1]["explanation"]
        == "No model verdict returned for this claim."
    )


def test_explanation_truncated_and_usage_reported(crosscheck_env):
    crosscheck_env.verdicts = [_verdict(0, "supported", ["E-004"], "x" * 600)]
    result = crosscheck_claims([_claim(0, "Claim.")], FINDINGS, POOL)
    assert result["contradictions"][0]["explanation"] == "x" * 500
    assert result["usage"] == {
        "prompt_tokens": 500,
        "completion_tokens": 100,
        "cached_tokens": 0,
    }
    assert result["estimated_cost_usd"] == pytest.approx(0.004)


def _pool_item(evidence_id, kind=None, locator="locator", excerpt="Excerpt."):
    item = {
        "evidence_id": evidence_id,
        "source_type": "document",
        "locator": locator,
        "excerpt": excerpt,
    }
    if kind is not None:
        item["collector"] = "soc2_analyzer"
        item["evidence_kind"] = kind
    return item


def test_catalog_counts_and_labels_no_exception(crosscheck_env):
    findings = [_finding("F-001", "high", ["E-001"])]
    pool = [
        _pool_item("E-001", excerpt="Outside-in excerpt."),
        _pool_item(
            "E-002",
            "exception",
            "Section 4, CC6.1-01",
            "Exception noted. 4 of 25 reviews were late.",
        ),
        _pool_item(
            "E-003",
            "no_exception",
            "Section 4, A1.2-01",
            "No exceptions noted.",
        ),
        _pool_item(
            "E-004",
            "no_exception",
            "Section 4, CC4.1-01",
            "No exceptions noted. 2 high-severity findings were reported.",
        ),
        _pool_item(
            "E-005",
            "notable",
            "Section 5",
            "Management plans to obtain a bridge letter upon request.",
        ),
    ]
    crosscheck_env.verdicts = []
    result = crosscheck_claims([_claim(0, "Claim.")], findings, pool)
    assert result["catalog"] == {
        "findings": 1,
        "outside_in_evidence": 1,
        "soc2_exceptions": 1,
        "soc2_no_exception": 2,
        "soc2_notables": 1,
    }
    prompt = crosscheck_env.calls[0]["messages"][1]["content"]
    assert "control tested, no exceptions: No exceptions noted." in prompt
    assert "Section 4, A1.2-01" in prompt
    assert "Section 4, CC4.1-01" in prompt
    assert "bridge letter" in prompt
