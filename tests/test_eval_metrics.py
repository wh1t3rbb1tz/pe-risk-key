# SPDX-License-Identifier: AGPL-3.0-or-later
"""Tests for pe_risk_key.engine.eval_metrics. No network, fixed inputs."""

from pe_risk_key.engine.eval_metrics import (
    match_contradictions,
    score_findings,
    score_profile,
)


def _finding(rule_id, severity="high", title="", excerpts=()):
    return {
        "finding_id": "F-001",
        "rule_id": rule_id,
        "severity": severity,
        "title": title,
        "evidence": [{"excerpt": excerpt} for excerpt in excerpts],
    }


def _entry(rule_id, severity="high", **extra):
    return {"rule_id": rule_id, "severity": severity, **extra}


def test_score_findings_recall_and_precision():
    findings = [
        _finding("EMAIL-DMARC-NONE", "high"),
        _finding("KEV-POTENTIAL", "critical"),
        _finding("SURFACE-SPRAWL", "low"),
    ]
    expected = [
        _entry("EMAIL-DMARC-NONE", "high"),
        _entry("KEV-POTENTIAL", "critical"),
        _entry("DNS-NO-DNSSEC", "low"),
    ]
    result = score_findings(findings, expected, ["KEV-PRODUCT-LISTED"])
    assert result["recall"] == 2 / 3
    assert result["precision"] == 2 / 3
    assert result["matched"] == 2
    assert result["missing"] == ["DNS-NO-DNSSEC"]
    assert result["unexpected"] == ["SURFACE-SPRAWL"]
    assert result["severity_exact"] == 2
    assert result["must_not_find_hits"] == []


def test_score_findings_duplicate_rules_match_one_to_one():
    findings = [
        _finding(
            "SOC2-EXCEPTION-ACCESS",
            "high",
            "SOC 2 exception in logical access controls (CC6.1)",
        )
    ]
    expected = [
        _entry(
            "SOC2-EXCEPTION-ACCESS", "high", control_id="CC6.1"
        ),
        _entry(
            "SOC2-EXCEPTION-ACCESS", "high", control_id="CC6.2"
        ),
    ]
    result = score_findings(findings, expected)
    assert result["recall"] == 0.5
    assert result["precision"] == 1.0
    assert result["missing"] == ["SOC2-EXCEPTION-ACCESS"]


def test_score_findings_subservice_org_and_must_not_find():
    findings = [
        _finding(
            "SOC2-CARVE-OUT-CRITICAL",
            "low",
            "Critical subservice org carved out",
            ["Nimbus Cloud Services is carved out of scope: hosting."],
        ),
        _finding("KEV-PRODUCT-LISTED", "low"),
    ]
    expected = [
        _entry(
            "SOC2-CARVE-OUT-CRITICAL",
            "low",
            subservice_org="Nimbus Cloud Services",
        )
    ]
    result = score_findings(
        findings, expected, ["KEV-PRODUCT-LISTED", "WEB-NO-HSTS"]
    )
    assert result["recall"] == 1.0
    assert result["precision"] == 0.5
    assert result["must_not_find_hits"] == ["KEV-PRODUCT-LISTED"]


def test_score_findings_empty_inputs():
    assert score_findings([], [])["recall"] is None
    assert score_findings([], [_entry("X")])["recall"] == 0.0
    assert score_findings([], [_entry("X")])["precision"] is None
    assert score_findings([_finding("X")], [])["recall"] is None


def _contradiction(text, verdict):
    return {
        "contradiction_id": "C-001",
        "claim": {
            "speaker": "CTO",
            "timestamp": "01:00",
            "text": text,
            "claim_type": "control_exists",
        },
        "verdict": verdict,
        "severity": "high",
        "evidence_refs": ["F-001"],
        "explanation": "Explanation.",
    }


def _wanted(ref, verdict=None, verdict_any_of=None, pattern="MFA"):
    entry = {
        "claim_ref": ref,
        "topic": "topic",
        "match_keywords": pattern,
    }
    if verdict is not None:
        entry["verdict"] = verdict
    if verdict_any_of is not None:
        entry["verdict_any_of"] = verdict_any_of
    return entry


def test_match_contradictions_recall_and_accuracy():
    contradictions = [
        _contradiction("MFA covers all admins.", "contradicted")
    ]
    expected = [
        _wanted(1, verdict="contradicted"),
        _wanted(2, verdict="supported", pattern="backup"),
    ]
    result = match_contradictions(contradictions, expected)
    assert result["recall"] == 0.5
    assert result["accuracy"] == 1.0
    assert result["misses"] == ["claim 2: topic"]
    assert result["wrong"] == []


def test_match_contradictions_uses_context_question():
    contradictions = [_contradiction("We can get one.", "supported")]
    expected = [_wanted(9, verdict="supported", pattern="bridge letter")]
    missed = match_contradictions(contradictions, expected, {})
    assert missed["recall"] == 0.0
    hit = match_contradictions(
        contradictions,
        expected,
        {"We can get one.": "Can you provide a bridge letter?"},
    )
    assert hit["recall"] == 1.0
    assert hit["accuracy"] == 1.0


def test_match_contradictions_verdict_any_of():
    contradictions = [_contradiction("We can get one.", "unsupported")]
    expected = [
        _wanted(
            9,
            verdict_any_of=["supported", "unsupported"],
            pattern="bridge letter",
        )
    ]
    questions = {"We can get one.": "Can you provide a bridge letter?"}
    result = match_contradictions(contradictions, expected, questions)
    assert result["recall"] == 1.0
    assert result["accuracy"] == 1.0
    assert result["wrong"] == []
    bad = match_contradictions(
        [_contradiction("We can get one.", "contradicted")],
        expected,
        questions,
    )
    assert bad["accuracy"] == 0.0
    assert bad["wrong"] == [
        "claim 9: topic (want supported/unsupported, "
        "got contradicted)"
    ]


def test_match_contradictions_no_matches():
    result = match_contradictions([], [_wanted(1)])
    assert result["recall"] == 0.0
    assert result["accuracy"] is None


def test_score_profile_expected_overall_shape():
    overall = {
        "rating": "D",
        "rating_caps_applied": ["CAP-CRIT", "CAP-INCIDENT"],
        "confidence": "high",
        "deal_signal": "escalate_full_diligence",
    }
    expected = {
        "caps_applied": ["CAP-INCIDENT", "CAP-CRIT"],
        "max_rating": "D",
        "deal_signal": "escalate_full_diligence",
        "confidence": "high",
    }
    result = score_profile(overall, expected)
    assert result["profile_match"] is True
    assert result["caps_match"] is True


def test_score_profile_outside_in_shape_and_mismatch():
    overall = {
        "rating": "C",
        "rating_caps_applied": ["CAP-CRIT"],
        "confidence": "low",
        "deal_signal": "proceed_with_conditions",
    }
    expected = {
        "caps": ["CAP-CRIT", "CAP-LOW-COVERAGE"],
        "rating": "B",
        "confidence": "low",
        "deal_signal": "proceed_with_conditions",
    }
    result = score_profile(overall, expected)
    assert result["profile_match"] is False
    assert result["rating_match"] is False
    assert result["rating_got"] == "C"
    assert result["caps_match"] is False
    assert result["confidence_match"] is True
    assert result["deal_signal_match"] is True
