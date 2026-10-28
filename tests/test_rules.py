"""Tests for pe_risk_key.engine.rules: deterministic rule constraints."""

import copy

from pe_risk_key.engine.rules import apply_rule_constraints

CONFIG = {
    "rules": [
        {
            "id": "KEV-POTENTIAL",
            "severity": "critical",
            "max_confidence": "medium",
            "csf": "ID.RA",
        },
        {"id": "EMAIL-SPF-SOFT", "severity": "medium", "csf": "PR.DS"},
    ]
}


def _finding(**overrides):
    base = {
        "finding_id": "F-001",
        "rule_id": "EMAIL-SPF-SOFT",
        "severity": "medium",
        "confidence": "high",
        "csf_function": "PR",
        "csf_category": "PR.DS",
    }
    base.update(overrides)
    return base


def _kev_finding(**overrides):
    base = {
        "severity": "critical",
        "csf_function": "ID",
        "csf_category": "ID.RA",
    }
    base.update(overrides)
    return _finding(rule_id="KEV-POTENTIAL", **base)


def test_confidence_clamped_to_max():
    findings, adjustments = apply_rule_constraints(
        [_kev_finding(confidence="high")], CONFIG
    )
    assert findings[0]["confidence"] == "medium"
    assert adjustments == [
        {
            "finding_id": "F-001",
            "field": "confidence",
            "from": "high",
            "to": "medium",
            "reason": "max_confidence",
        }
    ]


def test_confidence_at_or_below_max_untouched():
    for confidence in ("medium", "low"):
        findings, adjustments = apply_rule_constraints(
            [_kev_finding(confidence=confidence)], CONFIG
        )
        assert findings[0]["confidence"] == confidence
        assert adjustments == []


def test_severity_clamped_up_to_one_level():
    findings, adjustments = apply_rule_constraints(
        [_finding(severity="critical")], CONFIG  # baseline medium
    )
    assert findings[0]["severity"] == "high"
    assert adjustments == [
        {
            "finding_id": "F-001",
            "field": "severity",
            "from": "critical",
            "to": "high",
            "reason": "severity_bounds",
        }
    ]


def test_severity_clamped_down_to_one_level():
    findings, adjustments = apply_rule_constraints(
        [_finding(severity="info")], CONFIG  # baseline medium
    )
    assert findings[0]["severity"] == "low"
    assert adjustments[0]["from"] == "info"
    assert adjustments[0]["to"] == "low"


def test_severity_within_one_level_untouched():
    for severity in ("medium", "high", "low"):
        findings, adjustments = apply_rule_constraints(
            [_finding(severity=severity)], CONFIG
        )
        assert findings[0]["severity"] == severity
        assert adjustments == []


def test_csf_category_and_function_set_from_rule():
    findings, adjustments = apply_rule_constraints(
        [_finding(csf_function="GV", csf_category="GV.SC")], CONFIG
    )
    assert findings[0]["csf_category"] == "PR.DS"
    assert findings[0]["csf_function"] == "PR"
    assert [(a["field"], a["from"], a["to"]) for a in adjustments] == [
        ("csf_category", "GV.SC", "PR.DS"),
        ("csf_function", "GV", "PR"),
    ]
    assert all(a["reason"] == "rule_csf" for a in adjustments)


def test_matching_csf_records_no_adjustment():
    _, adjustments = apply_rule_constraints([_finding()], CONFIG)
    assert adjustments == []


def test_unknown_rule_kept_and_recorded():
    finding = _finding(rule_id="NOPE-1", severity="critical")
    findings, adjustments = apply_rule_constraints([finding], CONFIG)
    assert findings == [finding]  # kept, unconstrained
    assert adjustments == [
        {
            "finding_id": "F-001",
            "field": "rule_id",
            "from": "NOPE-1",
            "to": "NOPE-1",
            "reason": "unknown_rule",
        }
    ]


def test_missing_rule_id_recorded_as_unknown():
    finding = _finding()
    del finding["rule_id"]
    findings, adjustments = apply_rule_constraints([finding], CONFIG)
    assert "rule_id" not in findings[0]
    assert adjustments[0]["reason"] == "unknown_rule"
    assert adjustments[0]["from"] is None


def test_inputs_not_mutated():
    findings = [
        _finding(rule_id="KEV-POTENTIAL", confidence="high", severity="info")
    ]
    snapshot = copy.deepcopy(findings)
    config_snapshot = copy.deepcopy(CONFIG)
    constrained, _ = apply_rule_constraints(findings, CONFIG)
    assert findings == snapshot
    assert CONFIG == config_snapshot
    assert constrained[0] is not findings[0]
