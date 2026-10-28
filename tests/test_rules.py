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
    ],
    "cost_bands_usd": {
        "201-1000": {
            "critical": [100000, 400000],
            "high": [40000, 150000],
            "medium": [10000, 50000],
            "low": [2000, 10000],
        }
    },
}


def _finding(**overrides):
    base = {
        "finding_id": "F-001",
        "rule_id": "EMAIL-SPF-SOFT",
        "severity": "medium",
        "confidence": "high",
        "csf_function": "PR",
        "csf_category": "PR.DS",
        "remediation": {
            "summary": "Fix it.",
            "cost_low_usd": 10000,
            "cost_high_usd": 50000,
            "effort_weeks": 2,
        },
    }
    base.update(overrides)
    return base


def _remediation(low=1, high=2):
    return {
        "summary": "Fix it.",
        "cost_low_usd": low,
        "cost_high_usd": high,
        "effort_weeks": 3,
    }


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


def test_cost_band_lookup_overwrites_model_costs():
    findings, adjustments = apply_rule_constraints(
        [_finding(remediation=_remediation())], CONFIG, "201-1000"
    )
    assert findings[0]["remediation"] == {
        "summary": "Fix it.",
        "cost_low_usd": 10000,
        "cost_high_usd": 50000,
        "effort_weeks": 3,
    }
    assert adjustments == [
        {
            "finding_id": "F-001",
            "field": "remediation.cost_usd",
            "from": [1, 2],
            "to": [10000, 50000],
            "reason": "cost_band",
        }
    ]


def test_cost_override_takes_precedence_over_band():
    rule = {**CONFIG["rules"][1], "cost_override_usd": [111, 222]}
    config = {"rules": [rule], "cost_bands_usd": CONFIG["cost_bands_usd"]}
    findings, adjustments = apply_rule_constraints(
        [_finding(remediation=_remediation())], config, "201-1000"
    )
    assert findings[0]["remediation"]["cost_low_usd"] == 111
    assert findings[0]["remediation"]["cost_high_usd"] == 222
    assert adjustments[0]["to"] == [111, 222]
    assert adjustments[0]["reason"] == "cost_band"


def test_cost_uses_clamped_severity():
    findings, adjustments = apply_rule_constraints(
        [_finding(severity="critical", remediation=_remediation())],
        CONFIG,
        "201-1000",
    )
    assert findings[0]["severity"] == "high"  # clamped from critical
    assert findings[0]["remediation"]["cost_low_usd"] == 40000
    assert findings[0]["remediation"]["cost_high_usd"] == 150000
    assert [a["reason"] for a in adjustments] == [
        "severity_bounds",
        "cost_band",
    ]


def test_matching_costs_record_no_adjustment():
    _, adjustments = apply_rule_constraints([_finding()], CONFIG, "201-1000")
    assert adjustments == []


def test_cost_skipped_without_employee_band():
    findings, adjustments = apply_rule_constraints(
        [_finding(remediation=_remediation())], CONFIG
    )
    assert findings[0]["remediation"]["cost_low_usd"] == 1
    assert adjustments == []


def test_cost_skipped_for_unknown_rule():
    findings, adjustments = apply_rule_constraints(
        [_finding(rule_id="NOPE-1", remediation=_remediation())],
        CONFIG,
        "201-1000",
    )
    assert findings[0]["remediation"]["cost_low_usd"] == 1
    assert [a["reason"] for a in adjustments] == ["unknown_rule"]


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
