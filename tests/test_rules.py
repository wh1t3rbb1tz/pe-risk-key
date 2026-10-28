"""Tests for pe_risk_key.engine.rules: deterministic rule constraints."""

import copy
from pathlib import Path

import yaml

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
    "cost_size_multiplier": {
        "1-50": 0.4,
        "51-200": 0.7,
        "201-1000": 1.0,
        "1001-5000": 2.0,
        "5000+": 4.0,
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
        [_kev_finding(confidence="high", remediation=_remediation(100000, 400000))],
        CONFIG,
        "201-1000",
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
            [
                _kev_finding(
                    confidence=confidence,
                    remediation=_remediation(100000, 400000),
                )
            ],
            CONFIG,
            "201-1000",
        )
        assert findings[0]["confidence"] == confidence
        assert adjustments == []


def test_severity_clamped_up_to_one_level():
    findings, adjustments = apply_rule_constraints(
        [_finding(severity="critical", remediation=_remediation(40000, 150000))],
        CONFIG,  # baseline medium
        "201-1000",
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
        [_finding(severity="info", remediation=_remediation(2000, 10000))],
        CONFIG,  # baseline medium
        "201-1000",
    )
    assert findings[0]["severity"] == "low"
    assert adjustments[0]["from"] == "info"
    assert adjustments[0]["to"] == "low"


def test_severity_within_one_level_untouched():
    cases = {
        "medium": (10000, 50000),
        "high": (40000, 150000),
        "low": (2000, 10000),
    }
    for severity, (low, high) in cases.items():
        findings, adjustments = apply_rule_constraints(
            [_finding(severity=severity, remediation=_remediation(low, high))],
            CONFIG,
            "201-1000",
        )
        assert findings[0]["severity"] == severity
        assert adjustments == []


def test_csf_category_and_function_set_from_rule():
    findings, adjustments = apply_rule_constraints(
        [_finding(csf_function="GV", csf_category="GV.SC")], CONFIG, "201-1000"
    )
    assert findings[0]["csf_category"] == "PR.DS"
    assert findings[0]["csf_function"] == "PR"
    assert [(a["field"], a["from"], a["to"]) for a in adjustments] == [
        ("csf_category", "GV.SC", "PR.DS"),
        ("csf_function", "GV", "PR"),
    ]
    assert all(a["reason"] == "rule_csf" for a in adjustments)


def test_matching_csf_records_no_adjustment():
    _, adjustments = apply_rule_constraints([_finding()], CONFIG, "201-1000")
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


def _config_with_override(override):
    rule = {**CONFIG["rules"][1], "cost_override_usd": override}
    return {
        "rules": [rule],
        "cost_bands_usd": CONFIG["cost_bands_usd"],
        "cost_size_multiplier": CONFIG["cost_size_multiplier"],
    }


def test_cost_override_takes_precedence_over_band():
    config = _config_with_override([11000, 22000])
    findings, adjustments = apply_rule_constraints(
        [_finding(remediation=_remediation())], config, "201-1000"
    )
    assert findings[0]["remediation"]["cost_low_usd"] == 11000
    assert findings[0]["remediation"]["cost_high_usd"] == 22000
    assert adjustments[0]["to"] == [11000, 22000]
    assert adjustments[0]["reason"] == "cost_override"


def test_cost_override_scaled_by_size_band():
    config = _config_with_override([8000, 30000])
    cases = {
        "201-1000": [8000, 30000],
        "1-50": [3000, 12000],  # 3200/12000 rounded to $500
        "5000+": [32000, 120000],
    }
    for band, expected in cases.items():
        findings, adjustments = apply_rule_constraints(
            [_finding(remediation=_remediation())], config, band
        )
        remediation = findings[0]["remediation"]
        assert [remediation["cost_low_usd"], remediation["cost_high_usd"]] == (
            expected
        )
        assert adjustments[0]["reason"] == "cost_override"


def test_cost_override_rounds_to_nearest_500():
    config = _config_with_override([2000, 8000])
    findings, _ = apply_rule_constraints(
        [_finding(remediation=_remediation())], config, "1-50"
    )
    remediation = findings[0]["remediation"]
    assert remediation["cost_low_usd"] == 1000  # 800 rounds up
    assert remediation["cost_high_usd"] == 3000  # 3200 rounds down


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


def test_missing_employee_band_defaults_to_201_1000():
    findings, adjustments = apply_rule_constraints(
        [_finding(remediation=_remediation())], CONFIG
    )
    remediation = findings[0]["remediation"]
    assert [remediation["cost_low_usd"], remediation["cost_high_usd"]] == [
        10000,
        50000,
    ]
    assert [a["reason"] for a in adjustments] == [
        "default_size_band",
        "cost_band",
    ]
    assert adjustments[0]["field"] == "employee_band"
    assert adjustments[0]["from"] is None
    assert adjustments[0]["to"] == "201-1000"


def test_cost_skipped_for_unknown_rule():
    findings, adjustments = apply_rule_constraints(
        [_finding(rule_id="NOPE-1", remediation=_remediation())],
        CONFIG,
        "201-1000",
    )
    assert findings[0]["remediation"]["cost_low_usd"] == 1
    assert [a["reason"] for a in adjustments] == ["unknown_rule"]


def _config_with_effort(weeks):
    rule = {**CONFIG["rules"][1], "effort_weeks_override": weeks}
    return {
        "rules": [rule],
        "cost_bands_usd": CONFIG["cost_bands_usd"],
        "cost_size_multiplier": CONFIG["cost_size_multiplier"],
    }


def test_effort_override_sets_weeks_unscaled():
    config = _config_with_effort(6)
    for band in ("201-1000", "5000+"):
        findings, adjustments = apply_rule_constraints(
            [_finding(remediation=_remediation(10000, 50000))], config, band
        )
        assert findings[0]["remediation"]["effort_weeks"] == 6
        assert adjustments == [
            {
                "finding_id": "F-001",
                "field": "remediation.effort_weeks",
                "from": 3,
                "to": 6,
                "reason": "effort_override",
            }
        ]


def test_effort_kept_without_override():
    findings, adjustments = apply_rule_constraints(
        [_finding(remediation=_remediation())], CONFIG, "201-1000"
    )
    assert findings[0]["remediation"]["effort_weeks"] == 3
    assert all(a["reason"] != "effort_override" for a in adjustments)


def test_source_derived_public_record():
    finding = _finding(
        source="outside_in",
        evidence=[{"source_type": "outside_in"}, {"source_type": "public_record"}],
    )
    findings, adjustments = apply_rule_constraints([finding], CONFIG, "201-1000")
    assert findings[0]["source"] == "public_record"
    assert adjustments == [
        {
            "finding_id": "F-001",
            "field": "source",
            "from": "outside_in",
            "to": "public_record",
            "reason": "source",
        }
    ]


def test_source_kept_when_document_or_interview_evidence_present():
    for other in ("document", "interview"):
        finding = _finding(
            source="outside_in",
            evidence=[{"source_type": "public_record"}, {"source_type": other}],
        )
        findings, adjustments = apply_rule_constraints(
            [finding], CONFIG, "201-1000"
        )
        assert findings[0]["source"] == "outside_in"
        assert adjustments == []


def test_source_derived_document_for_soc2_rule():
    config = {
        "rules": [
            {"id": "SOC2-EXCEPTION-ACCESS", "severity": "high", "csf": "PR.AA"}
        ],
        "cost_bands_usd": CONFIG["cost_bands_usd"],
        "cost_size_multiplier": CONFIG["cost_size_multiplier"],
    }
    finding = _finding(
        rule_id="SOC2-EXCEPTION-ACCESS",
        severity="high",
        csf_category="PR.AA",
        source="outside_in",
        evidence=[{"source_type": "document"}],
        remediation=_remediation(40000, 150000),
    )
    findings, adjustments = apply_rule_constraints([finding], config, "201-1000")
    assert findings[0]["source"] == "document"
    assert adjustments == [
        {
            "finding_id": "F-001",
            "field": "source",
            "from": "outside_in",
            "to": "document",
            "reason": "source",
        }
    ]


def test_source_unchanged_when_already_correct():
    finding = _finding(
        source="public_record",
        evidence=[{"source_type": "public_record"}],
    )
    findings, adjustments = apply_rule_constraints([finding], CONFIG, "201-1000")
    assert findings[0]["source"] == "public_record"
    assert adjustments == []


def _repo_files():
    root = Path(__file__).resolve().parents[1]
    scoring = yaml.safe_load((root / "scoring.yaml").read_text(encoding="utf-8"))
    expected = yaml.safe_load(
        (root / "fixtures/expected/brightwaterfleet.example.yaml").read_text(
            encoding="utf-8"
        )
    )
    return scoring, expected


def test_every_expected_rule_has_cost_override():
    scoring, expected = _repo_files()
    by_id = {rule["id"]: rule for rule in scoring["rules"]}
    rule_ids = {entry["rule_id"] for entry in expected["expected_findings"]}
    assert len(rule_ids) == 14  # SOC2-EXCEPTION-ACCESS covers two controls
    for rule_id in sorted(rule_ids):
        override = by_id[rule_id].get("cost_override_usd")
        assert isinstance(override, list) and len(override) == 2, rule_id
        assert all(isinstance(v, (int, float)) for v in override), rule_id
        assert 0 <= override[0] <= override[1], rule_id


def test_every_expected_rule_has_effort_override():
    scoring, expected = _repo_files()
    by_id = {rule["id"]: rule for rule in scoring["rules"]}
    rule_ids = {entry["rule_id"] for entry in expected["expected_findings"]}
    for rule_id in sorted(rule_ids):
        weeks = by_id[rule_id].get("effort_weeks_override")
        assert isinstance(weeks, (int, float)) and weeks >= 0, rule_id


def test_surface_rules_cap_confidence_at_medium():
    scoring, _ = _repo_files()
    by_id = {rule["id"]: rule for rule in scoring["rules"]}
    assert by_id["SURFACE-RISKY-HOSTS"]["max_confidence"] == "medium"
    assert by_id["SURFACE-SPRAWL"]["max_confidence"] == "medium"


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
