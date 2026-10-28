"""Tests for pe_risk_key.engine.scoring: deterministic digest scoring."""

import json
from pathlib import Path

import pytest
import yaml

from pe_risk_key.engine.scoring import (
    CAP_IMPLEMENTATIONS,
    FUNCTIONS,
    apply_rating_caps,
    assessed_functions,
    deal_signal,
    limitations,
    rating_for_score,
    remediation_plan,
    score_digest,
    score_functions,
    weighted_score,
)

ROOT = Path(__file__).resolve().parents[1]
SCORING = yaml.safe_load((ROOT / "scoring.yaml").read_text(encoding="utf-8"))


def _finding(
    finding_id,
    severity,
    confidence="high",
    category="PR.DS",
    rule_id=None,
    low=0,
    high=0,
):
    return {
        "finding_id": finding_id,
        "title": f"Title {finding_id}",
        "severity": severity,
        "confidence": confidence,
        "csf_function": category.split(".")[0],
        "csf_category": category,
        "source": "outside_in",
        "evidence": [],
        "deal_impact": "",
        "remediation": {
            "summary": f"Fix {finding_id}.",
            "cost_low_usd": low,
            "cost_high_usd": high,
            "effort_weeks": 0,
        },
        "rule_id": rule_id,
    }


def _contradiction(verdict, severity):
    return {"verdict": verdict, "severity": severity}


def _scores_by_function(entries):
    return {entry["function"]: entry for entry in entries}


def test_known_findings_exact_scores():
    findings = [
        _finding("F-001", "critical", "high", "PR.DS"),
        _finding("F-002", "high", "high", "PR.DS"),
        _finding("F-003", "medium", "medium", "ID.AM"),
        _finding("F-004", "high", "medium", "RS.MA"),
    ]
    out = score_digest(findings, [], SCORING, revenue_band="50M-250M")
    by_function = _scores_by_function(out["function_scores"])
    # PR: 35×1.0×1.0 + 18×1.0×0.6 = 45.8
    assert by_function["PR"]["score"] == pytest.approx(54.2)
    assert by_function["PR"]["finding_count"] == 2
    assert by_function["ID"]["score"] == pytest.approx(94.0)
    assert by_function["RS"]["score"] == pytest.approx(86.5)
    for function in ("ID", "PR", "RS"):
        assert by_function[function]["assessed"] is True
    for function in ("GV", "DE", "RC"):
        assert by_function[function]["score"] == 100.0
        assert by_function[function]["finding_count"] == 0
        assert by_function[function]["assessed"] is False
    # (94×.15 + 54.2×.30 + 86.5×.10) / .55 = 70.927…
    assert out["overall"]["score"] == pytest.approx(70.92727272727273)
    assert out["overall"]["rating"] == "C"  # B capped by CAP-CRIT
    assert out["overall"]["rating_caps_applied"] == ["CAP-CRIT"]
    assert out["overall"]["confidence"] == "low"
    assert out["overall"]["deal_signal"] == "proceed_with_conditions"


def test_decay_orders_by_severity_not_input_order():
    low_first = [
        _finding("F-001", "low", "high", "PR.DS"),
        _finding("F-002", "critical", "high", "PR.DS"),
    ]
    high_first = list(reversed(low_first))
    assessed = ["ID", "PR", "RS"]
    first = _scores_by_function(
        score_functions(low_first, [], SCORING, assessed)
    )["PR"]
    second = _scores_by_function(
        score_functions(high_first, [], SCORING, assessed)
    )["PR"]
    # Critical takes decay 1.0 either way: 35 + 3×0.6 = 36.8.
    assert first["score"] == pytest.approx(63.2)
    assert second["score"] == pytest.approx(63.2)


def test_decay_tiebreak_is_input_order_independent():
    pair = [
        _finding("F-001", "medium", "low", "PR.DS"),
        _finding("F-002", "medium", "high", "PR.DS"),
    ]
    assessed = ["ID", "PR", "RS"]
    forward = score_functions(pair, [], SCORING, assessed)
    backward = score_functions(list(reversed(pair)), [], SCORING, assessed)
    assert forward == backward


def test_weight_renormalization_over_assessed_only():
    scores = [
        {
            "function": function,
            "score": 0.0 if function == "PR" else 100.0,
            "finding_count": 0,
        }
        for function in FUNCTIONS
    ]
    # (100×.15 + 0×.30 + 100×.10) / .55 = 45.45 → D.
    # Without renormalization the same scores give 25 → F.
    assert weighted_score(scores, SCORING, ["ID", "PR", "RS"]) == pytest.approx(
        45.45454545454545
    )


def test_assessed_functions_from_inputs():
    assert assessed_functions(
        SCORING, domain_scan=True, has_soc2=False, has_interview=False
    ) == ["ID", "PR", "RS"]
    assert assessed_functions(
        SCORING, domain_scan=True, has_soc2=True, has_interview=True
    ) == ["GV", "ID", "PR", "DE", "RS", "RC"]
    assert assessed_functions(
        SCORING, domain_scan=False, has_soc2=False, has_interview=True
    ) == ["GV"]


def test_cap_crit_fires():
    out = score_digest(
        [_finding("F-001", "critical", "high", "PR.DS")],
        [],
        SCORING,
        revenue_band="50M-250M",
    )
    assert out["overall"]["rating"] == "C"
    assert out["overall"]["rating_caps_applied"] == ["CAP-CRIT"]


def test_cap_crit_ignores_low_confidence():
    out = score_digest(
        [_finding("F-001", "critical", "low", "PR.DS")],
        [],
        SCORING,
        revenue_band="50M-250M",
    )
    assert out["overall"]["rating_caps_applied"] == []


def test_cap_soc2_qualified_fires():
    out = score_digest(
        [], [], SCORING, soc2_opinion="qualified", revenue_band="50M-250M"
    )
    assert out["overall"]["score"] == 100.0
    assert out["overall"]["rating"] == "C"
    assert out["overall"]["rating_caps_applied"] == ["CAP-SOC2-QUAL"]


def test_cap_incident_fires_and_escalates():
    out = score_digest(
        [
            _finding(
                "F-001",
                "high",
                "high",
                "RS.MA",
                rule_id="PUB-INCIDENT-RECENT",
            )
        ],
        [],
        SCORING,
        revenue_band="50M-250M",
    )
    assert out["overall"]["rating_caps_applied"] == ["CAP-INCIDENT"]
    assert out["overall"]["deal_signal"] == "escalate_full_diligence"


def test_cap_contradiction_fires():
    contradictions = [
        _contradiction("contradicted", "high"),
        _contradiction("contradicted", "critical"),
    ]
    out = score_digest([], contradictions, SCORING, revenue_band="50M-250M")
    assert out["overall"]["rating"] == "D"
    assert out["overall"]["rating_caps_applied"] == ["CAP-CONTRADICTION"]
    assert out["overall"]["deal_signal"] == "escalate_full_diligence"


def test_every_cap_id_has_implementation():
    yaml_ids = {cap["id"] for cap in SCORING["rating_caps"]}
    assert yaml_ids == set(CAP_IMPLEMENTATIONS)


def test_contradiction_penalty_goes_to_contradiction_function():
    out = score_digest(
        [],
        [_contradiction("contradicted", "high")],
        SCORING,
        revenue_band="50M-250M",
        has_soc2=True,
    )
    by_function = _scores_by_function(out["function_scores"])
    assert by_function["GV"]["score"] == pytest.approx(90.0)
    assert by_function["GV"]["finding_count"] == 0


def test_deal_signal_reprice_beats_conditions():
    findings = [
        _finding("F-001", "medium", "high", "PR.DS", high=20000),
        _finding("F-002", "medium", "high", "PR.PS", high=20000),
        _finding("F-003", "medium", "high", "ID.AM", high=20000),
        _finding("F-004", "medium", "high", "ID.RA", high=20000),
        _finding("F-005", "medium", "high", "RS.MA", high=20000),
    ]
    out = score_digest(findings, [], SCORING, revenue_band="<10M")
    assert out["overall"]["rating"] == "A"
    # 100k total high > 1% of the $5M midpoint.
    assert out["remediation_plan"]["total_cost_high_usd"] == 100000
    assert out["overall"]["deal_signal"] == "reprice_or_restructure"


def test_deal_signal_high_severity_at_rating_a():
    out = score_digest(
        [_finding("F-001", "high", "high", "PR.DS")],
        [],
        SCORING,
        revenue_band="50M-250M",
    )
    assert out["overall"]["rating"] == "A"
    assert out["overall"]["deal_signal"] == "proceed_with_conditions"


def test_deal_signal_clean_run_proceeds():
    out = score_digest([], [], SCORING, revenue_band="50M-250M")
    assert out["overall"] == {
        "score": 100.0,
        "rating": "A",
        "deal_signal": "proceed",
        "confidence": "low",
        "rating_caps_applied": [],
    }


def test_rating_bands_and_floor():
    assert rating_for_score(100.0, SCORING) == "A"
    assert rating_for_score(85.0, SCORING) == "A"
    assert rating_for_score(84.9, SCORING) == "B"
    assert rating_for_score(0.0, SCORING) == "F"
    out = score_digest(
        [_finding(f"F-{i:03d}", "critical", "high", "PR.DS") for i in range(8)],
        [],
        SCORING,
        revenue_band="50M-250M",
    )
    by_function = _scores_by_function(out["function_scores"])
    assert by_function["PR"]["score"] == 0.0


def test_remediation_windows_owners_and_totals():
    findings = [
        _finding("F-001", "critical", "high", "GV.SC", low=100, high=200),
        _finding("F-002", "high", "high", "ID.AM", low=10, high=20),
        _finding("F-003", "medium", "high", "PR.DS", low=1, high=2),
        _finding("F-004", "low", "high", "DE.CM"),
        _finding("F-005", "info", "high", "RS.MA"),
        _finding("F-006", "low", "high", "RC.RP"),
    ]
    plan = remediation_plan(findings)
    assert [item["window"] for item in plan["items"]] == [
        "days_0_30",
        "days_31_60",
        "days_61_100",
        "post_100",
        "post_100",
        "post_100",
    ]
    assert [item["owner_role"] for item in plan["items"]] == [
        "CISO/Board",
        "IT Ops",
        "Security Engineering",
        "SecOps",
        "Incident Response",
        "IT Ops",
    ]
    assert [item["finding_ids"] for item in plan["items"]] == [
        ["F-001"],
        ["F-002"],
        ["F-003"],
        ["F-004"],
        ["F-005"],
        ["F-006"],
    ]
    assert plan["total_cost_low_usd"] == 111
    assert plan["total_cost_high_usd"] == 222


def test_limitations_content_outside_in_only():
    entries = limitations(
        assessed=["ID", "PR", "RS"],
        has_soc2=False,
        has_interview=False,
        demo=False,
    )
    assert entries == [
        "Unassessed CSF functions (no evidence from provided inputs): GV, DE, RC",
        "Passive outside-in assessment only; no authenticated or internal testing",
        "KEV matches are product-level; versions not verified",
        "No SOC 2 report provided",
        "No management interview provided",
    ]


def test_limitations_demo_and_full_inputs(monkeypatch):
    full = limitations(
        assessed=["GV", "ID", "PR", "DE", "RS", "RC"],
        has_soc2=True,
        has_interview=True,
        demo=False,
    )
    assert full == [
        "Passive outside-in assessment only; no authenticated or internal testing",
        "KEV matches are product-level; versions not verified",
    ]
    monkeypatch.setenv("DEMO_MODE", "1")
    assert limitations(
        assessed=["ID", "PR", "RS"],
        has_soc2=False,
        has_interview=False,
        demo=None,
    )[-1] == "Demo mode: signals from fixtures"
    monkeypatch.delenv("DEMO_MODE")
    assert "Demo mode: signals from fixtures" not in limitations(
        assessed=["ID", "PR", "RS"],
        has_soc2=False,
        has_interview=False,
        demo=None,
    )


def test_determinism_same_inputs_identical_json():
    findings = [
        _finding("F-001", "critical", "high", "PR.DS"),
        _finding("F-002", "high", "high", "PR.DS"),
        _finding("F-003", "medium", "medium", "ID.AM"),
    ]
    first = json.dumps(
        score_digest(findings, [], SCORING, revenue_band="50M-250M"),
        sort_keys=True,
    )
    second = json.dumps(
        score_digest(
            [dict(f) for f in findings], [], SCORING, revenue_band="50M-250M"
        ),
        sort_keys=True,
    )
    assert first == second
    # Scores (but not item order) are input-order independent.
    shuffled = score_digest(
        list(reversed(findings)), [], SCORING, revenue_band="50M-250M"
    )
    parsed = json.loads(first)
    assert shuffled["function_scores"] == parsed["function_scores"]
    assert shuffled["overall"] == parsed["overall"]


def test_apply_rating_caps_keeps_best_max():
    ctx = {
        "findings": [
            _finding("F-001", "critical", "high", "PR.DS"),
        ],
        "contradictions": [
            _contradiction("contradicted", "high"),
            _contradiction("contradicted", "high"),
        ],
        "soc2_opinion": None,
    }
    rating, applied = apply_rating_caps("A", ctx, SCORING)
    assert rating == "D"  # CAP-CRIT allows C, CAP-CONTRADICTION allows D
    assert applied == ["CAP-CRIT", "CAP-CONTRADICTION"]


def test_confidence_levels():
    out = score_digest(
        [],
        [],
        SCORING,
        revenue_band="50M-250M",
        has_soc2=True,
        has_interview=True,
    )
    assert out["overall"]["confidence"] == "high"
    out = score_digest(
        [], [], SCORING, revenue_band="50M-250M", has_soc2=True
    )
    assert out["overall"]["confidence"] == "medium"
    out = score_digest(
        [],
        [],
        SCORING,
        revenue_band="50M-250M",
        domain_scan=False,
        has_soc2=True,
        has_interview=True,
    )
    assert out["overall"]["confidence"] == "low"
