"""Tests for pe_risk_key.engine.narrative (mocked model). No network."""

import copy
import json

import pytest

import pe_risk_key.engine.narrative as narrative_module
from pe_risk_key.engine.narrative import (
    generate_narrative,
    needs_regeneration,
    render_ic_memo,
    repair_narrative,
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
            "Bottom line: rating C reflects one critical gap [F-001]. "
            "Key risks: the score is 72.5. "
            "Management credibility: statements conflict "
            "with evidence [C-001]. "
            "Next steps: proceed with conditions; no SOC 2 report "
            "was provided."
        ),
        "key_questions_for_management": [
            f"Confirm control {index} status [F-001]?" for index in range(4)
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
    assert "rating C reflects" in result["narrative"]["executive_summary"]
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


def _memo_digest():
    return {
        "digest_id": "dg_abc123",
        "generated_at": "2026-10-30T12:00:00+00:00",
        "target": {"name": "Acme", "domain": "acme.example"},
        "overall": {
            "score": 72.5,
            "rating": "C",
            "confidence": "medium",
            "deal_signal": "proceed_with_conditions",
            "rating_caps_applied": ["CAP-CRIT"],
        },
        "inputs": {"domain_scan": True, "documents": [], "interviews": []},
        "mode": {
            "providers": [
                {
                    "role": "orchestrator",
                    "provider": "meta_model_api",
                    "model": "muse-wonder-1.0",
                }
            ]
        },
        "function_scores": [
            {
                "function": "PR",
                "score": 60.0,
                "assessed": True,
                "finding_count": 1,
            },
            {
                "function": "GV",
                "score": 100.0,
                "assessed": False,
                "finding_count": 0,
            },
        ],
        "findings": _payload()["findings"],
        "contradictions": _payload()["contradictions"],
        "narrative": {
            "executive_summary": "Bottom line: proceed.",
            "key_questions_for_management": ["Confirm status [F-001]?"],
        },
        "deal_recommendations": [
            {
                "type": "closing_condition",
                "text": "Require the fix.",
                "basis_ids": ["F-001"],
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
                },
                {
                    "action": "Later hardening.",
                    "finding_ids": ["F-002"],
                    "window": "post_100",
                    "cost_low_usd": 1000,
                    "cost_high_usd": 2000,
                    "owner_role": "IT Ops",
                },
            ],
            "total_cost_low_usd": 9000,
            "total_cost_high_usd": 32000,
        },
        "limitations": ["No SOC 2 report provided."],
    }


def test_memo_renders(narrative_env):
    memo = render_ic_memo(
        _memo_digest(),
        evidence_pool=[
            {"evidence_id": "E-001", "excerpt": "No DMARC record published."}
        ],
        run_cost_usd=0.0123,
    )
    assert "# IC Memo: Acme (acme.example)" in memo
    assert "Date: 2026-10-30 | Digest: dg_abc123" in memo
    assert "Decision: Proceed with conditions" in memo
    assert "## Why the rating" in memo
    assert "Score 72.5 reflects a critical, potentially exploitable exposure" in memo
    assert "Confidence medium, based on outside-in scan" in memo
    assert "| Protect | 60.0 | 1 |" in memo
    assert "| Govern | Not assessed | 0 |" in memo
    assert "## Key risks" in memo
    assert "[High] DMARC not enforced (F-001, $8K–$30K)" in memo
    assert "## Management claims vs. evidence" in memo
    assert "[Contradicted/High] C-001" in memo
    assert "No SOC 2 report provided." in memo
    assert "Days 31–60" in memo
    assert "Later hardening." in memo
    assert "| Total | | | $9K–$32K |" in memo
    assert "### Closing condition" in memo
    assert "## Questions for management" in memo
    assert "Remediation costs are triage estimates" in memo
    assert "outside-in scan of acme.example" in memo
    assert "orchestrator: muse-wonder-1.0 (meta_model_api)" in memo
    assert "Run cost: $0.0123" in memo
    assert "Generated by PE Risk Key" in memo


def test_enum_leak_fails_validation():
    from pe_risk_key.engine.narrative import required_recommendation_types

    assert required_recommendation_types  # trigger table is tested below
    base_ids = {"finding_ids": {"F-001"}, "contradiction_ids": {"C-001"}}
    numbers = {"72.5", "001"}
    for leak in (
        "escalate_full_diligence",
        "CAP-CRIT",
        "days_0_30",
        "PR.DS",
        "the PR function",
    ):
        output = _good_output()
        output["executive_summary"] = (
            "Bottom line: rating C [F-001]. Key risks: none. "
            f"Management credibility: {leak} [F-001]. Next steps: none."
        )
        errors = validate_narrative(
            output, input_numbers=numbers, required_types=set(), **base_ids
        )
        assert any(
            "leaks" in error for error in errors
        ), f"no leak error for {leak!r}: {errors}"
    output = _good_output()
    output["key_questions_for_management"][0] = "Why did this happen [F-001]?"
    errors = validate_narrative(
        output, input_numbers=numbers, required_types=set(), **base_ids
    )
    assert any("why did" in error for error in errors)


def test_trigger_table_yields_brightwater_types():
    from pe_risk_key.engine.narrative import required_recommendation_types

    findings = [
        {"finding_id": "F-001", "rule_id": "EMAIL-DMARC-NONE"},
        {"finding_id": "F-008", "rule_id": "KEV-POTENTIAL"},
        {"finding_id": "F-009", "rule_id": "PUB-INCIDENT-RECENT"},
        {"finding_id": "F-010", "rule_id": "SOC2-EXCEPTION-ACCESS"},
    ]
    required = required_recommendation_types(
        findings=findings,
        caps_applied=["CAP-CRIT", "CAP-INCIDENT", "CAP-CONTRADICTION"],
        remediation_plan={
            "items": [{"window": "days_31_60", "finding_ids": ["F-001"]}],
            "total_cost_low_usd": 142000,
            "total_cost_high_usd": 643000,
        },
        revenue_midpoint_usd=150000000,
        soc2_analysis={"exceptions": [{"control_id": "CC6.1"}]},
    )
    assert set(required) == {
        "closing_condition",
        "full_diligence_scope",
        "specific_indemnity",
        "rw_insurance_note",
        "cyber_insurance",
        "post_close_covenant",
        "price_adjustment",
    }
    assert any(
        "no adjustment is warranted" in guidance
        for guidance in required["price_adjustment"]["guidance"]
    )
    assert required["cyber_insurance"]["trigger_findings"] == [
        "F-001",
        "F-010",
    ]
    assert required["closing_condition"]["trigger_findings"] == ["F-008"]
    assert required["post_close_covenant"]["trigger_findings"] == [
        "F-010",
        "F-001",
    ]


def test_low_coverage_trigger_and_label():
    from pe_risk_key.engine.narrative import (
        CAP_LABELS,
        required_recommendation_types,
    )

    assert (
        CAP_LABELS["CAP-LOW-COVERAGE"]
        == "limited evidence: outside-in signals only"
    )
    required = required_recommendation_types(
        findings=[{"finding_id": "F-001", "rule_id": "SURFACE-RISKY-HOSTS"}],
        caps_applied=["CAP-LOW-COVERAGE"],
        remediation_plan={
            "items": [
                {
                    "window": "days_61_100",
                    "finding_ids": ["F-001"],
                }
            ],
            "total_cost_low_usd": 10000,
            "total_cost_high_usd": 50000,
        },
        revenue_midpoint_usd=30000000,
        soc2_analysis=None,
    )
    assert any(
        "SOC 2 Type II report" in guidance
        for guidance in required["closing_condition"]["guidance"]
    )


def test_no_interview_credibility_sentence():
    output = _good_output()
    output["executive_summary"] = (
        "Bottom line: rating C reflects one gap [F-001]. "
        "Key risks: the score is 72.5. "
        "Management credibility: Not assessed: no management "
        "interview provided. "
        "Next steps: proceed with conditions."
    )
    errors = validate_narrative(
        output, has_interview=False, **_validate_ids()
    )
    assert errors == []
    errors = validate_narrative(
        _good_output(), has_interview=False, **_validate_ids()
    )
    assert any("must read exactly" in error for error in errors)


def test_no_soc2_statement_required():
    errors = validate_narrative(
        _good_output(), has_soc2=False, **_validate_ids()
    )
    assert errors == []
    output = _good_output()
    output["executive_summary"] = output["executive_summary"].replace(
        "; no SOC 2 report was provided", ""
    )
    errors = validate_narrative(
        output, has_soc2=False, **_validate_ids()
    )
    assert any("no SOC 2" in error for error in errors)


def test_short_evidence_length_limits():
    long_summary = _good_output()
    long_summary["executive_summary"] += " Extra detail here." * 60
    errors = validate_narrative(long_summary, **_validate_ids())
    assert any("max 600" in error for error in errors)
    many_questions = _good_output()
    many_questions["key_questions_for_management"].append(
        "Confirm one more control [F-001]?"
    )
    errors = validate_narrative(many_questions, **_validate_ids())
    assert any("need 3-4" in error for error in errors)
    full = dict(_validate_ids())
    full["finding_ids"] = {"F-001", "F-002", "F-003", "F-004"}
    errors = validate_narrative(_good_output(), **full)
    assert any("need 5-8" in error for error in errors)
    overcited = _good_output()
    overcited["executive_summary"] = (
        "Bottom line: one [F-001] two [F-001]. "
        "Key risks: three [F-001]. "
        "Management credibility: ok. "
        "Next steps: done."
    )
    errors = validate_narrative(overcited, **_validate_ids())
    assert any("max 2" in error for error in errors)
    errors = validate_narrative(overcited, **full)
    assert not any("max 2" in error for error in errors)


def _repairable_output():
    output = _good_output()
    output["executive_summary"] = output["executive_summary"].replace(
        "72.5", "72.50"
    )
    output["deal_recommendations"][0]["text"] = (
        "Require the fix in Days 31-60 [F-001], consistent with the "
        "escalate decision."
    )
    output["deal_recommendations"].append(
        {
            "type": "price_adjustment",
            "text": (
                "No adjustment is warranted under "
                "proceed_with_conditions."
            ),
            "basis_ids": ["F-001"],
        }
    )
    return output


def test_repair_rounds_scores():
    fixed, repairs = repair_narrative(
        _repairable_output(), max_chars=600, short=True, deal_label="Go"
    )
    assert "72.5" in fixed["executive_summary"]
    assert "72.50" not in fixed["executive_summary"]
    assert any("rounded 72.50" in repair for repair in repairs)


def test_repair_replaces_tokens_with_labels():
    fixed, repairs = repair_narrative(
        _repairable_output(), max_chars=600, short=True, deal_label="Go"
    )
    text = fixed["deal_recommendations"][1]["text"]
    assert text == "No adjustment is warranted under Proceed with conditions."
    output = _good_output()
    output["executive_summary"] += " Triggers CAP-CRIT in PR."
    fixed, _ = repair_narrative(
        output, max_chars=1200, short=False, deal_label="Go"
    )
    assert "CAP-CRIT" not in fixed["executive_summary"]
    assert "a critical, potentially exploitable exposure" in fixed[
        "executive_summary"
    ]
    assert "in Protect." in fixed["executive_summary"]


def test_repair_removes_restated_decision_anywhere():
    output = _good_output()
    output["deal_recommendations"][0]["text"] = (
        "Require the fix in Days 31-60 [F-001], consistent with full "
        "cyber diligence required before signing."
    )
    fixed, repairs = repair_narrative(
        output,
        max_chars=600,
        short=True,
        deal_label="Escalate: full cyber diligence required before signing",
    )
    assert fixed["deal_recommendations"][0]["text"] == (
        "Require the fix in Days 31-60 [F-001]."
    )
    assert any("removed restated decision" in repair for repair in repairs)
    kept, kept_repairs = repair_narrative(
        _good_output(), max_chars=600, short=True, deal_label="Proceed"
    )
    assert (
        kept["deal_recommendations"][0]["text"]
        == "Require DMARC enforcement before close."
    )
    assert kept_repairs == []


def test_repair_removes_full_label_and_conditions():
    output = _good_output()
    output["deal_recommendations"] = [
        {
            "type": "closing_condition",
            "text": (
                "Require the fix, consistent with Escalate: full cyber "
                "diligence required before signing."
            ),
            "basis_ids": ["F-001"],
        },
        {
            "type": "price_adjustment",
            "text": (
                "No adjustment is warranted under Proceed with conditions."
            ),
            "basis_ids": ["F-001"],
        },
        {
            "type": "cyber_insurance",
            "text": "Proceed on the basis that coverage holds [F-001].",
            "basis_ids": ["F-001"],
        },
    ]
    fixed, _ = repair_narrative(
        output,
        max_chars=600,
        short=True,
        deal_label="Escalate: full cyber diligence required before signing",
    )
    assert fixed["deal_recommendations"][0]["text"] == "Require the fix."
    kept, _ = repair_narrative(
        output,
        max_chars=600,
        short=True,
        deal_label="Proceed with conditions",
    )
    assert (
        kept["deal_recommendations"][1]["text"]
        == "No adjustment is warranted."
    )
    verb, verb_repairs = repair_narrative(
        output, max_chars=600, short=True, deal_label="Proceed"
    )
    assert verb["deal_recommendations"][2]["text"] == (
        "Proceed on the basis that coverage holds [F-001]."
    )
    assert verb_repairs == []


def test_repair_strips_run_dg_b808md3ua63f_restatements():
    texts = [
        (
            "closing_condition",
            "Make signing conditional on verification and a compromise "
            "assessment for the internet-facing ExampleGate SSL-VPN "
            "exposure during Days 0–30, with a bring-down of security "
            "representations at signing.",
        ),
        (
            "full_diligence_scope",
            "Commission a scope covering the known-exploited-product "
            "exposure and independent validation of management "
            "representations, sequenced with the Days 0–30 work, to "
            "satisfy full cyber diligence required before signing "
            "[F-008].",
        ),
        (
            "specific_indemnity",
            "Seek a specific indemnity for pre-closing incident losses "
            "tied to the disclosed incident, informed by the Days 31–60 "
            "incident review and full cyber diligence required before "
            "signing [F-009].",
        ),
        (
            "rw_insurance_note",
            "Proceed on the basis that the known incident is likely "
            "excluded from representations and warranties coverage, "
            "resolve any gap before close after the Days 31–60 review, "
            "and reflect full cyber diligence required before signing "
            "[F-009].",
        ),
        (
            "cyber_insurance",
            "Confirm insurability and likely underwriting requirements "
            "before close, using remediation of email spoofing and "
            "privileged-access controls in Days 31–60, within full cyber "
            "diligence required before signing [F-001] [F-010] [F-011].",
        ),
        (
            "post_close_covenant",
            "Impose a post-close covenant to complete the remaining "
            "remediation across Days 31–60 and Days 61–100, sequenced "
            "after full cyber diligence required before signing [F-010] "
            "[F-011] [F-012] [F-013] [F-001] [F-002] [F-004] [F-006] "
            "[F-009] [F-014].",
        ),
        (
            "price_adjustment",
            "Do not seek a price adjustment on cyber grounds alone "
            "because total remediation of $142K–$643K is immaterial "
            "relative to the 50M-250M revenue band, but preserve full "
            "cyber diligence required before signing and the windows "
            "from Days 0–30 through After day 100 [F-008] [F-009].",
        ),
    ]
    output = {
        "executive_summary": (
            "Bottom line: ok [F-008]. Key risks: none. Management "
            "credibility: ok. Next steps: none."
        ),
        "key_questions_for_management": [],
        "deal_recommendations": [
            {"type": rec_type, "text": text, "basis_ids": ["F-008"]}
            for rec_type, text in texts
        ],
    }
    fixed, repairs = repair_narrative(
        output,
        max_chars=1200,
        short=False,
        deal_label="Escalate: full cyber diligence required before signing",
    )
    cleaned = {
        rec["type"]: rec["text"]
        for rec in fixed["deal_recommendations"]
    }
    assert len(repairs) == 6
    for text in cleaned.values():
        assert "full cyber diligence required before signing" not in text
    assert cleaned["closing_condition"] == texts[0][1]
    assert cleaned["full_diligence_scope"] == (
        "Commission a scope covering the known-exploited-product "
        "exposure and independent validation of management "
        "representations, sequenced with the Days 0–30 work [F-008]."
    )
    assert cleaned["price_adjustment"] == (
        "Do not seek a price adjustment on cyber grounds alone because "
        "total remediation of $142K–$643K is immaterial relative to the "
        "50M-250M revenue band, but preserve the windows from Days 0–30 "
        "through After day 100 [F-008] [F-009]."
    )


def test_repair_trims_and_dedupes():
    output = _good_output()
    output["executive_summary"] = (
        "Bottom line: one [F-001] two [F-001] three [F-001] four "
        "[F-001]. "
        + "Padding sentence here. " * 40
        + "Next steps: done [F-001]."
    )
    fixed, repairs = repair_narrative(
        output, max_chars=600, short=True, deal_label="Go"
    )
    summary = fixed["executive_summary"]
    assert len(summary) <= 600
    assert summary.endswith(".")
    assert summary.count("[F-001]") == 2
    assert any("trimmed summary" in repair for repair in repairs)
    assert any("duplicate citation" in repair for repair in repairs)
    kept, repairs = repair_narrative(
        output, max_chars=1200, short=False, deal_label="Go"
    )
    assert kept["executive_summary"].count("[F-001]") > 2
    assert not any("duplicate citation" in repair for repair in repairs)


def test_repaired_narrative_passes_without_regeneration(narrative_env):
    narrative_env.outputs = [_repairable_output()]
    narrative_env.calls = []
    result = generate_narrative(_payload())
    assert result["valid"] is True
    assert result["regenerated"] is False
    assert len(narrative_env.calls) == 1
    assert result["narrative_repairs"] != []


def test_unmapped_leak_skips_regeneration(narrative_env):
    output = _good_output()
    output["executive_summary"] += " See foo_bar for details."
    narrative_env.outputs = [output]
    narrative_env.calls = []
    result = generate_narrative(_payload())
    assert result["valid"] is False
    assert result["regenerated"] is False
    assert len(narrative_env.calls) == 1
    assert needs_regeneration(result["validation_errors"]) is False
    assert needs_regeneration(["executive_summary has an uncited risk."])


def test_speculation_phrasing_flagged():
    output = _good_output()
    output["executive_summary"] = (
        "Bottom line: rating C [F-001]. Key risks: data may contain "
        "secrets. Management credibility: ok [C-001]. "
        "Next steps: none."
    )
    errors = validate_narrative(output, **_validate_ids())
    assert any("may contain" in error for error in errors)
    output = _good_output()
    output["key_questions_for_management"][0] = (
        "Confirm the host is isolated if present [F-001]?"
    )
    errors = validate_narrative(output, **_validate_ids())
    assert any("if present" in error for error in errors)
    output = _good_output()
    output["deal_recommendations"][0]["text"] = (
        "Require cleanup if present before close."
    )
    errors = validate_narrative(output, **_validate_ids())
    assert any("if present" in error for error in errors)


def test_plan_sorted_by_window_with_total():
    digest = _memo_digest()
    digest["remediation_plan"]["items"] = list(
        reversed(digest["remediation_plan"]["items"])
    )
    memo = render_ic_memo(digest)
    plan = memo.split("## 100-day plan")[1].split("## Deal recommendations")[0]
    assert plan.index("Enforce DMARC.") < plan.index("Later hardening.")
    assert "| Total | | | $9K–$32K |" in plan


def test_supported_claims_appear_last():
    digest = _memo_digest()
    digest["contradictions"] = [
        {
            "contradiction_id": "C-001",
            "claim": {"text": "Backups are immutable."},
            "verdict": "supported",
            "severity": "info",
            "evidence_refs": [],
            "explanation": "Corroborated.",
        },
        {
            "contradiction_id": "C-002",
            "claim": {"text": "DMARC is enforced."},
            "verdict": "contradicted",
            "severity": "high",
            "evidence_refs": ["F-001"],
            "explanation": "Contradicted.",
        },
        {
            "contradiction_id": "C-003",
            "claim": {"text": "Alerts are reviewed."},
            "verdict": "unsupported",
            "severity": "low",
            "evidence_refs": [],
            "explanation": "No evidence.",
        },
    ]
    memo = render_ic_memo(digest)
    section = memo.split("## Management claims vs. evidence")[1].split(
        "## SOC 2 summary"
    )[0]
    assert (
        section.index("C-002")
        < section.index("C-003")
        < section.index("C-001")
    )


def _validate_ids():
    return {
        "finding_ids": {"F-001"},
        "contradiction_ids": {"C-001"},
        "input_numbers": {"72.5", "001"},
    }


def test_shared_leading_clause_flagged():
    output = _good_output()
    output["deal_recommendations"] = [
        {
            "type": "closing_condition",
            "text": "Proceed with conditions and require the buyer to verify controls.",
            "basis_ids": ["F-001"],
        },
        {
            "type": "price_adjustment",
            "text": "Proceed with conditions and require the buyer to confirm coverage.",
            "basis_ids": ["F-001"],
        },
    ]
    errors = validate_narrative(output, **_validate_ids())
    assert any("leading clause" in error for error in errors)


def test_type_label_prefix_flagged():
    output = _good_output()
    output["deal_recommendations"] = [
        {
            "type": "closing_condition",
            "text": "Closing condition: require the fix before signing.",
            "basis_ids": ["F-001"],
        }
    ]
    errors = validate_narrative(output, **_validate_ids())
    assert any("own type label" in error for error in errors)


def test_supported_basis_flagged():
    output = _good_output()
    output["deal_recommendations"] = [
        {
            "type": "closing_condition",
            "text": "Require the fix before signing.",
            "basis_ids": ["C-002"],
        }
    ]
    errors = validate_narrative(
        output,
        finding_ids={"F-001"},
        contradiction_ids={"C-001", "C-002"},
        input_numbers={"72.5", "001"},
        contradiction_verdicts={"C-002": "supported"},
    )
    assert any("supported contradiction C-002" in error for error in errors)


def test_trigger_ids_added_before_validation(narrative_env):
    payload = _payload()
    payload["required_recommendations"] = {
        "closing_condition": {
            "guidance": ["verification before signing"],
            "trigger_findings": ["F-001"],
        }
    }
    output = _good_output()
    output["deal_recommendations"] = [
        {
            "type": "closing_condition",
            "text": "Require the fix before signing.",
            "basis_ids": ["C-001"],
        }
    ]
    narrative_env.outputs = [output]
    result = generate_narrative(payload)
    assert result["valid"] is True
    (rec,) = result["deal_recommendations"]
    assert rec["basis_ids"] == ["C-001", "F-001"]


def test_scores_one_decimal_in_input(narrative_env):
    narrative_env.outputs = [_good_output()]
    generate_narrative(_payload())
    sent = narrative_env.calls[0]["messages"][1]["content"]
    labeled = json.loads(sent)
    assert labeled["overall"]["score"] == "72.5"
    assert labeled["function_scores"][0]["score"] == "60.0"


def test_decision_in_prompt_not_in_labeled_input(narrative_env):
    narrative_env.outputs = [_good_output()]
    generate_narrative(_payload())
    messages = narrative_env.calls[0]["messages"]
    labeled = json.loads(messages[1]["content"])
    assert "decision" not in labeled["overall"]
    system = messages[0]["content"]
    assert "The overall decision is: Proceed with conditions." in system
    assert "must not be restated in deal recommendations" in system
    assert "must not be restated in any recommendation" in system


def test_trailing_signal_restatement_flagged():
    output = _good_output()
    output["deal_recommendations"][0]["text"] = (
        "Require the fix in Days 31-60 [F-001], consistent with the "
        "escalate decision."
    )
    errors = validate_narrative(
        output,
        **_validate_ids(),
        deal_label="Escalate: full cyber diligence required before signing",
    )
    assert any(
        "ends by restating the deal signal" in error for error in errors
    )
    output["deal_recommendations"][0]["text"] = (
        "No adjustment is warranted under Proceed with conditions."
    )
    errors = validate_narrative(
        output, **_validate_ids(), deal_label="Proceed with conditions"
    )
    assert any(
        "ends by restating the deal signal" in error for error in errors
    )


def test_trailing_signal_check_ignores_clean_text():
    output = _good_output()
    output["deal_recommendations"][0]["text"] = (
        "Confirm insurability and likely underwriting requirements "
        "before close [F-001]."
    )
    errors = validate_narrative(
        output,
        **_validate_ids(),
        deal_label="Escalate: full cyber diligence required before signing",
    )
    assert errors == []
    assert (
        validate_narrative(_good_output(), **_validate_ids()) == []
    )


def test_trailing_signal_restatement_regenerates(narrative_env):
    bad = _good_output()
    bad["deal_recommendations"][0]["text"] = (
        "Require the fix [F-001], consistent with the proceed decision."
    )
    narrative_env.outputs = [bad, _good_output()]
    result = generate_narrative(_payload())
    assert result["regenerated"] is True
    assert result["valid"] is True
    assert any(
        "ends by restating the deal signal" in error
        for error in result["first_attempt_errors"]
    )


def test_two_decimal_score_flagged():
    output = _good_output()
    output["executive_summary"] = (
        "Bottom line: rating C [F-001]. Key risks: score 72.50. "
        "Management credibility: ok [C-001]. Next steps: none."
    )
    errors = validate_narrative(output, **_validate_ids())
    assert any("2+ decimals" in error for error in errors)
