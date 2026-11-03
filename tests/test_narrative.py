"""Tests for pe_risk_key.engine.narrative (mocked model). No network."""

import copy
import json

import pytest

import pe_risk_key.engine.narrative as narrative_module
from pe_risk_key.engine.narrative import (
    assemble_narrative,
    generate_narrative,
    needs_regeneration,
    recommendation_slots,
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
        "required_recommendations": {
            "closing_condition": {
                "guidance": ["verification before signing"],
                "trigger_findings": ["F-001"],
            }
        },
    }


def _good_output():
    return {
        "bottom_line": {
            "text": (
                "Proceed with conditions. Rating C reflects one "
                "critical gap and a score of 72.5."
            ),
            "basis_ids": ["F-001"],
        },
        "key_risks": {
            "text": "Email spoofing exposure with no sender authentication.",
            "basis_ids": ["F-001"],
        },
        "management_credibility": {
            "text": "The claim conflicts with test evidence.",
        },
        "next_steps": {
            "text": (
                "Enforce sender authentication; no SOC 2 report was "
                "provided."
            ),
            "basis_ids": ["F-001"],
        },
        "key_questions_for_management": [
            {
                "text": "Confirm sender authentication status?",
                "basis_ids": ["F-001"],
            },
            {
                "text": "Confirm the enforcement timeline?",
                "basis_ids": ["F-001"],
            },
            {
                "text": "Reconcile the claim with test evidence?",
                "basis_ids": ["C-001"],
            },
            {
                "text": "Provide the enforcement evidence?",
                "basis_ids": ["F-001"],
            },
        ],
        "deal_recommendations": [
            {"text": "Require DMARC enforcement before close."}
        ],
    }


def _validate_ids():
    return {
        "finding_ids": {"F-001"},
        "contradiction_ids": {"C-001"},
        "input_numbers": {"72.5"},
        "slot_types": ["closing_condition"],
    }


def test_unknown_basis_id_triggers_regeneration(narrative_env):
    bad = _good_output()
    bad["bottom_line"]["basis_ids"] = ["F-999"]
    narrative_env.outputs = [bad, _good_output()]
    result = generate_narrative(_payload())
    assert result["valid"] is True
    assert result["regenerated"] is True
    assert len(narrative_env.calls) == 2
    assert "Rating C reflects" in result["narrative"]["executive_summary"]
    retry_messages = narrative_env.calls[1]["messages"]
    assert "unknown id" in retry_messages[-1]["content"]


def test_unknown_id_fails_twice_and_is_kept(narrative_env):
    bad = _good_output()
    bad["bottom_line"]["basis_ids"] = ["F-999"]
    narrative_env.outputs = [bad, bad]
    result = generate_narrative(_payload())
    assert result["valid"] is False
    assert result["regenerated"] is True
    assert any("F-999" in e for e in result["validation_errors"])
    assert "[F-999]" in result["narrative"]["executive_summary"]


def test_number_not_in_input_is_flagged(narrative_env):
    bad = _good_output()
    bad["key_risks"]["text"] = "Costs run to 50000 with a gap."
    narrative_env.outputs = [bad, bad]
    result = generate_narrative(_payload())
    assert result["valid"] is False
    assert any("50000" in e for e in result["validation_errors"])


def test_validate_accepts_grounded_numbers():
    assert validate_narrative(_good_output(), **_validate_ids()) == []


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
    base_ids = {
        "finding_ids": {"F-001"},
        "contradiction_ids": {"C-001"},
        "slot_types": ["closing_condition"],
    }
    numbers = {"72.5"}
    for leak in (
        "escalate_full_diligence",
        "CAP-CRIT",
        "days_0_30",
        "PR.DS",
        "the PR function",
    ):
        output = _good_output()
        output["key_risks"]["text"] = f"Email spoofing exposure {leak}."
        errors = validate_narrative(
            output, input_numbers=numbers, **base_ids
        )
        assert any(
            "leaks" in error for error in errors
        ), f"no leak error for {leak!r}: {errors}"
    output = _good_output()
    output["key_questions_for_management"][0] = {
        "text": "Why did this happen?",
        "basis_ids": ["F-001"],
    }
    errors = validate_narrative(output, input_numbers=numbers, **base_ids)
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


def test_recommendation_slots_carry_deterministic_basis():
    from pe_risk_key.engine.narrative import required_recommendation_types

    findings = [
        {"finding_id": "F-001", "rule_id": "EMAIL-DMARC-NONE"},
        {"finding_id": "F-008", "rule_id": "KEV-POTENTIAL"},
    ]
    required = required_recommendation_types(
        findings=findings,
        caps_applied=["CAP-CRIT"],
        remediation_plan={
            "items": [{"window": "days_31_60", "finding_ids": ["F-001"]}],
            "total_cost_low_usd": 142000,
            "total_cost_high_usd": 643000,
        },
        revenue_midpoint_usd=150000000,
        soc2_analysis={"exceptions": [{"control_id": "CC6.1"}]},
    )
    slots = recommendation_slots(required, ["F-001", "F-008"])
    by_type = {slot["type"]: slot for slot in slots}
    assert by_type["closing_condition"]["basis_ids"] == ["F-008"]
    assert by_type["price_adjustment"]["basis_ids"] == ["F-001", "F-008"]
    assert by_type["full_diligence_scope"]["basis_ids"] == ["F-008"]
    assert all(slot["basis_ids"] for slot in slots)
    assert [slot["type"] for slot in slots] == list(required)


def test_slots_cover_cap_and_price_with_all_findings(narrative_env):
    payload = _payload()
    payload["findings"].append(
        {
            "finding_id": "F-002",
            "title": "Second gap",
            "severity": "low",
            "confidence": "low",
            "deal_impact": "Minor.",
            "evidence": [{"excerpt": "Noted."}],
            "remediation": {
                "summary": "Fix later.",
                "cost_low_usd": 1000,
                "cost_high_usd": 2000,
                "effort_weeks": 1,
            },
        }
    )
    payload["required_recommendations"] = {
        "closing_condition": {
            "guidance": ["verification before signing"],
            "trigger_findings": ["F-001"],
        },
        "price_adjustment": {
            "guidance": ["no adjustment is warranted"],
            "trigger_findings": [],
        },
    }
    output = _good_output()
    output["deal_recommendations"] = [
        {"text": "Require the fix before signing."},
        {"text": "No adjustment is warranted."},
    ]
    narrative_env.outputs = [output]
    result = generate_narrative(payload)
    assert result["valid"] is True
    (closing, price) = result["deal_recommendations"]
    assert closing["type"] == "closing_condition"
    assert closing["basis_ids"] == ["F-001"]
    assert "Require the fix before signing [F-001]." in closing["text"]
    assert price["type"] == "price_adjustment"
    assert price["basis_ids"] == ["F-001", "F-002"]
    assert "No adjustment is warranted [F-001] [F-002]." in price["text"]


def test_rec_count_mismatch_regenerates(narrative_env):
    payload = _payload()
    payload["required_recommendations"] = {
        "closing_condition": {
            "guidance": ["verification before signing"],
            "trigger_findings": ["F-001"],
        },
        "price_adjustment": {
            "guidance": ["no adjustment is warranted"],
            "trigger_findings": [],
        },
    }
    short = _good_output()
    full = _good_output()
    full["deal_recommendations"] = [
        {"text": "Require the fix before signing."},
        {"text": "No adjustment is warranted."},
    ]
    narrative_env.outputs = [short, full]
    result = generate_narrative(payload)
    assert result["regenerated"] is True
    assert result["valid"] is True
    assert any(
        "2 slots" in error for error in result["first_attempt_errors"]
    )


def test_credibility_counts_computed_from_verdicts():
    contradictions = [
        {
            "contradiction_id": f"C-{index:03d}",
            "verdict": (
                "contradicted" if index <= 7 else "supported"
            ),
        }
        for index in range(1, 10)
    ]
    narrative, _ = assemble_narrative(
        _good_output(),
        slots=[],
        contradictions=contradictions,
        has_interview=True,
    )
    summary = narrative["executive_summary"]
    assert (
        "Management credibility: Of 9 claims assessed, 7 were "
        "contradicted, 0 unsupported, 2 supported. The claim conflicts "
        "with test evidence "
        "[C-001] [C-002] [C-003] [C-004] [C-005] [C-006] [C-007]."
    ) in summary


def test_credibility_no_interview_or_no_claims(narrative_env):
    payload = _payload()
    payload["has_interview"] = False
    narrative_env.outputs = [_good_output()]
    result = generate_narrative(payload)
    assert result["valid"] is True
    assert (
        "Management credibility: Not assessed: no management "
        "interview provided." in result["narrative"]["executive_summary"]
    )
    narrative, _ = assemble_narrative(
        _good_output(),
        slots=[],
        contradictions=[],
        has_interview=True,
    )
    assert "No management claims were assessed." in narrative[
        "executive_summary"
    ]


def test_assembled_summary_keeps_all_sections_with_chips():
    output = _good_output()
    output["bottom_line"] = {
        "text": (
            "Escalate: full cyber diligence required before signing. "
            "Brightwater scored 55.5 with a D rating, capped by a "
            "critical, potentially exploitable exposure."
        ),
        "basis_ids": ["F-008", "F-009"],
    }
    narrative, _ = assemble_narrative(
        output,
        slots=[],
        contradictions=_payload()["contradictions"],
        has_interview=True,
    )
    summary = narrative["executive_summary"]
    for label in (
        "Bottom line:",
        "Key risks:",
        "Management credibility:",
        "Next steps:",
    ):
        assert label in summary
    assert "exploitable exposure [F-008] [F-009]." in summary
    assert narrative["key_questions_for_management"][0] == (
        "Confirm sender authentication status [F-001]?"
    )


def test_no_soc2_statement_required():
    errors = validate_narrative(
        _good_output(), has_soc2=False, **_validate_ids()
    )
    assert errors == []
    output = _good_output()
    output["next_steps"]["text"] = "Enforce sender authentication."
    errors = validate_narrative(output, has_soc2=False, **_validate_ids())
    assert any("no SOC 2" in error for error in errors)


def test_question_counts_by_evidence_size():
    many_questions = _good_output()
    many_questions["key_questions_for_management"].append(
        {"text": "Confirm one more control?", "basis_ids": ["F-001"]}
    )
    errors = validate_narrative(many_questions, **_validate_ids())
    assert any("need 3-4" in error for error in errors)
    full = dict(_validate_ids())
    full["finding_ids"] = {"F-001", "F-002", "F-003", "F-004"}
    errors = validate_narrative(_good_output(), **full)
    assert any("need 5-8" in error for error in errors)


def _repairable_output():
    output = _good_output()
    output["key_risks"]["text"] = "Email spoofing exposure scores 72.50."
    output["deal_recommendations"][0]["text"] = (
        "Require the fix in Days 31-60, consistent with Proceed with "
        "conditions."
    )
    output["deal_recommendations"].append(
        {"text": "No adjustment is warranted under proceed_with_conditions."}
    )
    return output


def test_repair_rounds_scores():
    fixed, repairs = repair_narrative(
        _repairable_output(), deal_label="Go"
    )
    assert "72.5" in fixed["key_risks"]["text"]
    assert "72.50" not in fixed["key_risks"]["text"]
    assert any("rounded 72.50" in repair for repair in repairs)


def test_repair_replaces_tokens_with_labels():
    fixed, repairs = repair_narrative(
        _repairable_output(), deal_label="Go"
    )
    text = fixed["deal_recommendations"][1]["text"]
    assert text == "No adjustment is warranted under Proceed with conditions."
    output = _good_output()
    output["key_risks"]["text"] += " Triggers CAP-CRIT in PR."
    fixed, _ = repair_narrative(output, deal_label="Go")
    assert "CAP-CRIT" not in fixed["key_risks"]["text"]
    assert "a critical, potentially exploitable exposure" in fixed[
        "key_risks"
    ]["text"]
    assert fixed["key_risks"]["text"].endswith("in Protect.")


def test_repair_removes_restated_decision_anywhere():
    output = _good_output()
    output["deal_recommendations"][0]["text"] = (
        "Require the fix in Days 31-60, consistent with full "
        "cyber diligence required before signing."
    )
    fixed, repairs = repair_narrative(
        output,
        deal_label="Escalate: full cyber diligence required before signing",
    )
    assert fixed["deal_recommendations"][0]["text"] == (
        "Require the fix in Days 31-60."
    )
    assert any("removed restated decision" in repair for repair in repairs)
    kept, kept_repairs = repair_narrative(
        _good_output(), deal_label="Proceed"
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
            "text": (
                "Require the fix, consistent with Escalate: full cyber "
                "diligence required before signing."
            )
        },
        {
            "text": (
                "No adjustment is warranted under Proceed with conditions."
            )
        },
        {"text": "Proceed on the basis that coverage holds."},
    ]
    fixed, _ = repair_narrative(
        output,
        deal_label="Escalate: full cyber diligence required before signing",
    )
    assert fixed["deal_recommendations"][0]["text"] == "Require the fix."
    kept, _ = repair_narrative(
        output,
        deal_label="Proceed with conditions",
    )
    assert (
        kept["deal_recommendations"][1]["text"]
        == "No adjustment is warranted."
    )
    verb, verb_repairs = repair_narrative(output, deal_label="Proceed")
    assert verb["deal_recommendations"][2]["text"] == (
        "Proceed on the basis that coverage holds."
    )
    assert verb_repairs == []


def test_repair_strips_run_dg_b808md3ua63f_restatements():
    texts = [
        "Make signing conditional on verification and a compromise "
        "assessment for the internet-facing ExampleGate SSL-VPN "
        "exposure during Days 0–30, with a bring-down of security "
        "representations at signing.",
        "Commission a scope covering the known-exploited-product "
        "exposure and independent validation of management "
        "representations, sequenced with the Days 0–30 work, to "
        "satisfy full cyber diligence required before signing "
        "[F-008].",
        "Seek a specific indemnity for pre-closing incident losses "
        "tied to the disclosed incident, informed by the Days 31–60 "
        "incident review and full cyber diligence required before "
        "signing [F-009].",
        "Proceed on the basis that the known incident is likely "
        "excluded from representations and warranties coverage, "
        "resolve any gap before close after the Days 31–60 review, "
        "and reflect full cyber diligence required before signing "
        "[F-009].",
        "Confirm insurability and likely underwriting requirements "
        "before close, using remediation of email spoofing and "
        "privileged-access controls in Days 31–60, within full cyber "
        "diligence required before signing [F-001] [F-010] [F-011].",
        "Impose a post-close covenant to complete the remaining "
        "remediation across Days 31–60 and Days 61–100, sequenced "
        "after full cyber diligence required before signing [F-010] "
        "[F-011] [F-012] [F-013] [F-001] [F-002] [F-004] [F-006] "
        "[F-009] [F-014].",
        "Do not seek a price adjustment on cyber grounds alone "
        "because total remediation of $142K–$643K is immaterial "
        "relative to the 50M-250M revenue band, but preserve full "
        "cyber diligence required before signing and the windows "
        "from Days 0–30 through After day 100 [F-008] [F-009].",
    ]
    output = {
        "bottom_line": {"text": "ok", "basis_ids": []},
        "key_risks": {"text": "ok", "basis_ids": []},
        "management_credibility": {"text": "ok"},
        "next_steps": {"text": "ok", "basis_ids": []},
        "key_questions_for_management": [],
        "deal_recommendations": [{"text": text} for text in texts],
    }
    fixed, repairs = repair_narrative(
        output,
        deal_label="Escalate: full cyber diligence required before signing",
    )
    cleaned = [rec["text"] for rec in fixed["deal_recommendations"]]
    removed = [r for r in repairs if "removed restated decision" in r]
    stripped = [r for r in repairs if "stripped inline" in r]
    assert len(removed) == 6
    assert len(stripped) == 18
    for text in cleaned:
        assert "full cyber diligence required before signing" not in text
        assert "[F-" not in text
    assert cleaned[0] == texts[0]
    assert cleaned[1] == (
        "Commission a scope covering the known-exploited-product "
        "exposure and independent validation of management "
        "representations, sequenced with the Days 0–30 work."
    )
    assert cleaned[6] == (
        "Do not seek a price adjustment on cyber grounds alone because "
        "total remediation of $142K–$643K is immaterial relative to the "
        "50M-250M revenue band, but preserve the windows from Days 0–30 "
        "through After day 100."
    )


def test_repair_trims_fields_and_dedupes_basis():
    output = _good_output()
    output["key_risks"]["text"] = (
        "First risk sentence here. " + "Padding sentence here. " * 40
    )
    output["key_risks"]["basis_ids"] = ["F-001", "F-001", "C-001"]
    fixed, repairs = repair_narrative(output, deal_label="Go")
    risks = fixed["key_risks"]["text"]
    assert len(risks) <= 400
    assert risks.endswith(".")
    assert fixed["key_risks"]["basis_ids"] == ["F-001", "C-001"]
    assert any("trimmed key_risks from" in repair for repair in repairs)
    assert any("deduped basis_ids" in repair for repair in repairs)
    for key in (
        "bottom_line",
        "key_risks",
        "management_credibility",
        "next_steps",
    ):
        assert key in fixed


def test_repair_truncates_credibility_to_one_sentence():
    output = _good_output()
    output["management_credibility"]["text"] = (
        "First interpretation here. Second interpretation here."
    )
    fixed, _ = repair_narrative(output, deal_label="Go")
    assert fixed["management_credibility"]["text"] == (
        "First interpretation here."
    )


def test_repaired_narrative_passes_without_regeneration(narrative_env):
    payload = _payload()
    payload["required_recommendations"]["price_adjustment"] = {
        "guidance": ["no adjustment is warranted"],
        "trigger_findings": [],
    }
    narrative_env.outputs = [_repairable_output()]
    narrative_env.calls = []
    result = generate_narrative(payload)
    assert result["valid"] is True
    assert result["regenerated"] is False
    assert len(narrative_env.calls) == 1
    assert result["narrative_repairs"] != []


def test_unmapped_leak_skips_regeneration(narrative_env):
    output = _good_output()
    output["key_risks"]["text"] += " See foo_bar for details."
    narrative_env.outputs = [output]
    narrative_env.calls = []
    result = generate_narrative(_payload())
    assert result["valid"] is False
    assert result["regenerated"] is False
    assert len(narrative_env.calls) == 1
    assert needs_regeneration(result["validation_errors"]) is False
    assert needs_regeneration(["bottom_line cites unknown id 'F-999'."])


def test_speculation_phrasing_flagged():
    output = _good_output()
    output["key_risks"]["text"] = (
        "Email data may contain secrets from exposure."
    )
    errors = validate_narrative(output, **_validate_ids())
    assert any("may contain" in error for error in errors)
    output = _good_output()
    output["key_questions_for_management"][0] = {
        "text": "Confirm the host is isolated if present?",
        "basis_ids": ["F-001"],
    }
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


def test_shared_leading_clause_flagged():
    output = _good_output()
    output["deal_recommendations"] = [
        {
            "text": "Proceed with conditions and require the buyer to verify controls."
        },
        {
            "text": "Proceed with conditions and require the buyer to confirm coverage."
        },
    ]
    ids = _validate_ids()
    ids["slot_types"] = ["closing_condition", "price_adjustment"]
    errors = validate_narrative(output, **ids)
    assert any("leading clause" in error for error in errors)


def test_type_label_prefix_flagged():
    output = _good_output()
    output["deal_recommendations"] = [
        {"text": "Closing condition: require the fix before signing."}
    ]
    errors = validate_narrative(output, **_validate_ids())
    assert any("own type label" in error for error in errors)


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
    assert "required_recommendations" not in labeled
    assert labeled["available_ids"] == ["C-001", "F-001"]
    (slot,) = labeled["recommendation_slots"]
    assert slot["index"] == 0
    assert slot["type"] == "Closing condition"
    assert slot["basis_ids"] == ["F-001"]
    system = messages[0]["content"]
    assert "The overall decision is: Proceed with conditions." in system
    assert "must not be restated in deal recommendations" in system
    assert "must not be restated in any recommendation" in system


def test_trailing_signal_restatement_flagged():
    output = _good_output()
    output["deal_recommendations"][0]["text"] = (
        "Require the fix in Days 31-60, consistent with the "
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
        "before close."
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
        "Require the fix, consistent with the proceed decision."
    )
    narrative_env.outputs = [bad, _good_output()]
    result = generate_narrative(_payload())
    assert result["regenerated"] is True
    assert result["valid"] is True
    assert any(
        "ends by restating the deal signal" in error
        for error in result["first_attempt_errors"]
    )


def test_window_numbers_ground_despite_en_dashes(narrative_env):
    output = _good_output()
    output["deal_recommendations"][0]["text"] = (
        "Require the fix in Days 31–60."
    )
    narrative_env.outputs = [output]
    result = generate_narrative(_payload())
    assert result["valid"] is True


def test_two_decimal_score_flagged():
    output = _good_output()
    output["key_risks"]["text"] = "The score is 72.50 this quarter."
    errors = validate_narrative(output, **_validate_ids())
    assert any("2+ decimals" in error for error in errors)
