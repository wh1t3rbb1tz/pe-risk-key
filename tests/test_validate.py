"""Tests for pe_risk_key.validate: schema + cross-reference checks."""

import copy

from pe_risk_key.validate import validate_digest


def _valid_digest() -> dict:
    return {
        "schema_version": "1.0.0",
        "digest_id": "dg_abc123def456",
        "generated_at": "2026-10-28T00:00:00Z",
        "target": {"name": "Acme", "domain": "acme.example"},
        "mode": {
            "confidential": False,
            "providers": [
                {
                    "role": "orchestrator",
                    "provider": "meta_model_api",
                    "model": "muse-wonder-1.0",
                }
            ],
        },
        "inputs": {"domain_scan": True, "documents": [], "interviews": []},
        "overall": {
            "score": 62.5,
            "rating": "C",
            "deal_signal": "proceed_with_conditions",
            "confidence": "medium",
            "rating_caps_applied": [],
        },
        "function_scores": [
            {
                "function": "PR",
                "score": 60.0,
                "finding_count": 1,
                "assessed": True,
            }
        ],
        "findings": [
            {
                "finding_id": "F-001",
                "title": "DMARC policy missing",
                "severity": "medium",
                "confidence": "high",
                "csf_function": "PR",
                "csf_category": "PR.AC",
                "source": "outside_in",
                "evidence": [
                    {
                        "evidence_id": "E-001",
                        "source_type": "outside_in",
                        "collection_method": "dns_query",
                        "locator": "_dmarc.acme.example TXT",
                        "excerpt": "No DMARC record published.",
                    }
                ],
                "deal_impact": "Phishing risk against the brand.",
                "remediation": {
                    "summary": "Publish a DMARC reject policy.",
                    "cost_low_usd": 2000,
                    "cost_high_usd": 5000,
                    "effort_weeks": 1,
                },
            }
        ],
        "contradictions": [
            {
                "contradiction_id": "C-001",
                "claim": {
                    "speaker": "CISO",
                    "timestamp": "12:34",
                    "text": "We enforce DMARC reject on all domains.",
                    "claim_type": "control_exists",
                },
                "verdict": "contradicted",
                "severity": "medium",
                "evidence_refs": ["E-001", "F-001"],
                "explanation": "No DMARC record exists for the apex domain.",
            }
        ],
        "remediation_plan": {
            "items": [
                {
                    "action": "Publish DMARC reject policy.",
                    "finding_ids": ["F-001"],
                    "window": "days_0_30",
                    "cost_low_usd": 2000,
                    "cost_high_usd": 5000,
                }
            ],
            "total_cost_low_usd": 2000,
            "total_cost_high_usd": 5000,
        },
        "deal_recommendations": [
            {
                "type": "closing_condition",
                "text": "Require DMARC enforcement before close.",
                "basis_ids": ["F-001", "C-001"],
            }
        ],
        "narrative": {"executive_summary": "Email authentication gaps remain."},
        "limitations": ["No internal access; outside-in signals only."],
    }


def test_valid_digest_has_no_errors():
    assert validate_digest(_valid_digest()) == []


def test_non_object_digest_rejected():
    assert validate_digest(["not", "a", "dict"]) != []


def test_schema_violation_reported():
    digest = _valid_digest()
    digest["findings"][0]["severity"] = "bogus"
    errors = validate_digest(digest)
    assert any("bogus" in e for e in errors)


def test_contradiction_dangling_evidence_ref():
    digest = _valid_digest()
    digest["contradictions"][0]["evidence_refs"] = ["E-999"]
    errors = validate_digest(digest)
    assert len(errors) == 1
    assert "E-999" in errors[0] and "C-001" in errors[0]


def test_contradiction_dangling_finding_ref():
    digest = _valid_digest()
    digest["contradictions"][0]["evidence_refs"] = ["F-404"]
    errors = validate_digest(digest)
    assert len(errors) == 1
    assert "F-404" in errors[0] and "C-001" in errors[0]


def test_deal_recommendation_dangling_basis_ids():
    digest = _valid_digest()
    digest["deal_recommendations"][0]["basis_ids"] = ["F-404", "C-404"]
    errors = validate_digest(digest)
    assert len(errors) == 2
    assert any("F-404" in e for e in errors)
    assert any("C-404" in e for e in errors)


def test_remediation_plan_dangling_finding_id():
    digest = _valid_digest()
    digest["remediation_plan"]["items"][0]["finding_ids"] = ["F-404"]
    errors = validate_digest(digest)
    assert len(errors) == 1
    assert "F-404" in errors[0] and "remediation_plan" in errors[0]


def test_fixture_not_mutated_across_tests():
    first = _valid_digest()
    digest = _valid_digest()
    digest["contradictions"][0]["evidence_refs"] = ["E-999"]
    assert validate_digest(digest) != []
    assert validate_digest(first) == []
    assert copy.deepcopy(first) == _valid_digest()
