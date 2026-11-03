"""Tests for pe_risk_key.mcp_server (tool functions called directly)."""

import json

import pytest

from pe_risk_key.api import app as api_app
from pe_risk_key.mcp_server import (
    compare_targets,
    explain_finding,
    get_risk_digest,
    list_digests,
)


@pytest.fixture
def runs_dir(monkeypatch, tmp_path):
    runs = tmp_path / "runs"
    runs.mkdir()
    monkeypatch.setattr(api_app, "RUNS_DIR", runs)
    return runs


def _digest(
    digest_id,
    company,
    domain,
    generated_at,
    rating="C",
    score=70.0,
    summary="Bottom line: ok.",
    findings=None,
    contradictions=None,
    documents=None,
    interviews=None,
):
    return {
        "schema_version": "1.0.0",
        "digest_id": digest_id,
        "generated_at": generated_at,
        "target": {
            "name": company,
            "domain": domain,
            "employee_band": "201-1000",
            "revenue_band": "50M-250M",
        },
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
        "inputs": {
            "domain_scan": True,
            "documents": documents or [],
            "interviews": interviews or [],
        },
        "overall": {
            "score": score,
            "rating": rating,
            "deal_signal": "proceed",
            "confidence": "medium",
            "rating_caps_applied": [],
        },
        "function_scores": [
            {
                "function": function,
                "score": 80.0,
                "finding_count": 0,
                "assessed": True,
            }
            for function in ("GV", "ID", "PR", "DE", "RS", "RC")
        ],
        "findings": findings or [],
        "contradictions": contradictions or [],
        "remediation_plan": {
            "items": [],
            "total_cost_low_usd": 1000,
            "total_cost_high_usd": 5000,
        },
        "deal_recommendations": [],
        "narrative": {"executive_summary": summary},
        "limitations": ["Demo."],
    }


def _finding(finding_id="F-001", severity="high", evidence_id="E-001"):
    return {
        "finding_id": finding_id,
        "title": "DMARC not enforced",
        "severity": severity,
        "confidence": "high",
        "csf_function": "PR",
        "csf_category": "PR.AC",
        "source": "outside_in",
        "evidence": [
            {
                "evidence_id": evidence_id,
                "source_type": "outside_in",
                "collection_method": "dns_query",
                "locator": "_dmarc.x TXT",
                "excerpt": "no record",
            }
        ],
        "deal_impact": "Spoofing risk.",
        "remediation": {
            "summary": "Enforce DMARC.",
            "cost_low_usd": 8000,
            "cost_high_usd": 30000,
            "effort_weeks": 8,
        },
    }


def _doc():
    return {
        "doc_id": "doc_soc2x",
        "type": "soc2_type2",
        "filename": "soc2.md",
        "sha256": "ab" * 32,
    }


def _interview():
    return {
        "interview_id": "int_iv01",
        "filename": "iv.wav",
        "sha256": "cd" * 32,
        "duration_seconds": 60,
    }


def _contradiction(contradiction_id, refs):
    return {
        "contradiction_id": contradiction_id,
        "claim": {
            "speaker": "CTO",
            "timestamp": "01:00",
            "text": "Mail is secure.",
            "claim_type": "control_exists",
        },
        "verdict": "contradicted",
        "severity": "high",
        "evidence_refs": refs,
        "explanation": "DMARC missing.",
    }


def _write(runs_dir, digest, narrative_valid=True):
    run_dir = runs_dir / digest["digest_id"]
    run_dir.mkdir()
    (run_dir / "digest.json").write_text(
        json.dumps(digest), encoding="utf-8"
    )
    (run_dir / "trace.jsonl").write_text(
        json.dumps(
            {"seq": 1, "type": "narrative_complete", "valid": narrative_valid}
        )
        + "\n"
        + json.dumps({"seq": 2, "type": "run_end", "usage": {}})
        + "\n",
        encoding="utf-8",
    )


def test_list_digests_complete_only(runs_dir):
    _write(
        runs_dir,
        _digest(
            "dg_000000000001", "Acme", "acme.example",
            "2026-03-01T00:00:00+00:00",
        ),
    )
    _write(
        runs_dir,
        _digest(
            "dg_000000000002", "Beta", "beta.example",
            "2026-04-01T00:00:00+00:00",
            summary="Narrative pending.",
        ),
    )
    _write(runs_dir, {"digest_id": "dg_000000000003"})
    assert list_digests() == [
        {
            "digest_id": "dg_000000000001",
            "company": "Acme",
            "rating": "C",
            "decision": "Proceed",
            "date": "2026-03-01",
            "inputs": {
                "domain_scan": True,
                "documents": [],
                "interviews": [],
            },
            "schema_valid": True,
            "narrative_valid": True,
        }
    ]


def test_domain_resolves_to_authoritative_run(runs_dir):
    _write(
        runs_dir,
        _digest(
            "dg_000000000001", "Acme", "acme.example",
            "2026-01-01T00:00:00+00:00", rating="D", score=40.0,
            documents=[_doc()], interviews=[_interview()],
        ),
    )
    _write(
        runs_dir,
        _digest(
            "dg_000000000002", "Acme", "acme.example",
            "2026-05-01T00:00:00+00:00", rating="B", score=82.5,
        ),
    )
    digest = get_risk_digest(domain="acme.example")
    assert digest["digest_id"] == "dg_000000000001"
    assert digest["inputs"]["documents"] != []
    assert digest["inputs"]["interviews"] != []
    assert digest["superseded_runs"] == 1
    assert [entry["digest_id"] for entry in list_digests()] == [
        "dg_000000000001"
    ]
    assert [entry["digest_id"] for entry in list_digests(True)] == [
        "dg_000000000002",
        "dg_000000000001",
    ]


def test_get_risk_digest_latest_by_domain(runs_dir):
    _write(
        runs_dir,
        _digest(
            "dg_000000000001", "Acme", "acme.example",
            "2026-01-01T00:00:00+00:00", rating="D", score=40.0,
            findings=[_finding()],
            contradictions=[_contradiction("C-001", ["E-001"])],
        ),
    )
    _write(
        runs_dir,
        _digest(
            "dg_000000000002", "Acme", "acme.example",
            "2026-05-01T00:00:00+00:00", rating="B", score=82.5,
        ),
    )
    latest = get_risk_digest(domain="acme.example")
    assert latest["digest_id"] == "dg_000000000002"
    assert latest["rating"] == "B"
    assert latest["score"] == 82.5
    by_id = get_risk_digest(digest_id="dg_000000000001")
    assert by_id["company"] == "Acme"
    assert by_id["decision"] == "Proceed"
    assert by_id["caps"] == []
    assert by_id["confidence"] == "medium"
    assert by_id["top_risks"][0]["finding_id"] == "F-001"
    assert by_id["top_risks"][0]["cost"] == "$8K–$30K"
    assert by_id["contradiction_counts"]["contradicted"] == 1
    assert by_id["remediation_total"]["display"] == "$1K–$5K"
    assert by_id["executive_summary"] == "Bottom line: ok."
    with pytest.raises(ValueError):
        get_risk_digest(domain="missing.example")
    with pytest.raises(ValueError):
        get_risk_digest()


def test_explain_finding(runs_dir):
    _write(
        runs_dir,
        _digest(
            "dg_000000000001", "Acme", "acme.example",
            "2026-01-01T00:00:00+00:00",
            findings=[
                _finding("F-001", "high", "E-001"),
                _finding("F-002", "low", "E-002"),
            ],
            contradictions=[
                _contradiction("C-001", ["E-001"]),
                _contradiction("C-002", ["F-001"]),
                _contradiction("C-003", ["F-002"]),
            ],
        ),
    )
    explained = explain_finding("dg_000000000001", "F-001")
    assert explained["title"] == "DMARC not enforced"
    assert explained["evidence"][0]["locator"] == "_dmarc.x TXT"
    assert explained["evidence"][0]["collection_method"] == "dns_query"
    assert explained["remediation"]["cost"] == "$8K–$30K"
    assert explained["remediation"]["effort_weeks"] == 8
    assert [
        item["contradiction_id"]
        for item in explained["contradictions_citing"]
    ] == ["C-001", "C-002"]
    with pytest.raises(ValueError):
        explain_finding("dg_000000000001", "F-999")
    with pytest.raises(ValueError):
        explain_finding("dg_999999999999", "F-001")


def test_compare_targets(runs_dir):
    _write(
        runs_dir,
        _digest(
            "dg_000000000001", "Acme", "acme.example",
            "2026-01-01T00:00:00+00:00", rating="D", score=41.2,
            findings=[_finding("F-001", "critical")],
            contradictions=[_contradiction("C-001", ["F-001"])],
        ),
    )
    _write(
        runs_dir,
        _digest(
            "dg_000000000002", "Beta", "beta.example",
            "2026-02-01T00:00:00+00:00", rating="B", score=81.0,
        ),
    )
    compared = compare_targets(["dg_000000000001", "dg_000000000002"])
    (acme, beta) = compared["targets"]
    assert acme["critical_count"] == 1
    assert acme["contradicted_count"] == 1
    assert acme["assessed_functions"] == ["GV", "ID", "PR", "DE", "RS", "RC"]
    assert beta["critical_count"] == 0
    assert compared["relative_risk"] == (
        "Highest to lowest risk: Acme (D, 41.2); Beta (B, 81.0)."
    )
    reversed_order = compare_targets(
        ["dg_000000000002", "dg_000000000001"]
    )
    assert (
        reversed_order["relative_risk"] == compared["relative_risk"]
    )
    with pytest.raises(ValueError):
        compare_targets(["dg_000000000001"])
    with pytest.raises(ValueError):
        compare_targets(["a", "b", "c", "d"])
