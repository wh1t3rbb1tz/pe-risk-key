"""Tests for scripts/run_digest.py print helpers. No network."""

import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _load_script():
    spec = importlib.util.spec_from_file_location(
        "run_digest_script", ROOT / "scripts" / "run_digest.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _contradiction(cid, text, verdict, severity="high", refs=("F-001",)):
    return {
        "contradiction_id": cid,
        "claim": {
            "speaker": "Dana Reyes (CTO)",
            "timestamp": "00:05",
            "text": text,
            "claim_type": "control_exists",
        },
        "verdict": verdict,
        "severity": severity,
        "evidence_refs": list(refs),
        "explanation": "Explanation text for the verdict.",
    }


def test_recall_matches_context_question(capsys):
    script = _load_script()
    contradictions = [
        _contradiction("C-001", "We can get one.", "supported")
    ]
    script.print_contradiction_recall(
        contradictions, "brightwaterfleet.example", {}
    )
    assert "contradiction recall: 0/9" in capsys.readouterr().out
    script.print_contradiction_recall(
        contradictions,
        "brightwaterfleet.example",
        {"We can get one.": "Can you provide a bridge letter on request?"},
    )
    out = capsys.readouterr().out
    assert "contradiction recall: 1/9" in out
    assert "verdict accuracy: 1/1" in out


def test_print_contradictions(capsys):
    script = _load_script()
    script.print_contradictions(
        [
            _contradiction(
                "C-001",
                "DMARC is enforced.",
                "contradicted",
                "high",
                ("F-002", "E-002"),
            ),
            _contradiction(
                "C-002",
                "Backups are immutable.",
                "supported",
                "info",
                ("E-010",),
            ),
        ],
        claim_count=2,
    )
    out = capsys.readouterr().out
    assert "contradictions (2):" in out
    assert "C-001 [contradicted/high] refs=F-002, E-002" in out
    assert "DMARC is enforced." in out
    assert "C-002 [supported/info] refs=E-010" in out
    assert "Explanation text for the verdict." in out
    assert "claims extracted: 2" in out


def test_print_catalog(capsys):
    script = _load_script()
    script.print_catalog(
        {
            "findings": 11,
            "outside_in_evidence": 9,
            "soc2_exceptions": 4,
            "soc2_no_exception": 4,
            "soc2_notables": 1,
        }
    )
    out = capsys.readouterr().out
    assert "findings=11" in out
    assert "outside_in=9" in out
    assert "soc2_exceptions=4" in out
    assert "soc2_no_exception=4" in out
    assert "soc2_notables=1" in out
    script.print_catalog(None)
    assert capsys.readouterr().out == ""


def test_print_narrative(capsys):
    script = _load_script()
    digest = {
        "narrative": {
            "executive_summary": "Rating C with a gap [F-001].",
            "key_questions_for_management": [
                "When is DMARC enforced [F-001]?"
            ],
        },
        "deal_recommendations": [
            {
                "type": "closing_condition",
                "text": "Require the fix.",
                "basis_ids": ["F-001"],
            }
        ],
    }
    trace = [{"type": "narrative_complete", "valid": True}]
    script.print_narrative(digest, trace)
    out = capsys.readouterr().out
    assert "Rating C with a gap" in out
    assert "key questions (1):" in out
    assert "When is DMARC enforced" in out
    assert "[closing_condition] Require the fix. (basis: F-001)" in out
    assert "narrative validation: valid=True" in out
