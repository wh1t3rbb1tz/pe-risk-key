# SPDX-License-Identifier: AGPL-3.0-or-later
"""Tests for scripts/runs_audit.py (tmp runs dir, never eval/runs/)."""

import importlib.util
import json
from pathlib import Path

from test_api import _complete_digest

from pe_risk_key.api import app as api_app

ROOT = Path(__file__).resolve().parents[1]


def _load_audit():
    spec = importlib.util.spec_from_file_location(
        "runs_audit", ROOT / "scripts" / "runs_audit.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _write(runs_dir, digest_id, digest):
    run_dir = runs_dir / digest_id
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / "digest.json").write_text(
        json.dumps(digest), encoding="utf-8"
    )
    (run_dir / "trace.jsonl").write_text(
        json.dumps({"seq": 1, "type": "narrative_complete", "valid": True})
        + "\n"
        + json.dumps({"seq": 2, "type": "run_end", "usage": {}})
        + "\n",
        encoding="utf-8",
    )


def test_audit_lists_and_archives(monkeypatch, tmp_path, capsys):
    runs = tmp_path / "runs"
    runs.mkdir()
    monkeypatch.setattr(api_app, "RUNS_DIR", runs)
    audit = _load_audit()
    good = _complete_digest(
        "dg_000000000001", "2026-03-01T00:00:00+00:00"
    )
    good["target"] = {
        "name": "Wrong Name",
        "domain": "brightwaterfleet.example",
        "employee_band": "201-1000",
        "revenue_band": "50M-250M",
    }
    _write(runs, "dg_000000000001", good)
    _write(runs, "dg_000000000002", {"digest_id": "dg_000000000002"})
    (runs / "dg_000000000003").mkdir()
    assert audit.main([]) == 0
    listed = capsys.readouterr().out
    assert "dg_000000000001" in listed
    assert "authoritative" in listed
    assert "differs from fixture" in listed
    assert "dg_000000000002" in listed
    assert "dg_000000000003" in listed
    assert audit.main(["--archive"]) == 0
    assert (runs / "dg_000000000001" / "digest.json").exists()
    assert (runs / "_archive" / "dg_000000000002").is_dir()
    assert (runs / "_archive" / "dg_000000000003").is_dir()
    assert not (runs / "dg_000000000002").exists()
