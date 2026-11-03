# SPDX-License-Identifier: AGPL-3.0-or-later
"""Tests for scripts/update_readme_results.py (tmp files only)."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest


def _load_updater():
    path = (
        Path(__file__).resolve().parents[1]
        / "scripts"
        / "update_readme_results.py"
    )
    spec = importlib.util.spec_from_file_location("update_readme_results", path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


@pytest.fixture()
def updater():
    return _load_updater()


@pytest.fixture()
def workspace(tmp_path):
    readme = tmp_path / "README.md"
    readme.write_text(
        "# Title\n\n<!-- EVAL:START -->\nold eval\n<!-- EVAL:END -->\n\n"
        "<!-- COST:START -->\nold cost\n<!-- COST:END -->\n",
        encoding="utf-8",
    )
    latest = tmp_path / "LATEST.md"
    latest.write_text(
        "# Eval 2026-11-03\n\n| Metric | Value |\n|---|---|\n| recall | 1.00 |\n",
        encoding="utf-8",
    )
    results = {
        "date": "2026-11-03",
        "targets": {
            "brightwater": {
                "runs": [
                    {
                        "status": "ok",
                        "cost_usd": 0.40,
                        "wall_seconds": 60.0,
                    },
                    {
                        "status": "ok",
                        "cost_usd": 0.30,
                        "wall_seconds": 80.0,
                    },
                    {"status": "error", "cost_usd": 1.00, "wall_seconds": 5.0},
                ]
            }
        },
    }
    results_path = tmp_path / "results.json"
    results_path.write_text(json.dumps(results), encoding="utf-8")
    return readme, latest, results_path


def test_eval_block_gets_latest_minus_h1(updater, workspace):
    readme, latest, results_path = workspace
    updater.update_readme(readme, latest, results_path)
    text = readme.read_text(encoding="utf-8")
    assert "# Eval 2026-11-03" not in text
    assert "| Metric | Value |" in text
    assert "old eval" not in text


def test_cost_block_gets_means_of_ok_runs(updater, workspace):
    readme, latest, results_path = workspace
    updater.update_readme(readme, latest, results_path)
    text = readme.read_text(encoding="utf-8")
    assert (
        "Mean $0.35 per run and 70s wall time across 2 runs "
        "(2026-11-03 eval)." in text
    )
    assert "old cost" not in text


def test_update_is_idempotent(updater, workspace):
    readme, latest, results_path = workspace
    updater.update_readme(readme, latest, results_path)
    first = readme.read_text(encoding="utf-8")
    updater.update_readme(readme, latest, results_path)
    assert readme.read_text(encoding="utf-8") == first


def test_missing_marker_raises(updater, workspace):
    readme, latest, results_path = workspace
    readme.write_text("# Title\n\nNo markers here.\n", encoding="utf-8")
    with pytest.raises(ValueError, match="EVAL:START"):
        updater.update_readme(readme, latest, results_path)


def test_no_results_dir_raises(updater, tmp_path):
    with pytest.raises(SystemExit, match="No eval results"):
        updater.latest_results_path(tmp_path)
