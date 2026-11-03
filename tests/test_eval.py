# SPDX-License-Identifier: AGPL-3.0-or-later
"""Tests for scripts/eval.py. No network, no live runs, fixed inputs."""

import importlib.util
import json
from pathlib import Path
from unittest.mock import Mock

ROOT = Path(__file__).resolve().parents[1]


def _load_script():
    spec = importlib.util.spec_from_file_location(
        "eval_script", ROOT / "scripts" / "eval.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _write_run(runs_dir, digest_id, cost, full):
    run_dir = runs_dir / digest_id
    run_dir.mkdir(parents=True)
    inputs: dict = {"domain_scan": True}
    if full:
        inputs["documents"] = [{"doc_id": "doc_x"}]
        inputs["interviews"] = [{"interview_id": "int_x"}]
    (run_dir / "digest.json").write_text(
        json.dumps({"digest_id": digest_id, "inputs": inputs}),
        encoding="utf-8",
    )
    (run_dir / "trace.jsonl").write_text(
        json.dumps(
            {
                "seq": 1,
                "type": "run_end",
                "usage": {"estimated_cost_usd": cost},
            }
        )
        + "\n",
        encoding="utf-8",
    )


def test_yes_guard_refuses_without_flag(capsys, tmp_path):
    script = _load_script()
    script.RUNS_DIR = tmp_path / "runs"
    runner = Mock()
    assert script.main([], runner=runner) == 2
    runner.assert_not_called()
    out = capsys.readouterr().out
    assert "Re-run with --yes" in out


def test_yes_runs_all_targets_with_counts(tmp_path, monkeypatch, capsys):
    script = _load_script()
    monkeypatch.delenv("DEMO_MODE", raising=False)
    script.RUNS_DIR = tmp_path / "runs"
    script.RESULTS_DIR = tmp_path / "results"
    runner = Mock(side_effect=RuntimeError("boom"))
    assert (
        script.main(
            ["--yes", "--brightwater-runs", "1", "--copperline-runs", "1"],
            runner=runner,
        )
        == 0
    )
    assert runner.call_count == 2
    brightwater_kwargs = runner.call_args_list[0].kwargs
    assert brightwater_kwargs["soc2_path"].endswith(
        "brightwater_soc2_type2.md"
    )
    assert brightwater_kwargs["interview_path"].endswith(
        "brightwater_cto_interview.wav"
    )
    assert str(brightwater_kwargs["as_of"]) == "2026-10-30"
    copperline_kwargs = runner.call_args_list[1].kwargs
    assert "soc2_path" not in copperline_kwargs
    assert "interview_path" not in copperline_kwargs
    assert len(list((tmp_path / "results").glob("*.json"))) == 1
    assert len(list((tmp_path / "results").glob("*.md"))) == 1


def test_estimate_cost_from_recent_runs(tmp_path):
    script = _load_script()
    runs_dir = tmp_path / "runs"
    _write_run(runs_dir, "dg_full00000001", 1.0, full=True)
    _write_run(runs_dir, "dg_full00000002", 3.0, full=True)
    _write_run(runs_dir, "dg_oi00000000001", 0.5, full=False)
    estimate = script.estimate_cost(runs_dir, 3, 2)
    assert estimate["full_mean_usd"] == 2.0
    assert estimate["outside_in_mean_usd"] == 0.5
    assert estimate["estimated_total_usd"] == 7.0


def test_estimate_cost_unknown_without_history(tmp_path):
    script = _load_script()
    estimate = script.estimate_cost(tmp_path / "empty", 3, 2)
    assert estimate["estimated_total_usd"] is None


def _scored(
    digest_id,
    recall,
    precision,
    contra_recall,
    accuracy,
    schema_valid=True,
    narrative_valid=True,
    rating_match=True,
    profile_match=True,
    score=70.0,
    cost=1.0,
    deterministic=True,
):
    return {
        "status": "ok",
        "digest_id": digest_id,
        "schema_valid": schema_valid,
        "findings": {"recall": recall, "precision": precision},
        "contradictions": {
            "recall": contra_recall,
            "accuracy": accuracy,
            "total_expected": 9 if contra_recall is not None else 0,
        },
        "narrative_valid": narrative_valid,
        "profile": {
            "rating_match": rating_match,
            "profile_match": profile_match,
        },
        "score": score,
        "cost_usd": cost,
        "deterministic_scoring": deterministic,
    }


def test_aggregate_mean_min_and_rates():
    script = _load_script()
    agg = script.aggregate(
        [
            _scored("dg_1", 1.0, 0.8, 0.9, 1.0, score=70.0, cost=1.0),
            _scored(
                "dg_2",
                0.5,
                0.6,
                0.5,
                0.5,
                schema_valid=False,
                narrative_valid=False,
                rating_match=False,
                profile_match=False,
                score=80.0,
                cost=3.0,
            ),
        ]
    )
    assert agg["runs"] == 2
    assert agg["finding_recall_mean"] == 0.75
    assert agg["finding_recall_min"] == 0.5
    assert agg["verdict_accuracy_mean"] == 0.75
    assert agg["schema_pass_rate"] == 0.5
    assert agg["narrative_pass_rate"] == 0.5
    assert agg["rating_match_fraction"] == 0.5
    assert agg["score_mean"] == 75.0
    assert agg["score_variance"] == 25.0
    assert agg["determinism_fraction"] == 1.0
    assert agg["total_cost_usd"] == 4.0


def test_check_scoring_determinism_fixed_input():
    script = _load_script()
    digest = {
        "target": {"revenue_band": "50M-250M"},
        "inputs": {"domain_scan": True},
        "findings": [
            {
                "finding_id": "F-001",
                "severity": "high",
                "confidence": "high",
                "csf_function": "PR",
                "csf_category": "PR.AC",
            }
        ],
        "contradictions": [],
    }
    result = script.check_scoring_determinism(digest)
    assert result["deterministic"] is True
    assert result["scored_bytes"] > 0


def test_render_markdown_has_tables():
    script = _load_script()
    scored = _scored("dg_abc", 1.0, 1.0, 1.0, 1.0)
    scored["narrative_attempts"] = 1
    scored["wall_seconds"] = 60.0
    scored["profile"].update(
        {
            "rating_got": "D",
            "rating_want": "D",
        }
    )
    per_target = {
        "brightwaterfleet.example": {
            "run_count": 1,
            "label": "outside-in + SOC 2 + interview",
            "runs": [scored],
            "aggregate": script.aggregate([scored]),
        }
    }
    results = {
        "date": "2026-11-03",
        "models": ["muse-wonder-1.0"],
        "total_runs": 1,
        "targets": {},
        "aggregate": script.aggregate([scored]),
        "total_cost_usd": 1.0,
    }
    markdown = script.render_markdown(results, per_target)
    assert "# Eval results — 2026-11-03" in markdown
    assert "muse-wonder-1.0" in markdown
    assert "| run | finding recall |" in markdown
    assert "`dg_abc`" in markdown
    assert "## Aggregate" in markdown
