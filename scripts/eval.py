# SPDX-License-Identifier: AGPL-3.0-or-later
"""Evaluation harness: run the demo pipeline N times per fixture target.

Runs 3x Brightwater (outside-in + SOC 2 + interview) and 2x Copperline
(outside-in only) by default, all in demo mode with live model calls.
Scores each run against fixtures/expected/*.yaml and writes
eval/results/<timestamp>.json + .md, copying the markdown to
eval/LATEST.md.

Without --yes, prints the cost estimate from recent runs and exits.
Run manually via `make eval`, not from the test suite.
"""

import argparse
import json
import os
import statistics
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import yaml

from pe_risk_key.engine.eval_metrics import (
    match_contradictions,
    score_findings,
    score_profile,
)
from pe_risk_key.engine.scoring import score_digest
from pe_risk_key.validate import validate_digest

ROOT = Path(__file__).resolve().parents[1]
RUNS_DIR = ROOT / "eval" / "runs"
RESULTS_DIR = ROOT / "eval" / "results"
SCORING_PATH = ROOT / "scoring.yaml"

SPEAKER_NAMES = ["Diligence Lead", "Dana Reyes (CTO)"]
TARGET_SPEAKERS = ["Dana Reyes (CTO)"]

TARGETS = (
    {
        "name": "brightwaterfleet.example",
        "runs": 3,
        "profile_key": "expected_overall",
        "soc2": "fixtures/documents/brightwater_soc2_type2.md",
        "interview": "fixtures/interviews/brightwater_cto_interview.wav",
    },
    {
        "name": "copperline.example",
        "runs": 2,
        "profile_key": "expected_outside_in_only",
        "soc2": None,
        "interview": None,
    },
)


def _target_args(domain: str) -> dict:
    """run_digest kwargs from the outside-in fixture target block."""
    target = json.loads(
        (
            ROOT / "fixtures" / "outside_in" / f"{domain}.json"
        ).read_text(encoding="utf-8")
    )["target"]
    return {
        "domain": target["domain"],
        "company_name": target["name"],
        "employee_band": target["employee_band"],
        "revenue_band": target["revenue_band"],
        "industry": target.get("industry"),
    }


def _recent_costs(runs_dir: Path, limit: int = 20) -> list[dict]:
    """Newest-first (cost, profile) pairs from saved run traces."""
    entries = []
    if not runs_dir.exists():
        return entries
    run_dirs = sorted(
        (p for p in runs_dir.iterdir() if (p / "trace.jsonl").exists()),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )
    for run_dir in run_dirs[:limit]:
        try:
            digest = json.loads(
                (run_dir / "digest.json").read_text(encoding="utf-8")
            )
            cost = None
            for line in (
                (run_dir / "trace.jsonl").read_text(encoding="utf-8")
            ).splitlines():
                event = json.loads(line)
                if event.get("type") == "run_end":
                    cost = (event.get("usage") or {}).get(
                        "estimated_cost_usd"
                    )
            if cost is None:
                continue
            inputs = digest.get("inputs", {})
            full = bool(inputs.get("documents")) and bool(
                inputs.get("interviews")
            )
            entries.append({"cost_usd": cost, "full": full})
        except (OSError, ValueError):
            continue
    return entries


def estimate_cost(
    runs_dir: Path, brightwater_runs: int, copperline_runs: int
) -> dict:
    """Mean cost per profile from recent runs, scaled to the plan."""
    entries = _recent_costs(runs_dir)
    full = [e["cost_usd"] for e in entries if e["full"]]
    outside_in = [e["cost_usd"] for e in entries if not e["full"]]
    full_mean = sum(full) / len(full) if full else None
    oi_mean = sum(outside_in) / len(outside_in) if outside_in else None
    total = 0.0
    if full_mean is not None:
        total += full_mean * brightwater_runs
    if oi_mean is not None:
        total += oi_mean * copperline_runs
    return {
        "full_runs_seen": len(full),
        "outside_in_runs_seen": len(outside_in),
        "full_mean_usd": full_mean,
        "outside_in_mean_usd": oi_mean,
        "brightwater_runs": brightwater_runs,
        "copperline_runs": copperline_runs,
        "estimated_total_usd": (
            total
            if full_mean is not None and oi_mean is not None
            else None
        ),
    }


def check_scoring_determinism(digest: dict) -> dict:
    """Re-score saved findings/contradictions twice; compare bytes."""
    scoring = yaml.safe_load(SCORING_PATH.read_text(encoding="utf-8"))
    inputs = digest.get("inputs", {})
    kwargs = {
        "domain_scan": inputs.get("domain_scan", True),
        "has_soc2": bool(inputs.get("documents")),
        "has_interview": bool(inputs.get("interviews")),
        "soc2_opinion": (digest.get("soc2_analysis") or {}).get(
            "opinion"
        ),
        "revenue_band": digest["target"]["revenue_band"],
    }
    runs = [
        json.dumps(
            score_digest(
                digest.get("findings", []),
                digest.get("contradictions", []),
                scoring,
                **kwargs,
            ),
            sort_keys=True,
        )
        for _ in range(2)
    ]
    return {
        "deterministic": runs[0] == runs[1],
        "scored_bytes": len(runs[0]),
    }


def score_run(run_dir: Path, expected: dict, profile_key: str) -> dict:
    """All harness metrics for one completed run directory."""
    digest = json.loads(
        (run_dir / "digest.json").read_text(encoding="utf-8")
    )
    trace = [
        json.loads(line)
        for line in (run_dir / "trace.jsonl")
        .read_text(encoding="utf-8")
        .splitlines()
        if line.strip()
    ]
    questions: dict[str, str] = {}
    claims_path = run_dir / "claims.json"
    if claims_path.exists():
        claims_data = json.loads(claims_path.read_text(encoding="utf-8"))
        questions = {
            claim["text"]: claim.get("context_question") or ""
            for claim in claims_data.get("claims", [])
        }
    findings = score_findings(
        digest.get("findings", []),
        expected.get("expected_findings", []),
        expected.get("must_not_find", []),
    )
    contradictions = match_contradictions(
        digest.get("contradictions", []),
        expected.get("expected_contradictions", []),
        questions,
    )
    complete = [e for e in trace if e["type"] == "narrative_complete"]
    run_end = next(e for e in trace if e["type"] == "run_end")
    usage = run_end.get("usage", {})
    determinism = check_scoring_determinism(digest)
    schema_errors = validate_digest(digest)
    return {
        "digest_id": digest["digest_id"],
        "schema_valid": schema_errors == [],
        "schema_errors": schema_errors,
        "findings": findings,
        "contradictions": contradictions,
        "narrative_valid": complete[0]["valid"] if complete else None,
        "narrative_attempts": (
            complete[0].get("attempts") if complete else None
        ),
        "profile": score_profile(
            digest.get("overall", {}), expected.get(profile_key, {})
        ),
        "score": digest.get("overall", {}).get("score"),
        "models": sorted(
            {
                provider.get("model")
                for provider in digest.get("mode", {}).get(
                    "providers", []
                )
                if provider.get("model")
            }
        ),
        "cost_usd": usage.get("estimated_cost_usd"),
        "deterministic_scoring": determinism["deterministic"],
    }


def _mean(values: list[float | None]) -> float | None:
    present = [v for v in values if v is not None]
    return sum(present) / len(present) if present else None


def _min(values: list[float | None]) -> float | None:
    present = [v for v in values if v is not None]
    return min(present) if present else None


def aggregate(scored: list[dict]) -> dict:
    """Mean/min per metric over successful runs, plus pass rates."""
    ok = [run for run in scored if run.get("status") == "ok"]
    recalls = [run["findings"]["recall"] for run in ok]
    precisions = [run["findings"]["precision"] for run in ok]
    contra_recalls = [
        run["contradictions"]["recall"]
        for run in ok
        if run["contradictions"]["total_expected"]
    ]
    accuracies = [
        run["contradictions"]["accuracy"]
        for run in ok
        if run["contradictions"]["accuracy"] is not None
    ]
    scores = [run["score"] for run in ok if run["score"] is not None]
    return {
        "runs": len(ok),
        "failed": len(scored) - len(ok),
        "finding_recall_mean": _mean(recalls),
        "finding_recall_min": _min(recalls),
        "finding_precision_mean": _mean(precisions),
        "finding_precision_min": _min(precisions),
        "contradiction_recall_mean": _mean(contra_recalls),
        "contradiction_recall_min": _min(contra_recalls),
        "verdict_accuracy_mean": _mean(accuracies),
        "verdict_accuracy_min": _min(accuracies),
        "schema_pass_rate": (
            sum(1 for run in ok if run["schema_valid"]) / len(ok)
            if ok
            else None
        ),
        "narrative_pass_rate": (
            sum(1 for run in ok if run["narrative_valid"]) / len(ok)
            if ok
            else None
        ),
        "rating_match_fraction": (
            sum(
                1
                for run in ok
                if run["profile"]["rating_match"]
            )
            / len(ok)
            if ok
            else None
        ),
        "profile_match_fraction": (
            sum(
                1
                for run in ok
                if run["profile"]["profile_match"]
            )
            / len(ok)
            if ok
            else None
        ),
        "score_mean": _mean(scores),
        "score_variance": (
            statistics.pvariance(scores) if len(scores) > 1 else 0.0
        ),
        "determinism_fraction": (
            sum(1 for run in ok if run["deterministic_scoring"])
            / len(ok)
            if ok
            else None
        ),
        "total_cost_usd": sum(
            run["cost_usd"] for run in ok if run["cost_usd"] is not None
        ),
    }


def _pct(value: float | None) -> str:
    return f"{value * 100:.1f}%" if value is not None else "n/a"


def _num(value: float | None, digits: int = 1) -> str:
    return f"{value:.{digits}f}" if value is not None else "n/a"


def render_markdown(
    results: dict, per_target: dict[str, dict]
) -> str:
    """README-ready results table."""
    lines = [
        f"# Eval results — {results['date']}",
        "",
        f"Models: {', '.join(results['models']) or 'n/a'} · "
        f"Runs: {results['total_runs']} "
        f"({', '.join(f'{name} x{plan['run_count']}' for name, plan in per_target.items())}) · "
        f"Total cost: ${results['total_cost_usd']:.4f}",
        "",
    ]
    for name, plan in per_target.items():
        lines.append(f"## {name} ({plan['label']})")
        lines.append("")
        lines.append(
            "| run | finding recall | precision | contra recall | "
            "verdict acc | schema | narrative (att) | rating | "
            "profile | score | cost | time |"
        )
        lines.append("| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |")
        for run in plan["runs"]:
            if run.get("status") != "ok":
                lines.append(
                    f"| `{run['digest_id']}` | FAILED: {run['error']} "
                    "| | | | | | | | | | |"
                )
                continue
            overall = run["profile"]
            lines.append(
                f"| `{run['digest_id']}` "
                f"| {_pct(run['findings']['recall'])} "
                f"| {_pct(run['findings']['precision'])} "
                f"| {_pct(run['contradictions']['recall'])} "
                f"| {_pct(run['contradictions']['accuracy'])} "
                f"| {'pass' if run['schema_valid'] else 'FAIL'} "
                f"| {'pass' if run['narrative_valid'] else 'FAIL'} "
                f"({run['narrative_attempts']}) "
                f"| {overall['rating_got']} "
                f"({'match' if overall['rating_match'] else 'want ' + str(overall['rating_want'])}) "
                f"| {'match' if overall['profile_match'] else 'DIFF'} "
                f"| {_num(run['score'])} "
                f"| ${_num(run['cost_usd'], 4)} "
                f"| {_num(run['wall_seconds'])}s |"
            )
        agg = plan["aggregate"]
        lines.append(
            f"| mean | {_pct(agg['finding_recall_mean'])} "
            f"| {_pct(agg['finding_precision_mean'])} "
            f"| {_pct(agg['contradiction_recall_mean'])} "
            f"| {_pct(agg['verdict_accuracy_mean'])} "
            f"| | | | | {_num(agg['score_mean'])} | | |"
        )
        lines.append(
            f"| min | {_pct(agg['finding_recall_min'])} "
            f"| {_pct(agg['finding_precision_min'])} "
            f"| {_pct(agg['contradiction_recall_min'])} "
            f"| {_pct(agg['verdict_accuracy_min'])} "
            f"| | | | | | | |"
        )
        lines.append("")
    total = results["aggregate"]
    lines.extend(
        [
            "## Aggregate",
            "",
            f"- schema pass rate: {_pct(total['schema_pass_rate'])}",
            f"- narrative pass rate: {_pct(total['narrative_pass_rate'])}",
            f"- rating match fraction: {_pct(total['rating_match_fraction'])}",
            f"- profile match fraction: {_pct(total['profile_match_fraction'])}",
            f"- scoring determinism: {_pct(total['determinism_fraction'])} byte-identical",
            f"- score variance: {_num(total['score_variance'], 2)}",
            "",
        ]
    )
    return "\n".join(lines)


def main(argv: list[str] | None = None, runner=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--yes",
        action="store_true",
        help="Confirm the estimated spend and run the harness.",
    )
    parser.add_argument("--brightwater-runs", type=int, default=3)
    parser.add_argument("--copperline-runs", type=int, default=2)
    args = parser.parse_args(argv)
    counts = {
        "brightwaterfleet.example": args.brightwater_runs,
        "copperline.example": args.copperline_runs,
    }

    estimate = estimate_cost(
        RUNS_DIR, args.brightwater_runs, args.copperline_runs
    )
    print(
        f"recent full runs: {estimate['full_runs_seen']} "
        f"(mean ${estimate['full_mean_usd']:.4f})"
        if estimate["full_mean_usd"] is not None
        else "recent full runs: none"
    )
    print(
        f"recent outside-in runs: {estimate['outside_in_runs_seen']} "
        f"(mean ${estimate['outside_in_mean_usd']:.4f})"
        if estimate["outside_in_mean_usd"] is not None
        else "recent outside-in runs: none"
    )
    if estimate["estimated_total_usd"] is not None:
        print(
            f"estimated cost for {args.brightwater_runs}x Brightwater + "
            f"{args.copperline_runs}x Copperline: "
            f"${estimate['estimated_total_usd']:.4f}"
        )
    else:
        print("estimated cost: unknown (no recent runs of each type)")
    if not args.yes:
        print("Re-run with --yes to start the eval runs.")
        return 2

    if runner is None:
        from pe_risk_key.agent import run_digest as runner

    os.environ["DEMO_MODE"] = "1"
    started = datetime.now(timezone.utc)
    per_target: dict[str, dict] = {}
    for target in TARGETS:
        name = target["name"]
        expected = yaml.safe_load(
            (
                ROOT / "fixtures" / "expected" / f"{name}.yaml"
            ).read_text(encoding="utf-8")
        )
        kwargs = _target_args(name)
        if target["soc2"] is not None:
            kwargs["soc2_path"] = str(ROOT / target["soc2"])
            kwargs["as_of"] = expected.get("digest_date", "2026-10-30")
        if target["interview"] is not None:
            kwargs["interview_path"] = str(ROOT / target["interview"])
            kwargs["speaker_names"] = list(SPEAKER_NAMES)
            kwargs["target_speakers"] = list(TARGET_SPEAKERS)
        runs: list[dict] = []
        for index in range(counts[name]):
            print(f"\n=== {name} run {index + 1}/{counts[name]} ===")
            begun = time.monotonic()
            try:
                result = runner(**kwargs)
                wall = time.monotonic() - begun
                run_dir = Path(result["trace_path"]).parent
                scored = score_run(
                    run_dir, expected, target["profile_key"]
                )
                scored["status"] = "ok"
                scored["wall_seconds"] = wall
                print(
                    f"done {scored['digest_id']}: "
                    f"recall={_pct(scored['findings']['recall'])} "
                    f"rating={scored['profile']['rating_got']} "
                    f"cost=${(scored['cost_usd'] or 0):.4f} "
                    f"{wall:.1f}s"
                )
            except Exception as exc:  # noqa: BLE001 - record and continue
                wall = time.monotonic() - begun
                scored = {
                    "status": "failed",
                    "digest_id": "-",
                    "error": f"{type(exc).__name__}: {exc}",
                    "wall_seconds": wall,
                }
                print(f"FAILED after {wall:.1f}s: {exc}")
            runs.append(scored)
        per_target[name] = {
            "run_count": counts[name],
            "label": (
                "outside-in + SOC 2 + interview"
                if target["soc2"]
                else "outside-in only"
            ),
            "runs": runs,
            "aggregate": aggregate(runs),
        }
    # Flatten runs for the overall aggregate (keyed lists would collide).
    all_runs = [
        run for plan in per_target.values() for run in plan["runs"]
    ]
    results = {
        "date": started.strftime("%Y-%m-%d"),
        "started_at": started.isoformat(),
        "models": sorted(
            {
                model
                for run in all_runs
                if run.get("status") == "ok"
                for model in run.get("models", [])
            }
        ),
        "total_runs": len(all_runs),
        "targets": {
            name: {
                "runs": plan["runs"],
                "aggregate": plan["aggregate"],
            }
            for name, plan in per_target.items()
        },
        "aggregate": aggregate(all_runs),
        "total_cost_usd": sum(
            run["cost_usd"]
            for run in all_runs
            if run.get("status") == "ok"
            and run.get("cost_usd") is not None
        ),
    }
    stamp = started.strftime("%Y%m%dT%H%M%SZ")
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    (RESULTS_DIR / f"{stamp}.json").write_text(
        json.dumps(results, indent=2), encoding="utf-8"
    )
    markdown = render_markdown(results, per_target)
    (RESULTS_DIR / f"{stamp}.md").write_text(markdown, encoding="utf-8")
    (RESULTS_DIR.parent / "LATEST.md").write_text(markdown, encoding="utf-8")
    print(f"\nwrote eval/results/{stamp}.json + .md (copied to eval/LATEST.md)")
    print(f"total cost: ${results['total_cost_usd']:.4f}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
