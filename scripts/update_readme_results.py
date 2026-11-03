# SPDX-License-Identifier: AGPL-3.0-or-later
"""Refresh the README's Results and Cost sections from the eval harness.

Replaces the content between <!-- EVAL:START --> and <!-- EVAL:END -->
with eval/LATEST.md minus its H1, and the line between
<!-- COST:START --> and <!-- COST:END --> with the mean per-run cost
and wall time from the newest eval/results/*.json.

Usage: make readme  (or: .venv/bin/python scripts/update_readme_results.py)
"""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
README = ROOT / "README.md"
LATEST = ROOT / "eval" / "LATEST.md"
RESULTS_DIR = ROOT / "eval" / "results"


def latest_results_path(results_dir: Path = RESULTS_DIR) -> Path:
    """Return the newest eval/results/*.json, which pairs with LATEST.md."""
    candidates = sorted(results_dir.glob("*.json"))
    if not candidates:
        raise SystemExit(
            "No eval results found. Run the harness first "
            "(`make eval ARGS=--yes`)."
        )
    return candidates[-1]


def cost_line(results_path: Path) -> str:
    """Mean per-run cost and wall time across successful runs."""
    results = json.loads(results_path.read_text(encoding="utf-8"))
    runs = [
        run
        for target in results["targets"].values()
        for run in target["runs"]
        if run.get("status") == "ok"
        and run.get("cost_usd") is not None
        and run.get("wall_seconds") is not None
    ]
    if not runs:
        raise SystemExit(f"No successful runs in {results_path.name}.")
    mean_cost = sum(run["cost_usd"] for run in runs) / len(runs)
    mean_wall = sum(run["wall_seconds"] for run in runs) / len(runs)
    return (
        f"Mean ${mean_cost:.2f} per run and {mean_wall:.0f}s wall time "
        f"across {len(runs)} runs ({results['date']} eval)."
    )


def strip_h1(markdown: str) -> str:
    """Drop a leading H1 line; the README provides its own heading."""
    lines = markdown.splitlines()
    if lines and lines[0].startswith("# "):
        lines = lines[1:]
    return "\n".join(lines).strip("\n")


def replace_block(text: str, name: str, body: str) -> str:
    """Replace the content between <!-- NAME:START --> and <!-- NAME:END -->."""
    start = f"<!-- {name}:START -->"
    end = f"<!-- {name}:END -->"
    before, sep, rest = text.partition(start)
    if not sep:
        raise ValueError(f"README is missing the {start} marker.")
    _, sep2, after = rest.partition(end)
    if not sep2:
        raise ValueError(f"README is missing the {end} marker.")
    preserved = after if after.startswith("\n") else "\n" + after
    return before + start + "\n" + body.strip("\n") + "\n" + end + preserved


def update_readme(
    readme_path: Path = README,
    latest_path: Path = LATEST,
    results_path: Path | None = None,
) -> None:
    """Rewrite the README's EVAL and COST blocks in place (idempotent)."""
    results_file = results_path or latest_results_path()
    eval_body = strip_h1(latest_path.read_text(encoding="utf-8"))
    cost_body = cost_line(results_file)
    text = readme_path.read_text(encoding="utf-8")
    text = replace_block(text, "EVAL", eval_body)
    text = replace_block(text, "COST", cost_body)
    readme_path.write_text(text, encoding="utf-8")


def main() -> None:
    update_readme()
    print(f"README results refreshed from {LATEST.name}.")


if __name__ == "__main__":
    main()
