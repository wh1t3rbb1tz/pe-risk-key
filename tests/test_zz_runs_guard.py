# SPDX-License-Identifier: AGPL-3.0-or-later
"""Guard: the suite must never write under the real eval/runs/.

This file sorts last so it runs after every other test; it compares
the live tree against the session-start snapshot from conftest.py.
"""

from pathlib import Path


def test_suite_created_nothing_under_real_runs_dir(runs_snapshot):
    real_runs = Path(__file__).resolve().parents[1] / "eval" / "runs"
    current: dict[str, tuple[int, int]] = {}
    if real_runs.is_dir():
        for path in sorted(real_runs.rglob("*")):
            if path.is_file():
                stat = path.stat()
                current[str(path.relative_to(real_runs))] = (
                    stat.st_size,
                    stat.st_mtime_ns,
                )
    added = sorted(p for p in current if p not in runs_snapshot)
    modified = sorted(
        p
        for p in current
        if p in runs_snapshot and current[p] != runs_snapshot[p]
    )
    assert not added, f"suite created under eval/runs/: {added}"
    assert not modified, f"suite modified under eval/runs/: {modified}"
