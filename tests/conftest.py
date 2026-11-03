# SPDX-License-Identifier: AGPL-3.0-or-later
"""Session snapshot of the real eval/runs/ for the write guard."""

from __future__ import annotations

from pathlib import Path

import pytest

REAL_RUNS = Path(__file__).resolve().parents[1] / "eval" / "runs"

_SNAPSHOT: dict[str, tuple[int, int]] | None = None


def _snapshot_runs() -> dict[str, tuple[int, int]]:
    snap: dict[str, tuple[int, int]] = {}
    if REAL_RUNS.is_dir():
        for path in sorted(REAL_RUNS.rglob("*")):
            if path.is_file():
                stat = path.stat()
                snap[str(path.relative_to(REAL_RUNS))] = (
                    stat.st_size,
                    stat.st_mtime_ns,
                )
    return snap


@pytest.fixture(scope="session", autouse=True)
def _snapshot_runs_dir():
    global _SNAPSHOT
    _SNAPSHOT = _snapshot_runs()
    yield


@pytest.fixture(scope="session")
def runs_snapshot(_snapshot_runs_dir):
    assert _SNAPSHOT is not None
    return _SNAPSHOT
