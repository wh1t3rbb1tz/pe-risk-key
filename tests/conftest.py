# SPDX-License-Identifier: AGPL-3.0-or-later
"""Session snapshot of the real eval/runs/ for the write guard.

Network access is blocked suite-wide (autouse fixture): tests must mock
sockets instead. Run green with no .env and no network.
"""

from __future__ import annotations

import socket
from pathlib import Path

import pytest

REAL_RUNS = Path(__file__).resolve().parents[1] / "eval" / "runs"


class NetworkBlockedError(RuntimeError):
    """A test attempted real network I/O; mock sockets instead."""


def _blocked(*args, **kwargs):
    raise NetworkBlockedError(
        "Network access is disabled in the test suite."
    )


class _BlockedSocket(socket.socket):
    """INET sockets raise on use; AF_UNIX stays open for asyncio."""

    def _guard(self):
        if self.family != socket.AF_UNIX:
            _blocked()

    def connect(self, *args, **kwargs):
        self._guard()
        return super().connect(*args, **kwargs)

    def send(self, *args, **kwargs):
        self._guard()
        return super().send(*args, **kwargs)

    def sendto(self, *args, **kwargs):
        self._guard()
        return super().sendto(*args, **kwargs)

    def sendall(self, *args, **kwargs):
        self._guard()
        return super().sendall(*args, **kwargs)


_REAL_SOCKETPAIR = socket.socketpair


def _guarded_socketpair(*args, **kwargs):
    left, right = _REAL_SOCKETPAIR(*args, **kwargs)
    return (
        _BlockedSocket(fileno=left.detach()),
        _BlockedSocket(fileno=right.detach()),
    )


@pytest.fixture(autouse=True)
def _block_network(monkeypatch):
    monkeypatch.setattr(socket, "socket", _BlockedSocket)
    monkeypatch.setattr(socket, "socketpair", _guarded_socketpair)
    monkeypatch.setattr(socket, "create_connection", _blocked)
    monkeypatch.setattr(socket, "getaddrinfo", _blocked)

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
