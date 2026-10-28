"""Network boundary (SPEC §2). The ONLY module allowed HTTP requests.

Every HTTP call in the collectors package goes through :func:`safe_get`,
which enforces the passive-collection boundary: GET only, HTTPS only,
hosts limited to the target apex, ``www.`` + apex, and ``crt.sh``, one
request per host per run. Anything else raises :class:`SafetyBoundaryError`.
"""

from __future__ import annotations

from urllib.parse import urlparse

import httpx

CRT_SH = "crt.sh"
TIMEOUT_SECONDS = 10.0


class SafetyBoundaryError(Exception):
    """A collection attempt stepped outside the SPEC §2 safety boundary."""


_run_domain: str | None = None
_run_hosts: set[str] = set()


def begin_run(domain: str) -> None:
    """Start a collector run: set the target and reset the per-host log."""
    global _run_domain, _run_hosts
    _run_domain = domain.lower()
    _run_hosts = set()


def safe_get(url: str, *, method: str = "GET") -> httpx.Response:
    """GET a URL inside the safety boundary (SPEC §2).

    Args:
        url: Target URL (must be HTTPS on an allowed host).
        method: Must be ``"GET"``; any other method is rejected.

    Raises:
        SafetyBoundaryError: On a non-GET method, missing run context,
            a non-HTTPS URL, a disallowed host, or a second request to
            the same host within one run.
    """
    if method != "GET":
        raise SafetyBoundaryError(f"Only GET is allowed, got {method!r}.")
    if _run_domain is None:
        raise SafetyBoundaryError(
            "No run context; registry.run() must begin a run first."
        )
    parts = urlparse(url)
    if parts.scheme != "https":
        raise SafetyBoundaryError(f"Only HTTPS is allowed, got {url!r}.")
    host = (parts.hostname or "").lower()
    allowed = {_run_domain, f"www.{_run_domain}", CRT_SH}
    if host not in allowed:
        raise SafetyBoundaryError(
            f"Host {host!r} is outside the boundary for target {_run_domain}."
        )
    if host in _run_hosts:
        raise SafetyBoundaryError(
            f"Second request to {host} in one run (at most one per host)."
        )
    _run_hosts.add(host)
    return httpx.get(url, timeout=TIMEOUT_SECONDS)
