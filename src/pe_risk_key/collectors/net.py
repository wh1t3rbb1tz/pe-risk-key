"""Network boundary (SPEC §2). The ONLY module allowed HTTP requests.

Every HTTP call in the collectors package goes through :func:`safe_get`,
which enforces the passive-collection boundary: GET only, HTTPS only,
hosts limited to the target apex, ``www.`` + apex, and ``crt.sh``, one
request per host per run. TLS inspection goes through :func:`tls_info`
(one handshake, no HTTP) and :func:`tls_accepts` (at most two legacy
handshake probes per host per run, apex/www only). Anything else raises
:class:`SafetyBoundaryError`.
"""

from __future__ import annotations

import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urlparse

import httpx

CRT_SH = "crt.sh"
TIMEOUT_SECONDS = 10.0
TLS_PORT = 443
MAX_TLS_PROBES_PER_HOST = 2

# Pinned at import so short_reason keeps working when tests swap net.httpx.
_TIMEOUT_EXC = httpx.TimeoutException
_CONNECT_EXC = httpx.ConnectError
_HTTP_STATUS_EXC = httpx.HTTPStatusError


class SafetyBoundaryError(Exception):
    """A collection attempt stepped outside the SPEC §2 safety boundary."""


_run_domain: str | None = None
_run_hosts: set[str] = set()
_run_tls_probes: dict[str, int] = {}


def begin_run(domain: str) -> None:
    """Start a collector run: set the target and reset the per-host logs."""
    global _run_domain, _run_hosts, _run_tls_probes
    _run_domain = domain.lower()
    _run_hosts = set()
    _run_tls_probes = {}


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
    return httpx.get(url, timeout=TIMEOUT_SECONDS, follow_redirects=False)


def short_reason(exc: BaseException) -> str:
    """Map a transport failure to a short human-readable reason."""
    if isinstance(exc, _TIMEOUT_EXC):
        return "timeout"
    if isinstance(exc, TimeoutError):
        return "timeout"
    if isinstance(exc, socket.gaierror):
        return "DNS failure"
    if isinstance(exc, ConnectionRefusedError):
        return "connection refused"
    if isinstance(exc, ssl.SSLError):
        return "TLS error"
    if isinstance(exc, _CONNECT_EXC):
        return "connection failed"
    if isinstance(exc, _HTTP_STATUS_EXC):
        return f"HTTP {exc.response.status_code}"
    if isinstance(exc, OSError):
        return "connection failed"
    return type(exc).__name__


def _check_tls_host(host: str) -> str:
    """Run context + apex/www allowlist for TLS functions. Returns host."""
    if _run_domain is None:
        raise SafetyBoundaryError(
            "No run context; registry.run() must begin a run first."
        )
    lowered = host.lower()
    if lowered not in {_run_domain, f"www.{_run_domain}"}:
        raise SafetyBoundaryError(
            f"Host {host!r} is outside the TLS boundary for {_run_domain} "
            "(apex or www only)."
        )
    return host


def _normalize_tls_version(version: str) -> str:
    return {"TLSv1": "TLSv1.0"}.get(version, version)


def _cert_issuer(cert: dict) -> str:
    for rdn in cert.get("issuer", ()):
        for key, value in rdn:
            if key == "organizationName":
                return value
    for rdn in cert.get("issuer", ()):
        for key, value in rdn:
            if key == "commonName":
                return value
    return ""


def tls_info(host: str) -> dict:
    """One TLS handshake to port 443; no HTTP is sent.

    Returns ``{"version", "issuer", "not_after", "days_remaining"}`` with
    the negotiated (normalized) version, the issuing org name, the cert
    expiry as an ISO timestamp, and whole days until expiry.
    """
    _check_tls_host(host)
    context = ssl.create_default_context()
    with socket.create_connection(
        (host, TLS_PORT), timeout=TIMEOUT_SECONDS
    ) as sock:
        with context.wrap_socket(sock, server_hostname=host) as tls_sock:
            version = _normalize_tls_version(tls_sock.version())
            cert = tls_sock.getpeercert()
    expires = datetime.strptime(
        cert["notAfter"], "%b %d %H:%M:%S %Y %Z"
    ).replace(tzinfo=timezone.utc)
    now = datetime.now(timezone.utc)
    return {
        "version": version,
        "issuer": _cert_issuer(cert),
        "not_after": expires.isoformat(),
        "days_remaining": (expires - now).days,
    }


_TLS_PROBE_VERSIONS = {"TLSv1.0": "TLSv1", "TLSv1.1": "TLSv1_1"}


def tls_accepts(host: str, version: str) -> bool | str:
    """Handshake-only probe forcing a legacy TLS version.

    Returns True if the handshake succeeds, False if the server refuses,
    or "unknown" if the attempt itself cannot run (local OpenSSL cannot
    configure that version, or the host is unreachable). At most two
    probes per host per run; no application data is ever sent.
    """
    _check_tls_host(host)
    if version not in _TLS_PROBE_VERSIONS:
        raise ValueError(
            f"Probe version must be one of {sorted(_TLS_PROBE_VERSIONS)}."
        )
    lowered = host.lower()
    if _run_tls_probes.get(lowered, 0) >= MAX_TLS_PROBES_PER_HOST:
        raise SafetyBoundaryError(
            f"More than {MAX_TLS_PROBES_PER_HOST} TLS probes to {host} in one run."
        )
    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        forced = getattr(ssl.TLSVersion, _TLS_PROBE_VERSIONS[version])
        context.minimum_version = forced
        context.maximum_version = forced
        try:
            context.set_ciphers("DEFAULT@SECLEVEL=0")
        except ssl.SSLError:
            pass  # engine without @SECLEVEL syntax; attempt anyway
    except (AttributeError, ValueError):
        return "unknown"
    _run_tls_probes[lowered] = _run_tls_probes.get(lowered, 0) + 1
    try:
        with socket.create_connection(
            (host, TLS_PORT), timeout=TIMEOUT_SECONDS
        ) as sock:
            with context.wrap_socket(sock, server_hostname=host):
                return True
    except ssl.SSLError:
        return False
    except OSError:
        return "unknown"
