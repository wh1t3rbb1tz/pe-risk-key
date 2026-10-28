"""Passive collectors (SPEC §2, §4.1)."""

from pe_risk_key.collectors import (  # noqa: F401
    ct,
    dnssec,
    email_auth,
    web_posture,
    kev,
    incidents,
)
from pe_risk_key.collectors.net import SafetyBoundaryError
from pe_risk_key.collectors.registry import (
    ALLOWED_METHODS,
    run,
    tool_definitions,
)

__all__ = [
    "ALLOWED_METHODS",
    "SafetyBoundaryError",
    "run",
    "tool_definitions",
]
