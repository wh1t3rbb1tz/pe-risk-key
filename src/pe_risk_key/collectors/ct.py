"""enumerate_ct_subdomains collector: hostnames from CT logs."""

from __future__ import annotations

from pe_risk_key.collectors.net import (
    SafetyBoundaryError,
    safe_get,
    short_reason,
)
from pe_risk_key.collectors.registry import register

COLLECTION_METHOD = "ct_log_query"

RISKY_PATTERNS = ["vpn", "jenkins", "staging", "dev", "admin", "legacy", "old"]


@register(
    tool_name="enumerate_ct_subdomains",
    description=(
        "List unique hostnames for the domain from Certificate Transparency "
        "logs (one crt.sh query) and flag risky name patterns. Read-only "
        "public log query."
    ),
    collection_method=COLLECTION_METHOD,
)
def collect(domain: str) -> dict:
    """Collect CT-log hostnames for a domain (one crt.sh request)."""
    query_url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        response = safe_get(query_url)
        response.raise_for_status()
        entries = response.json()
    except SafetyBoundaryError:
        raise
    except Exception as exc:
        return {
            "collection_method": COLLECTION_METHOD,
            "status": "error",
            "error": short_reason(exc),
            "query_url": query_url,
        }
    hostnames: dict[str, dict[str, str]] = {}
    apex = domain.lower()
    suffix = f".{apex}"
    for entry in entries if isinstance(entries, list) else []:
        if not isinstance(entry, dict):
            continue
        # crt.sh packs all names on a cert into one whitespace-separated blob;
        # first/last seen are the validity window aggregated per hostname,
        # the closest this feed offers to observation dates.
        for name in (entry.get("name_value") or "").split():
            name = name.strip().lower().removeprefix("*.")
            if not name or (name != apex and not name.endswith(suffix)):
                continue
            first = (entry.get("not_before") or "")[:10]
            last = (entry.get("not_after") or "")[:10]
            seen = hostnames.setdefault(
                name, {"first_seen": first, "last_seen": last}
            )
            if first and (not seen["first_seen"] or first < seen["first_seen"]):
                seen["first_seen"] = first
            if last and (not seen["last_seen"] or last > seen["last_seen"]):
                seen["last_seen"] = last
    risky = []
    for hostname, seen in hostnames.items():
        matched = [p for p in RISKY_PATTERNS if p in hostname]
        if matched:
            risky.append(
                {
                    "hostname": hostname,
                    "pattern": "|".join(matched),
                    **seen,
                }
            )
    return {
        "collection_method": COLLECTION_METHOD,
        "status": "ok",
        "query_url": query_url,
        "unique_hostnames": len(hostnames),
        "risky_hostnames": risky,
        "risky_hostnames_count": len(risky),
    }
