"""check_dnssec collector: DS record presence via DNS."""

from __future__ import annotations

import dns.resolver

from pe_risk_key.collectors.registry import register

COLLECTION_METHOD = "dns_query"


@register(
    tool_name="check_dnssec",
    description=(
        "Check whether DNSSEC is enabled by querying the DS record. "
        "Passive DNS query only."
    ),
    collection_method=COLLECTION_METHOD,
)
def collect(domain: str) -> dict:
    """Collect the DNSSEC enabled signal for a domain."""
    try:
        answers = dns.resolver.resolve(domain, "DS")
        enabled = any(True for _ in answers)
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        enabled = False
    return {
        "collection_method": COLLECTION_METHOD,
        "queried_name": domain,
        "record_type": "DS",
        "enabled": enabled,
    }
