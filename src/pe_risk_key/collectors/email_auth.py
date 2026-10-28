"""check_email_auth collector: SPF, DMARC, DKIM via DNS."""

from __future__ import annotations

import re

import dns.resolver

from pe_risk_key.collectors.registry import register

COLLECTION_METHOD = "dns_query"

DKIM_SELECTORS = ["default", "selector1", "selector2", "google", "k1", "s1"]


def _txt_records(name: str) -> list[str]:
    try:
        answers = dns.resolver.resolve(name, "TXT")
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return []
    records = []
    for rdata in answers:
        text = rdata.to_text()
        parts = re.findall(r'"([^"]*)"', text)
        records.append("".join(parts) if parts else text)
    return records


def _parse_spf(records: list[str]) -> dict:
    for record in records:
        if record.startswith("v=spf1"):
            match = re.search(r"([+\-~?])all(?:\s|$)", record)
            lookups = len(re.findall(r"\binclude:", record))
            if re.search(r"\bredirect=", record):
                lookups += 1
            return {
                "record": record,
                "qualifier": f"{match.group(1)}all" if match else None,
                "lookup_count": lookups,
            }
    return {"record": None, "qualifier": None, "lookup_count": 0}


def _parse_dmarc(records: list[str]) -> dict:
    for record in records:
        if record.startswith("v=DMARC1"):
            tags: dict[str, str] = {}
            for part in record.split(";"):
                if "=" in part:
                    key, value = part.split("=", 1)
                    tags[key.strip()] = value.strip()
            try:
                pct = int(tags.get("pct", "100"))
            except ValueError:
                pct = 100
            return {
                "record": record,
                "policy": tags.get("p"),
                "pct": pct,
                "rua": "rua=" in record,
            }
    return {"record": None, "policy": None, "pct": None, "rua": False}


def _check_dkim(domain: str) -> dict:
    found = []
    for selector in DKIM_SELECTORS:
        for record in _txt_records(f"{selector}._domainkey.{domain}"):
            if "v=DKIM1" in record:
                found.append(selector)
                break
    return {
        "selectors_checked": list(DKIM_SELECTORS),
        "selectors_found": found,
        "queried_names": {
            selector: f"{selector}._domainkey.{domain}"
            for selector in DKIM_SELECTORS
        },
    }


@register(
    tool_name="check_email_auth",
    description=(
        "Check email authentication: SPF record and all-qualifier from the "
        "apex TXT, DMARC policy from the _dmarc TXT, and DKIM by probing "
        "common selectors. Passive DNS queries only."
    ),
    collection_method=COLLECTION_METHOD,
)
def collect(domain: str) -> dict:
    """Collect SPF, DMARC, and DKIM signals for a domain."""
    spf = {
        "queried_name": domain,
        "record_type": "TXT",
        **_parse_spf(_txt_records(domain)),
    }
    dmarc_name = f"_dmarc.{domain}"
    dmarc = {
        "queried_name": dmarc_name,
        "record_type": "TXT",
        **_parse_dmarc(_txt_records(dmarc_name)),
    }
    return {
        "collection_method": COLLECTION_METHOD,
        "status": "ok",
        "spf": spf,
        "dmarc": dmarc,
        "dkim": _check_dkim(domain),
    }
