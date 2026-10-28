"""match_known_exploited collector: fingerprints vs the CISA KEV catalog.

Offline matching is product-level only: KEV lists products, not affected
versions, so a match is always phrased as potential exposure and the
fingerprinted version is never claimed as verified.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from pe_risk_key.collectors import web_posture
from pe_risk_key.collectors.registry import register

COLLECTION_METHOD = "offline_lookup"

ROOT = Path(__file__).resolve().parents[3]
KEV_SNAPSHOT_PATH = ROOT / "data" / "kev_snapshot.json"

VERSION_NOTE = "KEV lists products, not affected versions; version not verified."


def _load_snapshot() -> dict:
    try:
        return json.loads(KEV_SNAPSHOT_PATH.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise FileNotFoundError(
            f"KEV snapshot not found at {KEV_SNAPSHOT_PATH}; run "
            "scripts/update_kev.py to download it."
        ) from None


def _matches(product: str, vendor: str, catalog_product: str) -> bool:
    candidate = product.strip().lower()
    combined = f"{vendor} {catalog_product}".strip().lower()
    return bool(candidate) and (candidate in combined or combined in candidate)


def _match_fingerprints(
    fingerprints: list[dict], vulnerabilities: list[dict], snapshot_date: Any
) -> list[dict]:
    matches = []
    for fingerprint in fingerprints:
        if not isinstance(fingerprint, dict):
            continue
        product = fingerprint.get("product") or ""
        for vuln in vulnerabilities:
            if not isinstance(vuln, dict):
                continue
            vendor = vuln.get("vendorProject") or ""
            catalog_product = vuln.get("product") or ""
            if _matches(product, vendor, catalog_product):
                matches.append(
                    {
                        "cve_id": vuln.get("cveID"),
                        "vendor": vendor,
                        "product": catalog_product,
                        "matched_fingerprint": fingerprint,
                        "kev_snapshot_date": snapshot_date,
                        "match_level": "product",
                        "note": VERSION_NOTE,
                    }
                )
    return matches


@register(
    tool_name="match_known_exploited",
    description=(
        "Match web fingerprints against the local CISA KEV snapshot "
        "(product-level only; versions are never verified). Fully offline."
    ),
    collection_method=COLLECTION_METHOD,
)
def collect(domain: str, fingerprints: list[dict] | None = None) -> dict:
    """Match fingerprints against the KEV snapshot.

    Args:
        domain: Target apex domain.
        fingerprints: Fingerprint dicts (with locators) as produced by
            ``check_web_posture``; the orchestrator chains them in. When
            omitted, web posture is collected first.
    """
    if fingerprints is None:
        posture = web_posture.collect(domain)
        fingerprints = [
            {**fp, "host": host["host"]}
            for host in posture.get("hosts", [])
            if isinstance(host, dict)
            for fp in host.get("fingerprints", [])
        ]
    snapshot = _load_snapshot()
    matches = _match_fingerprints(
        fingerprints,
        snapshot.get("vulnerabilities", []),
        snapshot.get("snapshot_date"),
    )
    return {
        "collection_method": COLLECTION_METHOD,
        "snapshot_source": snapshot.get("snapshot_source"),
        "kev_snapshot_date": snapshot.get("snapshot_date"),
        "matches": matches,
        "matches_count": len(matches),
    }
