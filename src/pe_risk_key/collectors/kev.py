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

# Explicit (kind, normalized product) -> (vendorProject, product) mapping.
# No substring matching: anything outside this table must equal a catalog
# vendor+product pair exactly (normalized) to match.
KEV_ALIASES = {
    ("cms", "wordpress"): ("WordPress", "Core"),
    ("plugin", "wp-file-manager"): ("WordPress", "File Manager Plugin"),
    ("plugin", "duplicator"): ("WordPress", "Snap Creek Duplicator Plugin"),
    ("plugin", "social-warfare"): ("WordPress", "Social Warfare Plugin"),
    ("appliance", "examplegate ssl-vpn"): ("ExampleGate", "ExampleGate SSL-VPN"),
}


def _load_snapshot() -> dict:
    try:
        return json.loads(KEV_SNAPSHOT_PATH.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise FileNotFoundError(
            f"KEV snapshot not found at {KEV_SNAPSHOT_PATH}; run "
            "scripts/update_kev.py to download it."
        ) from None


def _normalize(text: Any) -> str:
    return " ".join(str(text or "").split()).lower()


def _catalog_index(vulnerabilities: list) -> tuple[dict, dict]:
    by_pair: dict[tuple[str, str], list] = {}
    by_combined: dict[str, list] = {}
    for vuln in vulnerabilities:
        if not isinstance(vuln, dict):
            continue
        vendor = _normalize(vuln.get("vendorProject"))
        product = _normalize(vuln.get("product"))
        by_pair.setdefault((vendor, product), []).append(vuln)
        by_combined.setdefault(f"{vendor} {product}".strip(), []).append(vuln)
    return by_pair, by_combined


def _match_fingerprints(
    fingerprints: list[dict], vulnerabilities: list[dict], snapshot_date: Any
) -> list[dict]:
    by_pair, by_combined = _catalog_index(vulnerabilities)
    matches = []
    seen = set()
    for fingerprint in fingerprints:
        if not isinstance(fingerprint, dict):
            continue
        if fingerprint.get("kind") == "cdn_or_proxy":
            continue
        name = _normalize(fingerprint.get("product"))
        if not name:
            continue
        alias = KEV_ALIASES.get((fingerprint.get("kind"), name))
        if alias is not None:
            candidates = by_pair.get(
                (_normalize(alias[0]), _normalize(alias[1])), []
            )
        else:
            candidates = by_combined.get(name, [])
        for vuln in candidates:
            key = (vuln.get("cveID"), fingerprint.get("host"))
            if key in seen:
                continue
            seen.add(key)
            tier = (
                "appliance_exposed"
                if fingerprint.get("kind") == "appliance"
                else "product_listed"
            )
            matches.append(
                {
                    "cve_id": vuln.get("cveID"),
                    "vendor": vuln.get("vendorProject"),
                    "product": vuln.get("product"),
                    "matched_fingerprint": fingerprint,
                    "kev_snapshot_date": snapshot_date,
                    "match_level": "product",
                    "match_tier": tier,
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
        "status": "ok",
        "snapshot_source": snapshot.get("snapshot_source"),
        "kev_snapshot_date": snapshot.get("snapshot_date"),
        "matches": matches,
        "matches_count": len(matches),
    }
