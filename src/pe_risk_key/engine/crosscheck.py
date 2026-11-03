"""Cross-check engine (SPEC §4.4): verdicts for interview claims.

One Muse Wonder call judges each claim against a compact evidence
catalog (every finding plus every evidence-pool item); code then drops
refs that exist nowhere in the run, downgrades ref-less verdicts to
unsupported, and derives severity deterministically.
"""

from __future__ import annotations

from typing import Any

from pe_risk_key.engine.scoring import SEVERITY_RANK
from pe_risk_key.providers import (
    WONDER_USD_PER_MTOK,
    Mode,
    ModelClient,
    estimate_token_cost_usd,
)

SYSTEM_PROMPT = """You cross-check interview claims against assessment evidence. Rules:
1. Return exactly one verdict per claim: contradicted (evidence conflicts with the claim), unsupported (no evidence either way), supported (evidence corroborates the claim).
2. supported requires positive evidence that corroborates the claim, not just the absence of contradiction.
3. CT log presence alone doesn't prove a host is live. However, certificates issued within the last 12 months (last_seen) for a hostname show the system is still actively maintained. That contradicts a claim it was decommissioned in the past; cite it and state the caveat in the explanation.
4. A SOC 2 control tested with no exceptions is positive evidence that supports a claim about that control.
5. Cite evidence_refs using only finding (F-) and evidence (E-) ids from the catalog below.
6. Keep each explanation under 500 characters."""

MAX_EXPLANATION_CHARS = 500
MAX_CLAIM_CHARS = 500

_MEDIUM_UNSUPPORTED_TYPES = ("incident_history", "control_coverage")
_VERDICT_PRECEDENCE = {"supported": 0, "unsupported": 1, "contradicted": 2}


def crosscheck_schema() -> dict[str, Any]:
    """Strict-ready schema for one verdict per claim."""
    return {
        "type": "object",
        "additionalProperties": False,
        "required": ["verdicts"],
        "properties": {
            "verdicts": {
                "type": "array",
                "items": {
                    "type": "object",
                    "additionalProperties": False,
                    "required": [
                        "claim_index",
                        "verdict",
                        "evidence_refs",
                        "explanation",
                    ],
                    "properties": {
                        "claim_index": {
                            "type": "integer",
                            "minimum": 0,
                        },
                        "verdict": {
                            "type": "string",
                            "enum": [
                                "contradicted",
                                "unsupported",
                                "supported",
                            ],
                        },
                        "evidence_refs": {
                            "type": "array",
                            "items": {"type": "string"},
                        },
                        "explanation": {
                            "type": "string",
                            "description": "Max 500 chars.",
                        },
                    },
                },
            },
        },
    }


def _catalog(findings: list[dict], evidence_pool: list[dict]) -> str:
    """Compact catalog: one line per finding and per pool item."""
    lines = ["Findings:"]
    for finding in findings:
        excerpts = " / ".join(
            item.get("excerpt", "") for item in finding.get("evidence", [])
        )
        lines.append(
            f"{finding.get('finding_id')} | {finding.get('severity')} | "
            f"{finding.get('title')} | {excerpts}"
        )
    lines.append("Evidence:")
    for item in evidence_pool:
        excerpt = item.get("excerpt", "")
        if item.get("evidence_kind") == "no_exception":
            excerpt = f"control tested, no exceptions: {excerpt}"
        lines.append(
            f"{item.get('evidence_id')} | {item.get('source_type')} | "
            f"{item.get('locator')} | {excerpt}"
        )
    return "\n".join(lines)


def _catalog_counts(
    findings: list[dict], evidence_pool: list[dict]
) -> dict[str, int]:
    """Catalog size by category for run reporting."""
    return {
        "findings": len(findings),
        "outside_in_evidence": sum(
            1 for item in evidence_pool if item.get("collector") != "soc2_analyzer"
        ),
        "soc2_exceptions": sum(
            1
            for item in evidence_pool
            if item.get("evidence_kind") == "exception"
        ),
        "soc2_no_exception": sum(
            1
            for item in evidence_pool
            if item.get("evidence_kind") == "no_exception"
        ),
        "soc2_notables": sum(
            1
            for item in evidence_pool
            if item.get("evidence_kind") == "notable"
        ),
    }


def _evidence_to_findings(
    findings: list[dict],
) -> dict[str, list[str]]:
    """Map each attached evidence id to its finding ids."""
    mapping: dict[str, list[str]] = {}
    for finding in findings:
        for item in finding.get("evidence", []):
            mapping.setdefault(item.get("evidence_id"), []).append(
                finding["finding_id"]
            )
    return mapping


def _derive_severity(
    verdict: str,
    refs: list[str],
    claim: dict[str, Any],
    finding_by_id: dict[str, dict],
    evidence_to_findings: dict[str, list[str]],
) -> str:
    """Deterministic contradiction severity from verdict and linked findings."""
    if verdict == "supported":
        return "info"
    if verdict == "unsupported":
        if claim.get("claim_type") in _MEDIUM_UNSUPPORTED_TYPES:
            return "medium"
        return "low"
    linked: set[str] = set()
    for ref in refs:
        if ref in finding_by_id:
            linked.add(ref)
        linked.update(evidence_to_findings.get(ref, ()))
    if not linked:
        return "medium"
    return max(
        (finding_by_id[finding_id]["severity"] for finding_id in linked),
        key=lambda severity: SEVERITY_RANK[severity],
    )


def crosscheck_claims(
    claims: list[dict[str, Any]],
    findings: list[dict[str, Any]],
    evidence_pool: list[dict[str, Any]],
    mode: Mode = "standard",
) -> dict[str, Any]:
    """Judge each claim against the evidence; one contradiction per claim.

    Returns ``{contradictions, catalog, usage, estimated_cost_usd}``.
    Contradictions match the digest schema's ``contradiction`` definition
    and are numbered C-001... in claim order. ``catalog`` counts catalog
    items by category.
    """
    finding_by_id = {
        finding["finding_id"]: finding
        for finding in findings
        if isinstance(finding.get("finding_id"), str)
    }
    pool_ids = {
        item.get("evidence_id")
        for item in evidence_pool
        if isinstance(item.get("evidence_id"), str)
    }
    evidence_to_findings = _evidence_to_findings(findings)
    claim_lines = [
        f"[{claim.get('claim_index')}] "
        f"{claim.get('speaker')} @ {claim.get('timestamp')} "
        f"({claim.get('claim_type')}): {claim.get('text')}"
        for claim in claims
    ]
    client = ModelClient(role="crosscheck", mode=mode)
    result = client.chat_json(
        [
            {"role": "system", "content": SYSTEM_PROMPT},
            {
                "role": "user",
                "content": (
                    "Claims:\n"
                    + "\n".join(claim_lines)
                    + "\n"
                    + _catalog(findings, evidence_pool)
                ),
            },
        ],
        schema=crosscheck_schema(),
        schema_name="crosscheck_verdicts",
        reasoning_effort="medium",
    )
    known_indices = {
        claim.get("claim_index")
        for claim in claims
        if isinstance(claim.get("claim_index"), int)
        and not isinstance(claim.get("claim_index"), bool)
    }
    verdicts_by_claim: dict[int, dict] = {}
    for raw in result.get("verdicts", []):
        if not isinstance(raw, dict):
            continue
        index = raw.get("claim_index")
        if (
            not isinstance(index, int)
            or isinstance(index, bool)
            or index in verdicts_by_claim
            or index not in known_indices
        ):
            continue
        verdicts_by_claim[index] = raw
    contradictions = []
    for position, claim in enumerate(claims):
        raw = verdicts_by_claim.get(claim.get("claim_index"), {})
        verdict = raw.get("verdict")
        if verdict not in ("contradicted", "unsupported", "supported"):
            verdict = "unsupported"
        refs = raw.get("evidence_refs", [])
        if not isinstance(refs, list):
            refs = []
        valid = list(
            dict.fromkeys(
                ref
                for ref in refs
                if ref in finding_by_id or ref in pool_ids
            )
        )
        if verdict in ("contradicted", "supported") and not valid:
            verdict = "unsupported"
        explanation = raw.get("explanation")
        if explanation is None and not raw:
            explanation = "No model verdict returned for this claim."
        elif not isinstance(explanation, str):
            explanation = ""
        contradictions.append(
            {
                "contradiction_id": f"C-{position + 1:03d}",
                "claim": {
                    "speaker": claim.get("speaker"),
                    "timestamp": claim.get("timestamp"),
                    "text": claim.get("text"),
                    "claim_type": claim.get("claim_type"),
                },
                "verdict": verdict,
                "severity": _derive_severity(
                    verdict,
                    valid,
                    claim,
                    finding_by_id,
                    evidence_to_findings,
                ),
                "evidence_refs": valid,
                "explanation": explanation[:MAX_EXPLANATION_CHARS],
            }
        )
    usage = dict(client.total_usage)
    return {
        "contradictions": contradictions,
        "catalog": _catalog_counts(findings, evidence_pool),
        "usage": usage,
        "estimated_cost_usd": estimate_token_cost_usd(
            usage, WONDER_USD_PER_MTOK
        ),
    }


def _merge_cluster(items: list[dict[str, Any]], number: int) -> dict[str, Any]:
    """One contradiction from same-turn fragments sharing evidence."""
    best = max(
        range(len(items)),
        key=lambda i: (_VERDICT_PRECEDENCE[items[i]["verdict"]], -i),
    )
    refs: list[str] = []
    for item in items:
        for ref in item.get("evidence_refs", []):
            if ref not in refs:
                refs.append(ref)
    first_claim = items[0].get("claim", {})
    return {
        "contradiction_id": f"C-{number + 1:03d}",
        "claim": {
            "speaker": first_claim.get("speaker"),
            "timestamp": first_claim.get("timestamp"),
            "text": " … ".join(
                str(item.get("claim", {}).get("text") or "")
                for item in items
            )[:MAX_CLAIM_CHARS],
            "claim_type": items[best].get("claim", {}).get("claim_type"),
        },
        "verdict": items[best]["verdict"],
        "severity": max(
            (item["severity"] for item in items),
            key=lambda severity: SEVERITY_RANK[severity],
        ),
        "evidence_refs": refs,
        "explanation": items[best].get("explanation", ""),
    }


def merge_contradictions(
    contradictions: list[dict[str, Any]],
    claims: list[dict[str, Any]],
    findings: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[list[Any]]]:
    """Merge over-split same-turn fragments into one contradiction each.

    Within one turn, fragments whose evidence_refs overlap (or link to
    the same finding) merge: verdict by contradicted > unsupported >
    supported precedence, max severity, unioned refs, fragments joined
    with " … " (≤500 chars), and the top-precedence explanation.
    Fragments with disjoint evidence stay separate, as do all
    cross-turn pairs. C-ids renumber in first-appearance order.

    ``contradictions`` pairs positionally with ``claims`` (the
    cross-check emits one verdict per claim in order); the turn comes
    from each claim's turn_index.

    Returns (merged contradictions, member claim_index per merged item).
    """
    finding_by_id = {
        finding["finding_id"]
        for finding in findings
        if isinstance(finding.get("finding_id"), str)
    }
    evidence_to_findings = _evidence_to_findings(findings)

    def linked(refs: list[str]) -> set[str]:
        out: set[str] = set()
        for ref in refs:
            if ref in finding_by_id:
                out.add(ref)
            out.update(evidence_to_findings.get(ref, ()))
        return out

    groups: dict[Any, list[int]] = {}
    for position in range(len(contradictions)):
        turn = None
        if position < len(claims):
            turn = claims[position].get("turn_index")
        key = turn if turn is not None else ("_solo", position)
        groups.setdefault(key, []).append(position)

    merged: list[dict[str, Any]] = []
    members: list[list[Any]] = []
    for positions in groups.values():
        parent = {position: position for position in positions}

        def find(node: int) -> int:
            while parent[node] != node:
                parent[node] = parent[parent[node]]
                node = parent[node]
            return node

        for left in range(len(positions)):
            refs_left = set(
                contradictions[positions[left]].get("evidence_refs", [])
            )
            for right in range(left + 1, len(positions)):
                refs_right = set(
                    contradictions[positions[right]].get("evidence_refs", [])
                )
                if refs_left & refs_right or (
                    linked(list(refs_left)) & linked(list(refs_right))
                ):
                    parent[find(positions[left])] = find(positions[right])
        clusters: dict[int, list[int]] = {}
        for position in positions:
            clusters.setdefault(find(position), []).append(position)
        for root in sorted(clusters, key=lambda r: min(clusters[r])):
            cluster = sorted(clusters[root])
            merged.append(
                _merge_cluster(
                    [contradictions[p] for p in cluster], len(merged)
                )
            )
            members.append(
                [
                    claims[p].get("claim_index") if p < len(claims) else None
                    for p in cluster
                ]
            )
    return merged, members
