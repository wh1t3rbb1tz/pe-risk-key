# SPDX-License-Identifier: AGPL-3.0-or-later
"""MCP server (stdio) over saved risk digests.

Read-only: it reads ``eval/runs/*/digest.json`` and never triggers new
runs or makes network calls. For a PE associate's AI assistant.
"""

from __future__ import annotations

import json
from typing import Any

from mcp.server.mcpserver import MCPServer

from pe_risk_key.api import app as api_app
from pe_risk_key.engine.narrative import CAP_LABELS, DEAL_SIGNAL_LABELS

server = MCPServer(
    "pe-risk-key",
    instructions=(
        "PE Risk Key digests: outside-in cyber risk assessments of "
        "acquisition targets, each with a rating (A best, F worst), a "
        "plain-language deal decision, key risks with triage costs, "
        "management claims checked against evidence, and an IC-ready "
        "executive summary."
    ),
)

_SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
_RATING_RANK = {"A": 0, "B": 1, "C": 2, "D": 3, "F": 4}


def _money(value: Any) -> str:
    try:
        amount = float(value)
    except (TypeError, ValueError):
        return "-"
    if amount >= 1000:
        return f"${amount / 1000:.0f}K"
    return f"${amount:.0f}"


def _range(low: Any, high: Any) -> str:
    return f"{_money(low)}–{_money(high)}"


def _read_digest(digest_id: str) -> dict[str, Any]:
    path = api_app.RUNS_DIR / digest_id / "digest.json"
    if not path.exists():
        raise ValueError(f"No saved digest {digest_id!r}.")
    digest = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(digest, dict):
        raise ValueError(f"Saved digest {digest_id!r} is corrupt.")
    return digest


def _complete_entries() -> list[dict[str, Any]]:
    entries = api_app.list_digests()["digests"]
    return [entry for entry in entries if entry.get("complete")]


def _trace_narrative_valid(digest_id: str) -> bool | None:
    path = api_app.RUNS_DIR / digest_id / "trace.jsonl"
    if not path.exists():
        return None
    valid: bool | None = None
    for line in path.read_text(encoding="utf-8").splitlines():
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if event.get("type") == "narrative_complete":
            valid = event.get("valid")
    return valid


def _resolve_entry(
    entries: list[dict[str, Any]],
    domain: str | None,
    digest_id: str | None,
) -> dict[str, Any]:
    if digest_id is not None:
        for entry in entries:
            if entry["digest_id"] == digest_id:
                return entry
        raise ValueError(f"No complete digest {digest_id!r}.")
    group = [
        entry
        for entry in entries
        if (entry.get("target") or {}).get("domain") == domain
    ]
    if not group:
        raise ValueError(f"No complete digest for {domain!r}.")
    for entry in group:
        if entry.get("authoritative"):
            return entry
    return max(group, key=lambda e: e.get("generated_at") or "")


@server.tool()
def list_digests(
    include_superseded: bool = False,
) -> list[dict[str, Any]]:
    """List finished risk digests, newest first — one authoritative run
    per target (most inputs wins, then newest). Pass
    include_superseded=true to also list older runs superseded by a
    fuller assessment of the same target.

    Each entry has the digest id, target company, rating (A best,
    F worst), the plain-language deal decision, the run date, the
    inputs behind it, and schema/narrative validity flags. Use this
    to find which targets have been assessed, then call
    get_risk_digest for detail.
    """
    shown = [
        entry
        for entry in _complete_entries()
        if include_superseded or entry.get("authoritative")
    ]
    result = []
    for entry in shown:
        digest = _read_digest(entry["digest_id"])
        result.append(
            {
                "digest_id": entry["digest_id"],
                "company": (entry.get("target") or {}).get("name"),
                "rating": entry["rating"],
                "decision": entry["decision"],
                "date": (entry.get("generated_at") or "")[:10],
                "inputs": digest.get("inputs", {}),
                "schema_valid": entry.get("schema_valid"),
                "narrative_valid": entry.get("narrative_valid"),
            }
        )
    return result


@server.tool()
def get_risk_digest(
    domain: str | None = None, digest_id: str | None = None
) -> dict[str, Any]:
    """Get the authoritative risk digest for a target company.

    Pass the target's domain (e.g. "acme.example") or an exact
    digest_id from list_digests. A domain resolves to the authoritative
    run: the complete assessment with the most inputs (outside-in plus
    SOC 2 plus interview beats fewer), then the newest. Returns the
    rating, score, deal decision, rating caps in plain words,
    confidence, the top 5 risks with triage costs, counts of
    management claims by verdict, the total remediation cost, the
    inputs behind it, how many runs it supersedes, and the executive
    summary for the IC memo.
    """
    if not domain and not digest_id:
        raise ValueError("Pass domain or digest_id (or both).")
    entries = _complete_entries()
    entry = _resolve_entry(entries, domain, digest_id)
    digest = _read_digest(entry["digest_id"])
    target_domain = (digest.get("target") or {}).get("domain")
    superseded_runs = sum(
        1
        for other in entries
        if other["digest_id"] != entry["digest_id"]
        and (other.get("target") or {}).get("domain") == target_domain
    )
    overall = digest.get("overall", {})
    plan = digest.get("remediation_plan", {})
    findings = sorted(
        digest.get("findings", []),
        key=lambda f: (
            _SEVERITY_RANK.get(f.get("severity"), 4),
            f.get("finding_id") or "",
        ),
    )
    counts = {"contradicted": 0, "unsupported": 0, "supported": 0}
    for contradiction in digest.get("contradictions", []):
        verdict = contradiction.get("verdict")
        if verdict in counts:
            counts[verdict] += 1
    return {
        "digest_id": digest["digest_id"],
        "company": (digest.get("target") or {}).get("name"),
        "domain": (digest.get("target") or {}).get("domain"),
        "generated_at": digest.get("generated_at"),
        "rating": overall.get("rating"),
        "score": overall.get("score"),
        "decision": DEAL_SIGNAL_LABELS.get(
            overall.get("deal_signal"), overall.get("deal_signal")
        ),
        "caps": [
            CAP_LABELS.get(cap, cap)
            for cap in overall.get("rating_caps_applied", [])
        ],
        "confidence": overall.get("confidence"),
        "top_risks": [
            {
                "finding_id": finding.get("finding_id"),
                "title": finding.get("title"),
                "severity": finding.get("severity"),
                "cost": _range(
                    (finding.get("remediation") or {}).get(
                        "cost_low_usd", 0
                    ),
                    (finding.get("remediation") or {}).get(
                        "cost_high_usd", 0
                    ),
                ),
            }
            for finding in findings[:5]
        ],
        "contradiction_counts": counts,
        "remediation_total": {
            "low_usd": plan.get("total_cost_low_usd", 0),
            "high_usd": plan.get("total_cost_high_usd", 0),
            "display": _range(
                plan.get("total_cost_low_usd", 0),
                plan.get("total_cost_high_usd", 0),
            ),
        },
        "executive_summary": (
            digest.get("narrative") or {}
        ).get("executive_summary"),
        "inputs": digest.get("inputs", {}),
        "superseded_runs": superseded_runs,
        "schema_valid": entry.get("schema_valid"),
        "narrative_valid": _trace_narrative_valid(entry["digest_id"]),
    }


@server.tool()
def explain_finding(digest_id: str, finding_id: str) -> dict[str, Any]:
    """Explain one finding in depth: what was found, the evidence behind
    it, how to fix it, and whether management's claims about it held up.

    Returns the finding's title, severity, confidence, and deal impact;
    each evidence item with its locator and collection method; the
    remediation plan with triage cost and effort; and any management
    claim verdicts that cite this finding's evidence, each with its
    cited evidence resolved to excerpts (including supporting
    evidence that lives in no finding).
    """
    digest = _read_digest(digest_id)
    finding = next(
        (
            item
            for item in digest.get("findings", [])
            if item.get("finding_id") == finding_id
        ),
        None,
    )
    if finding is None:
        raise ValueError(f"No finding {finding_id!r} in {digest_id!r}.")
    remediation = finding.get("remediation") or {}
    evidence_ids = {
        item.get("evidence_id") for item in finding.get("evidence", [])
    }
    by_evidence_id: dict[str, dict[str, Any]] = {}
    for item in digest.get("findings", []):
        for evidence in item.get("evidence", []) or []:
            by_evidence_id[evidence.get("evidence_id")] = evidence
    for evidence in digest.get("supporting_evidence", []) or []:
        by_evidence_id.setdefault(
            evidence.get("evidence_id"), evidence
        )
    by_finding_id = {
        item.get("finding_id"): item
        for item in digest.get("findings", [])
    }

    def _resolve(ref: str) -> dict[str, Any]:
        if ref.startswith("F-"):
            target = by_finding_id.get(ref, {})
            return {"ref": ref, "title": target.get("title")}
        target = by_evidence_id.get(ref, {})
        return {
            "ref": ref,
            "excerpt": target.get("excerpt"),
            "locator": target.get("locator"),
        }

    citing = []
    for contradiction in digest.get("contradictions", []):
        refs = set(contradiction.get("evidence_refs", []))
        if finding_id in refs or refs & evidence_ids:
            citing.append(
                {
                    "contradiction_id": contradiction.get(
                        "contradiction_id"
                    ),
                    "verdict": contradiction.get("verdict"),
                    "severity": contradiction.get("severity"),
                    "claim_text": (
                        contradiction.get("claim") or {}
                    ).get("text"),
                    "explanation": contradiction.get("explanation"),
                    "evidence": [
                        _resolve(ref)
                        for ref in contradiction.get("evidence_refs", [])
                    ],
                }
            )
    return {
        "digest_id": digest_id,
        "finding_id": finding_id,
        "title": finding.get("title"),
        "severity": finding.get("severity"),
        "confidence": finding.get("confidence"),
        "deal_impact": finding.get("deal_impact"),
        "evidence": [
            {
                "evidence_id": item.get("evidence_id"),
                "excerpt": item.get("excerpt"),
                "locator": item.get("locator"),
                "collection_method": item.get("collection_method"),
                "source_type": item.get("source_type"),
            }
            for item in finding.get("evidence", [])
        ],
        "remediation": {
            "summary": remediation.get("summary"),
            "cost_low_usd": remediation.get("cost_low_usd", 0),
            "cost_high_usd": remediation.get("cost_high_usd", 0),
            "cost": _range(
                remediation.get("cost_low_usd", 0),
                remediation.get("cost_high_usd", 0),
            ),
            "effort_weeks": remediation.get("effort_weeks"),
        },
        "contradictions_citing": citing,
    }


@server.tool()
def compare_targets(digest_ids: list[str]) -> dict[str, Any]:
    """Compare 2–3 targets side by side for relative risk. Pure
    arithmetic over saved digests; makes no model calls.

    Pass digest ids from list_digests. Returns a per-target table
    (rating, score, decision, critical/high finding counts,
    contradicted management claims, remediation total, assessed
    functions) plus a one-line relative-risk ranking, highest risk
    first.
    """
    if not 2 <= len(digest_ids) <= 3:
        raise ValueError(
            f"compare_targets needs 2–3 digest ids, got {len(digest_ids)}."
        )
    rows = []
    for digest_id in digest_ids:
        digest = _read_digest(digest_id)
        overall = digest.get("overall", {})
        plan = digest.get("remediation_plan", {})
        severities = [
            item.get("severity") for item in digest.get("findings", [])
        ]
        rows.append(
            {
                "digest_id": digest_id,
                "company": (digest.get("target") or {}).get("name"),
                "domain": (digest.get("target") or {}).get("domain"),
                "rating": overall.get("rating"),
                "score": overall.get("score"),
                "decision": DEAL_SIGNAL_LABELS.get(
                    overall.get("deal_signal"),
                    overall.get("deal_signal"),
                ),
                "critical_count": severities.count("critical"),
                "high_count": severities.count("high"),
                "contradicted_count": sum(
                    1
                    for item in digest.get("contradictions", [])
                    if item.get("verdict") == "contradicted"
                ),
                "remediation_total": _range(
                    plan.get("total_cost_low_usd", 0),
                    plan.get("total_cost_high_usd", 0),
                ),
                "assessed_functions": [
                    entry.get("function")
                    for entry in digest.get("function_scores", [])
                    if entry.get("assessed")
                ],
            }
        )
    ranked = sorted(
        rows,
        key=lambda r: (
            -_RATING_RANK.get(r["rating"], 5),
            r["score"] if isinstance(r["score"], (int, float)) else 0,
            r["digest_id"],
        ),
    )

    def _score(row: dict[str, Any]) -> str:
        score = row["score"]
        return f"{score:.1f}" if isinstance(score, (int, float)) else "?"

    statement = (
        "Highest to lowest risk: "
        + "; ".join(
            f"{row['company']} ({row['rating']}, {_score(row)})"
            for row in ranked
        )
        + "."
    )
    return {"targets": rows, "relative_risk": statement}


def main() -> None:
    server.run()


if __name__ == "__main__":
    main()
