"""Deterministic scoring (SPEC §4.5, scoring.yaml).

Pure Python, no model calls. Same findings in -> same score out: all
thresholds, weights, and caps come from scoring.yaml; only the cap
predicates live here as explicit functions (the YAML ``when`` strings
are documentation, not parsed).
"""

from __future__ import annotations

import os
from typing import Any, Callable

FUNCTIONS = ("GV", "ID", "PR", "DE", "RS", "RC")

SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
CONFIDENCE_RANK = {"low": 0, "medium": 1, "high": 2}
RATING_RANK = {"F": 0, "D": 1, "C": 2, "B": 3, "A": 4}

WINDOW_BY_SEVERITY = {
    "critical": "days_0_30",
    "high": "days_31_60",
    "medium": "days_61_100",
    "low": "post_100",
    "info": "post_100",
}

OWNER_BY_FUNCTION = {
    "GV": "CISO/Board",
    "ID": "IT Ops",
    "PR": "Security Engineering",
    "DE": "SecOps",
    "RS": "Incident Response",
    "RC": "IT Ops",
}


def assessed_functions(
    scoring_config: dict[str, Any],
    *,
    domain_scan: bool,
    has_soc2: bool,
    has_interview: bool,
) -> list[str]:
    """CSF functions covered by at least one provided input, in order."""
    coverage = scoring_config.get("function_coverage", {})
    provided = {
        "outside_in": domain_scan,
        "soc2": has_soc2,
        "interview": has_interview,
    }
    covered: set[str] = set()
    for input_name, functions in coverage.items():
        if provided.get(input_name):
            covered.update(functions)
    return [function for function in FUNCTIONS if function in covered]


def _decay_for(index: int, decay: list[float]) -> float:
    return decay[min(index, len(decay) - 1)]


def score_functions(
    findings: list[dict[str, Any]],
    contradictions: list[dict[str, Any]],
    scoring_config: dict[str, Any],
    assessed: list[str],
) -> list[dict[str, Any]]:
    """Score all six functions; unassessed ones stay 100 with count 0."""
    points = scoring_config["severity_points"]
    multipliers = scoring_config["confidence_multiplier"]
    decay = scoring_config["same_category_decay"]
    assessed_set = set(assessed)

    by_category: dict[str, list[dict]] = {}
    for finding in findings:
        by_category.setdefault(finding["csf_category"], []).append(finding)

    penalties: dict[str, float] = {function: 0.0 for function in FUNCTIONS}
    counts: dict[str, int] = {function: 0 for function in FUNCTIONS}
    for category in sorted(by_category):
        ordered = sorted(
            by_category[category],
            key=lambda f: (
                -SEVERITY_RANK[f["severity"]],
                -CONFIDENCE_RANK[f["confidence"]],
                f["finding_id"],
            ),
        )
        for index, finding in enumerate(ordered):
            function = finding["csf_function"]
            if function not in assessed_set:
                continue
            penalties[function] += (
                points[finding["severity"]]
                * multipliers[finding["confidence"]]
                * _decay_for(index, decay)
            )
            counts[function] += 1

    target = scoring_config.get("contradiction_function")
    if target in assessed_set:
        table = scoring_config["contradiction_points"]
        for contradiction in contradictions:
            entry = table[contradiction["verdict"]]
            if isinstance(entry, dict):
                penalties[target] += entry[contradiction["severity"]]

    return [
        {
            "function": function,
            "score": round(max(0.0, 100.0 - penalties[function]), 4),
            "finding_count": counts[function],
        }
        for function in FUNCTIONS
    ]


def weighted_score(
    function_scores: list[dict[str, Any]],
    scoring_config: dict[str, Any],
    assessed: list[str],
) -> float:
    """Weight-renormalized mean over assessed functions only."""
    if not assessed:
        raise ValueError("No assessed functions; nothing to score.")
    weights = scoring_config["function_weights"]
    by_function = {entry["function"]: entry["score"] for entry in function_scores}
    total_weight = sum(weights[function] for function in assessed)
    return round(
        sum(by_function[function] * weights[function] for function in assessed)
        / total_weight,
        4,
    )


def rating_for_score(score: float, scoring_config: dict[str, Any]) -> str:
    """First rating band (highest first) whose lower bound holds."""
    bands = sorted(
        scoring_config["rating_bands"].items(), key=lambda kv: -kv[1]
    )
    for rating, lower_bound in bands:
        if score >= lower_bound:
            return rating
    raise AssertionError("unreachable: F band starts at 0")  # pragma: no cover


# --- Rating caps -------------------------------------------------------------
# One explicit predicate per cap id in scoring.yaml. Each takes a context
# dict {findings, contradictions, soc2_opinion} and returns True when the
# cap fires. The YAML `when` strings document the same condition.

CapContext = dict[str, Any]


def cap_critical_findings(ctx: CapContext) -> bool:
    """CAP-CRIT: any critical finding with medium/high confidence."""
    return any(
        finding["severity"] == "critical"
        and finding["confidence"] in ("medium", "high")
        for finding in ctx["findings"]
    )


def cap_soc2_qualified(ctx: CapContext) -> bool:
    """CAP-SOC2-QUAL: SOC 2 opinion qualified, adverse, or disclaimer."""
    return ctx.get("soc2_opinion") in ("qualified", "adverse", "disclaimer")


def cap_incident(ctx: CapContext) -> bool:
    """CAP-INCIDENT: any PUB-INCIDENT-RECENT finding."""
    return any(
        finding.get("rule_id") == "PUB-INCIDENT-RECENT"
        for finding in ctx["findings"]
    )


def cap_contradictions(ctx: CapContext) -> bool:
    """CAP-CONTRADICTION: 2+ contradicted critical/high contradictions."""
    count = sum(
        1
        for contradiction in ctx["contradictions"]
        if contradiction["verdict"] == "contradicted"
        and contradiction["severity"] in ("critical", "high")
    )
    return count >= 2


CAP_IMPLEMENTATIONS: dict[str, Callable[[CapContext], bool]] = {
    "CAP-CRIT": cap_critical_findings,
    "CAP-SOC2-QUAL": cap_soc2_qualified,
    "CAP-INCIDENT": cap_incident,
    "CAP-CONTRADICTION": cap_contradictions,
}


def apply_rating_caps(
    rating: str, ctx: CapContext, scoring_config: dict[str, Any]
) -> tuple[str, list[str]]:
    """Downgrade rating through firing caps; returns (rating, caps_applied)."""
    applied: list[str] = []
    for cap in scoring_config.get("rating_caps", []):
        predicate = CAP_IMPLEMENTATIONS[cap["id"]]
        if predicate(ctx):
            applied.append(cap["id"])
            if RATING_RANK[cap["max_rating"]] < RATING_RANK[rating]:
                rating = cap["max_rating"]
    return rating, applied


def confidence_level(
    *, domain_scan: bool, has_soc2: bool, has_interview: bool
) -> str:
    """high: scan + soc2 + interview; medium: scan + either; else low."""
    if domain_scan and has_soc2 and has_interview:
        return "high"
    if domain_scan and (has_soc2 or has_interview):
        return "medium"
    return "low"


def deal_signal(
    *,
    rating: str,
    caps_applied: list[str],
    total_cost_high_usd: float,
    revenue_band: str,
    scoring_config: dict[str, Any],
    findings: list[dict[str, Any]],
) -> str:
    """First matching deal_signal_rule wins (YAML order)."""
    midpoint = scoring_config["revenue_midpoint_usd"][revenue_band]
    if rating in ("D", "F") or "CAP-INCIDENT" in caps_applied:
        return "escalate_full_diligence"
    if total_cost_high_usd > 0.01 * midpoint:
        return "reprice_or_restructure"
    if rating == "C" or any(f["severity"] == "high" for f in findings):
        return "proceed_with_conditions"
    return "proceed"


def remediation_plan(
    findings: list[dict[str, Any]],
) -> dict[str, Any]:
    """One plan item per finding, in findings order, plus cost totals."""
    items = []
    for finding in findings:
        remediation = finding.get("remediation", {})
        summary = remediation.get("summary") or finding.get("title", "")
        items.append(
            {
                "action": summary,
                "finding_ids": [finding["finding_id"]],
                "window": WINDOW_BY_SEVERITY[finding["severity"]],
                "cost_low_usd": remediation.get("cost_low_usd", 0),
                "cost_high_usd": remediation.get("cost_high_usd", 0),
                "owner_role": OWNER_BY_FUNCTION[finding["csf_function"]],
            }
        )
    return {
        "items": items,
        "total_cost_low_usd": sum(item["cost_low_usd"] for item in items),
        "total_cost_high_usd": sum(item["cost_high_usd"] for item in items),
    }


def limitations(
    *,
    assessed: list[str],
    has_soc2: bool,
    has_interview: bool,
    demo: bool | None = None,
) -> list[str]:
    """Deterministic limitations list; always non-empty."""
    if demo is None:
        demo = os.getenv("DEMO_MODE") == "1"
    unassessed = [f for f in FUNCTIONS if f not in set(assessed)]
    entries = []
    if unassessed:
        entries.append(
            "Unassessed CSF functions (no evidence from provided inputs): "
            + ", ".join(unassessed)
        )
    entries.append(
        "Passive outside-in assessment only; no authenticated or internal testing"
    )
    entries.append("KEV matches are product-level; versions not verified")
    if not has_soc2:
        entries.append("No SOC 2 report provided")
    if not has_interview:
        entries.append("No management interview provided")
    if demo:
        entries.append("Demo mode: signals from fixtures")
    return entries


def score_digest(
    findings: list[dict[str, Any]],
    contradictions: list[dict[str, Any]],
    scoring_config: dict[str, Any],
    *,
    domain_scan: bool = True,
    has_soc2: bool = False,
    has_interview: bool = False,
    soc2_opinion: str | None = None,
    revenue_band: str,
    demo: bool | None = None,
) -> dict[str, Any]:
    """Full deterministic scoring pass.

    Returns ``{function_scores, overall, remediation_plan, limitations}``
    with ``overall = {score, rating, deal_signal, confidence,
    rating_caps_applied}``.
    """
    assessed = assessed_functions(
        scoring_config,
        domain_scan=domain_scan,
        has_soc2=has_soc2,
        has_interview=has_interview,
    )
    function_scores = score_functions(
        findings, contradictions, scoring_config, assessed
    )
    score = weighted_score(function_scores, scoring_config, assessed)
    rating = rating_for_score(score, scoring_config)
    ctx: CapContext = {
        "findings": findings,
        "contradictions": contradictions,
        "soc2_opinion": soc2_opinion,
    }
    rating, caps_applied = apply_rating_caps(rating, ctx, scoring_config)
    plan = remediation_plan(findings)
    overall = {
        "score": score,
        "rating": rating,
        "deal_signal": deal_signal(
            rating=rating,
            caps_applied=caps_applied,
            total_cost_high_usd=plan["total_cost_high_usd"],
            revenue_band=revenue_band,
            scoring_config=scoring_config,
            findings=findings,
        ),
        "confidence": confidence_level(
            domain_scan=domain_scan,
            has_soc2=has_soc2,
            has_interview=has_interview,
        ),
        "rating_caps_applied": caps_applied,
    }
    return {
        "function_scores": function_scores,
        "overall": overall,
        "remediation_plan": plan,
        "limitations": limitations(
            assessed=assessed,
            has_soc2=has_soc2,
            has_interview=has_interview,
            demo=demo,
        ),
    }
