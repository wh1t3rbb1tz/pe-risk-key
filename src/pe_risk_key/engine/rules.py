"""Deterministic rule constraints (SPEC §4.5, scoring.yaml).

The model proposes findings; this module clamps them to the matching
rule's bounds so the same signals always produce the same floor:
confidence, severity (within one level of baseline), CSF category,
finding source, and remediation cost/effort. Every change (and every
unmatchable finding) is recorded as an adjustment dict
``{finding_id, field, from, to, reason}`` for the dashboard trace panel.
Inputs are never mutated.
"""

from __future__ import annotations

import copy
import math
from typing import Any

SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]
CONFIDENCE_ORDER = ["low", "medium", "high"]
DEFAULT_EMPLOYEE_BAND = "201-1000"


def apply_rule_constraints(
    findings: list[dict[str, Any]],
    scoring_config: dict[str, Any],
    employee_band: str | None = None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Clamp findings to their scoring.yaml rule bounds.

    ``employee_band`` (from the target record) sizes remediation costs;
    when omitted it defaults to ``201-1000`` with a ``default_size_band``
    adjustment. Returns ``(constrained_findings, adjustments)``. Findings
    whose ``rule_id`` matches no rule are kept unchanged and recorded
    with reason ``unknown_rule``.
    """
    rules = {
        rule["id"]: rule
        for rule in scoring_config.get("rules", [])
        if isinstance(rule, dict) and "id" in rule
    }
    constrained: list[dict[str, Any]] = []
    adjustments: list[dict[str, Any]] = []
    for finding in findings:
        if not isinstance(finding, dict):
            constrained.append(finding)
            continue
        updated = copy.deepcopy(finding)
        finding_id = finding.get("finding_id", "?")
        rule = rules.get(finding.get("rule_id"))
        if rule is None:
            adjustments.append(
                {
                    "finding_id": finding_id,
                    "field": "rule_id",
                    "from": finding.get("rule_id"),
                    "to": finding.get("rule_id"),
                    "reason": "unknown_rule",
                }
            )
            constrained.append(updated)
            continue
        _clamp_confidence(updated, finding_id, rule, adjustments)
        _clamp_severity(updated, finding_id, rule, adjustments)
        _apply_csf(updated, finding_id, rule, adjustments)
        _apply_source(updated, finding_id, rule, adjustments)
        _apply_cost(
            updated, finding_id, rule, scoring_config, employee_band, adjustments
        )
        _apply_effort(updated, finding_id, rule, adjustments)
        constrained.append(updated)
    return constrained, adjustments


def _is_cost_pair(value: Any) -> bool:
    return (
        isinstance(value, (list, tuple))
        and len(value) == 2
        and all(isinstance(v, (int, float)) for v in value)
    )


def _round_500(value: float) -> int:
    return int(math.floor(value / 500 + 0.5)) * 500


def _apply_cost(
    finding: dict[str, Any],
    finding_id: Any,
    rule: dict[str, Any],
    scoring_config: dict[str, Any],
    employee_band: str | None,
    adjustments: list[dict[str, Any]],
) -> None:
    remediation = finding.get("remediation")
    if not isinstance(remediation, dict):
        return
    band = employee_band if employee_band is not None else DEFAULT_EMPLOYEE_BAND
    override = rule.get("cost_override_usd")
    if _is_cost_pair(override):
        multipliers = scoring_config.get("cost_size_multiplier", {})
        multiplier = (
            multipliers.get(band) if isinstance(multipliers, dict) else None
        )
        if not isinstance(multiplier, (int, float)):
            return
        new = [
            _round_500(override[0] * multiplier),
            _round_500(override[1] * multiplier),
        ]
        reason = "cost_override"
    else:
        bands = scoring_config.get("cost_bands_usd", {})
        sizes = bands.get(band) if isinstance(bands, dict) else None
        pair = (
            sizes.get(finding.get("severity"))
            if isinstance(sizes, dict)
            else None
        )
        if not _is_cost_pair(pair):
            return
        new = [pair[0], pair[1]]
        reason = "cost_band"
    if employee_band is None:
        adjustments.append(
            {
                "finding_id": finding_id,
                "field": "employee_band",
                "from": None,
                "to": DEFAULT_EMPLOYEE_BAND,
                "reason": "default_size_band",
            }
        )
    old = [remediation.get("cost_low_usd"), remediation.get("cost_high_usd")]
    if old == new:
        return
    remediation["cost_low_usd"] = new[0]
    remediation["cost_high_usd"] = new[1]
    adjustments.append(
        {
            "finding_id": finding_id,
            "field": "remediation.cost_usd",
            "from": old,
            "to": new,
            "reason": reason,
        }
    )


def _clamp_confidence(
    finding: dict[str, Any],
    finding_id: Any,
    rule: dict[str, Any],
    adjustments: list[dict[str, Any]],
) -> None:
    cap = rule.get("max_confidence")
    current = finding.get("confidence")
    if (
        cap not in CONFIDENCE_ORDER
        or current not in CONFIDENCE_ORDER
        or CONFIDENCE_ORDER.index(current) <= CONFIDENCE_ORDER.index(cap)
    ):
        return
    finding["confidence"] = cap
    adjustments.append(
        {
            "finding_id": finding_id,
            "field": "confidence",
            "from": current,
            "to": cap,
            "reason": "max_confidence",
        }
    )


def _clamp_severity(
    finding: dict[str, Any],
    finding_id: Any,
    rule: dict[str, Any],
    adjustments: list[dict[str, Any]],
) -> None:
    baseline = rule.get("severity")
    current = finding.get("severity")
    if baseline not in SEVERITY_ORDER or current not in SEVERITY_ORDER:
        return
    delta = SEVERITY_ORDER.index(current) - SEVERITY_ORDER.index(baseline)
    if abs(delta) <= 1:
        return
    clamped = SEVERITY_ORDER[SEVERITY_ORDER.index(baseline) + (1 if delta > 0 else -1)]
    finding["severity"] = clamped
    adjustments.append(
        {
            "finding_id": finding_id,
            "field": "severity",
            "from": current,
            "to": clamped,
            "reason": "severity_bounds",
        }
    )


def _apply_csf(
    finding: dict[str, Any],
    finding_id: Any,
    rule: dict[str, Any],
    adjustments: list[dict[str, Any]],
) -> None:
    csf = rule.get("csf")
    if not isinstance(csf, str) or "." not in csf:
        return
    if finding.get("csf_category") != csf:
        adjustments.append(
            {
                "finding_id": finding_id,
                "field": "csf_category",
                "from": finding.get("csf_category"),
                "to": csf,
                "reason": "rule_csf",
            }
        )
        finding["csf_category"] = csf
    function = csf.split(".", 1)[0]
    if finding.get("csf_function") != function:
        adjustments.append(
            {
                "finding_id": finding_id,
                "field": "csf_function",
                "from": finding.get("csf_function"),
                "to": function,
                "reason": "rule_csf",
            }
        )
        finding["csf_function"] = function


def _apply_source(
    finding: dict[str, Any],
    finding_id: Any,
    rule: dict[str, Any],
    adjustments: list[dict[str, Any]],
) -> None:
    evidence = finding.get("evidence")
    types = (
        {item.get("source_type") for item in evidence if isinstance(item, dict)}
        if isinstance(evidence, list)
        else set()
    )
    if "public_record" in types and not (types & {"document", "interview"}):
        derived = "public_record"
    elif isinstance(rule.get("id"), str) and rule["id"].startswith("SOC2-"):
        derived = "document"
    else:
        return
    if finding.get("source") != derived:
        adjustments.append(
            {
                "finding_id": finding_id,
                "field": "source",
                "from": finding.get("source"),
                "to": derived,
                "reason": "source",
            }
        )
        finding["source"] = derived


def _apply_effort(
    finding: dict[str, Any],
    finding_id: Any,
    rule: dict[str, Any],
    adjustments: list[dict[str, Any]],
) -> None:
    remediation = finding.get("remediation")
    if not isinstance(remediation, dict):
        return
    override = rule.get("effort_weeks_override")
    if not isinstance(override, (int, float)):
        return
    if remediation.get("effort_weeks") == override:
        return
    adjustments.append(
        {
            "finding_id": finding_id,
            "field": "remediation.effort_weeks",
            "from": remediation.get("effort_weeks"),
            "to": override,
            "reason": "effort_override",
        }
    )
    remediation["effort_weeks"] = override
