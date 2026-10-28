"""Deterministic rule constraints (SPEC §4.5, scoring.yaml).

The model proposes findings; this module clamps them to the matching
rule's bounds so the same signals always produce the same floor:
confidence, severity (within one level of baseline), CSF category, and
remediation cost bands. Every change (and every unmatchable finding) is
recorded as an adjustment dict ``{finding_id, field, from, to, reason}``
for the dashboard trace panel. Inputs are never mutated.
"""

from __future__ import annotations

import copy
from typing import Any

SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]
CONFIDENCE_ORDER = ["low", "medium", "high"]


def apply_rule_constraints(
    findings: list[dict[str, Any]],
    scoring_config: dict[str, Any],
    employee_band: str | None = None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Clamp findings to their scoring.yaml rule bounds.

    ``employee_band`` (from the target record) enables the remediation
    cost lookup; when omitted, costs are left untouched. Returns
    ``(constrained_findings, adjustments)``. Findings whose ``rule_id``
    matches no rule are kept unchanged and recorded with reason
    ``unknown_rule``.
    """
    rules = {
        rule["id"]: rule
        for rule in scoring_config.get("rules", [])
        if isinstance(rule, dict) and "id" in rule
    }
    cost_bands = scoring_config.get("cost_bands_usd", {})
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
        _apply_cost(updated, finding_id, rule, cost_bands, employee_band, adjustments)
        constrained.append(updated)
    return constrained, adjustments


def _is_cost_pair(value: Any) -> bool:
    return (
        isinstance(value, (list, tuple))
        and len(value) == 2
        and all(isinstance(v, (int, float)) for v in value)
    )


def _apply_cost(
    finding: dict[str, Any],
    finding_id: Any,
    rule: dict[str, Any],
    cost_bands: Any,
    employee_band: str | None,
    adjustments: list[dict[str, Any]],
) -> None:
    remediation = finding.get("remediation")
    if not isinstance(remediation, dict):
        return
    override = rule.get("cost_override_usd")
    if _is_cost_pair(override):
        low, high = override
    elif employee_band is not None and isinstance(cost_bands, dict):
        band = cost_bands.get(employee_band)
        pair = band.get(finding.get("severity")) if isinstance(band, dict) else None
        if not _is_cost_pair(pair):
            return
        low, high = pair
    else:
        return
    old = [remediation.get("cost_low_usd"), remediation.get("cost_high_usd")]
    if old == [low, high]:
        return
    remediation["cost_low_usd"] = low
    remediation["cost_high_usd"] = high
    adjustments.append(
        {
            "finding_id": finding_id,
            "field": "remediation.cost_usd",
            "from": old,
            "to": [low, high],
            "reason": "cost_band",
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
