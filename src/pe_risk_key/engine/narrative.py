"""Narrative engine (SPEC §4.6): IC memo summary, questions, deal recs.

One Muse Wonder call drafts the investment-committee narrative from the
scored digest; code then validates citations, grounding, and references,
regenerating once on failure.
"""

from __future__ import annotations

import json
import re
from typing import Any

from pe_risk_key.providers import (
    WONDER_USD_PER_MTOK,
    Mode,
    ModelClient,
    estimate_token_cost_usd,
)
from pe_risk_key.schemas import deal_recommendation_type_enum

SYSTEM_PROMPT = """You write the investment-committee narrative for a cyber-risk digest. Rules:
1. executive_summary (max 1800 characters) is written for an IC memo: the rating and why, the caps applied, the top risks, the management-credibility issue from any contradictions, and what to do next.
2. Every sentence that asserts a risk must cite at least one finding or contradiction id in square brackets, e.g. [F-001] [C-002].
3. Never state numbers (costs, counts, dates, scores) that aren't in the input; use the scored values exactly as given.
4. Deal recommendations must reference the remediation windows and the deal signal.
5. key_questions_for_management: 5 to 8 questions, each tied to specific findings or contradictions via bracket citations."""

MAX_SUMMARY_CHARS = 1800

RISK_KEYWORDS = (
    "exception",
    "contradict",
    "breach",
    "kev",
    "not enforced",
    "gap",
    "exposure",
)

_CITE_RE = re.compile(r"\[(F|C)-(\d{3})\]")
_NUMBER_RE = re.compile(r"\d[\d,]*(?:\.\d+)?")
_WINDOW_LABELS = {
    "days_0_30": "Days 0-30",
    "days_31_60": "Days 31-60",
    "days_61_100": "Days 61-100",
    "post_100": "Post-100",
}
_PLAN_WINDOWS = ("days_0_30", "days_31_60", "days_61_100")


def narrative_schema() -> dict[str, Any]:
    """Strict-ready schema for the IC narrative output."""
    return {
        "type": "object",
        "additionalProperties": False,
        "required": [
            "executive_summary",
            "key_questions_for_management",
            "deal_recommendations",
        ],
        "properties": {
            "executive_summary": {
                "type": "string",
                "description": "IC memo summary, max 1800 chars.",
            },
            "key_questions_for_management": {
                "type": "array",
                "items": {"type": "string"},
                "description": "5 to 8 questions with bracket citations.",
            },
            "deal_recommendations": {
                "type": "array",
                "items": {
                    "type": "object",
                    "additionalProperties": False,
                    "required": ["type", "text", "basis_ids"],
                    "properties": {
                        "type": {
                            "type": "string",
                            "enum": deal_recommendation_type_enum(),
                        },
                        "text": {"type": "string"},
                        "basis_ids": {
                            "type": "array",
                            "items": {"type": "string"},
                        },
                    },
                },
            },
        },
    }


def _split_sentences(text: str) -> list[str]:
    """Naive sentence split on end punctuation followed by whitespace."""
    return [
        sentence.strip()
        for sentence in re.split(r"(?<=[.!?])\s+", text.strip())
        if sentence.strip()
    ]


def _number_tokens(text: str) -> set[str]:
    """Digit tokens with commas stripped ($10,000 -> 10000)."""
    return {
        match.replace(",", "") for match in _NUMBER_RE.findall(text)
    }


def _cited_ids(text: str) -> list[str]:
    return [f"{kind}-{num}" for kind, num in _CITE_RE.findall(text)]


def validate_narrative(
    output: Any,
    *,
    finding_ids: set[str],
    contradiction_ids: set[str],
    input_numbers: set[str],
) -> list[str]:
    """Human-readable validation errors; empty means valid."""
    errors: list[str] = []
    if not isinstance(output, dict):
        return ["narrative output is not an object."]
    summary = output.get("executive_summary")
    if not isinstance(summary, str):
        errors.append("executive_summary is not a string.")
        summary = ""
    elif len(summary) > MAX_SUMMARY_CHARS:
        errors.append(
            f"executive_summary is {len(summary)} chars "
            f"(max {MAX_SUMMARY_CHARS})."
        )
    questions = output.get("key_questions_for_management")
    if not isinstance(questions, list):
        errors.append("key_questions_for_management is not a list.")
        questions = []
    elif not 5 <= len(questions) <= 8:
        errors.append(
            f"key_questions_for_management has {len(questions)} entries "
            "(need 5-8)."
        )
    recs = output.get("deal_recommendations")
    if not isinstance(recs, list):
        errors.append("deal_recommendations is not a list.")
        recs = []

    def check_text(label: str, text: Any, require_citation: bool) -> None:
        if not isinstance(text, str):
            errors.append(f"{label} is not a string.")
            return
        if require_citation and not _CITE_RE.search(text):
            errors.append(
                f"{label} is not tied to any finding or contradiction."
            )
        for sentence in _split_sentences(text):
            lowered = sentence.lower()
            if any(word in lowered for word in RISK_KEYWORDS) and not (
                _CITE_RE.search(sentence)
            ):
                errors.append(
                    f"{label} has an uncited risk sentence: "
                    f"{sentence[:100]}"
                )

    check_text("executive_summary", summary, require_citation=False)
    for index, question in enumerate(questions):
        check_text(f"question {index + 1}", question, require_citation=True)
    valid_types = set(deal_recommendation_type_enum())
    for index, rec in enumerate(recs):
        label = f"deal_recommendations[{index}]"
        if not isinstance(rec, dict):
            errors.append(f"{label} is not an object.")
            continue
        if rec.get("type") not in valid_types:
            errors.append(f"{label} has unknown type {rec.get('type')!r}.")
        check_text(label, rec.get("text"), require_citation=False)
        basis = rec.get("basis_ids")
        if not isinstance(basis, list) or not basis:
            errors.append(f"{label} has no basis_ids.")
        else:
            for ref in basis:
                if ref in finding_ids or ref in contradiction_ids:
                    continue
                errors.append(f"{label} cites unknown id {ref!r}.")
    cited: set[str] = set()
    texts: list[Any] = [summary, *questions]
    texts.extend(
        rec.get("text") for rec in recs if isinstance(rec, dict)
    )
    for text in texts:
        if isinstance(text, str):
            cited.update(_cited_ids(text))
    for ref in sorted(cited):
        if ref in finding_ids or ref in contradiction_ids:
            continue
        errors.append(f"cited id {ref} does not exist in this digest.")
    for token in sorted(_number_tokens(summary) - input_numbers):
        errors.append(
            f"executive_summary states number {token} not in the input."
        )
    return errors


def generate_narrative(
    payload: dict[str, Any], mode: Mode = "standard"
) -> dict[str, Any]:
    """Draft, validate, and (once) regenerate the IC narrative.

    ``payload`` carries target, overall, function_scores, findings,
    contradictions, remediation_plan, soc2_summary, and limitations.
    Returns ``{narrative, deal_recommendations, valid,
    validation_errors, regenerated, usage, estimated_cost_usd}``. The
    narrative is sanitized for digest safety even when invalid.
    """
    findings = payload.get("findings", [])
    contradictions = payload.get("contradictions", [])
    finding_ids = {
        finding["finding_id"]
        for finding in findings
        if isinstance(finding.get("finding_id"), str)
    }
    contradiction_ids = {
        item["contradiction_id"]
        for item in contradictions
        if isinstance(item.get("contradiction_id"), str)
    }
    input_numbers = _number_tokens(json.dumps(payload))
    client = ModelClient(role="narrative", mode=mode)
    messages: list[dict[str, Any]] = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": json.dumps(payload, indent=2)},
    ]
    output = client.chat_json(
        messages,
        schema=narrative_schema(),
        schema_name="narrative",
        reasoning_effort="medium",
    )
    errors = validate_narrative(
        output,
        finding_ids=finding_ids,
        contradiction_ids=contradiction_ids,
        input_numbers=input_numbers,
    )
    regenerated = False
    if errors:
        regenerated = True
        messages = [
            *messages,
            {"role": "assistant", "content": json.dumps(output)},
            {
                "role": "user",
                "content": (
                    "Your previous output had these validation errors:\n"
                    + "\n".join(f"- {error}" for error in errors)
                    + "\nFix all of them and return the full corrected output."
                ),
            },
        ]
        output = client.chat_json(
            messages,
            schema=narrative_schema(),
            schema_name="narrative",
            reasoning_effort="medium",
        )
        errors = validate_narrative(
            output,
            finding_ids=finding_ids,
            contradiction_ids=contradiction_ids,
            input_numbers=input_numbers,
        )
    valid = not errors
    summary = output.get("executive_summary", "")
    questions = output.get("key_questions_for_management", [])
    valid_types = set(deal_recommendation_type_enum())
    recs: list[dict[str, Any]] = []
    for rec in output.get("deal_recommendations", []) or []:
        if not isinstance(rec, dict) or rec.get("type") not in valid_types:
            continue
        basis = [
            ref
            for ref in (rec.get("basis_ids") or [])
            if ref in finding_ids or ref in contradiction_ids
        ]
        if not basis:
            continue
        recs.append(
            {
                "type": rec["type"],
                "text": rec.get("text", "")
                if isinstance(rec.get("text"), str)
                else "",
                "basis_ids": basis,
            }
        )
    usage = dict(client.total_usage)
    return {
        "narrative": {
            "executive_summary": summary[:MAX_SUMMARY_CHARS]
            if isinstance(summary, str)
            else "",
            "key_questions_for_management": [
                question for question in questions if isinstance(question, str)
            ],
        },
        "deal_recommendations": recs,
        "valid": valid,
        "validation_errors": errors,
        "regenerated": regenerated,
        "usage": usage,
        "estimated_cost_usd": estimate_token_cost_usd(
            usage, WONDER_USD_PER_MTOK
        ),
    }


def _money(value: Any) -> str:
    try:
        return f"${value:,.0f}"
    except (TypeError, ValueError):
        return "-"


def render_ic_memo(digest: dict[str, Any]) -> str:
    """Render the digest as an IC memo markdown document."""
    target = digest.get("target", {})
    overall = digest.get("overall", {})
    lines = [
        f"# IC Memo: {target.get('name', '?')} ({target.get('domain', '?')})",
        "",
        f"Rating: {overall.get('rating', '?')} "
        f"(score {overall.get('score', '?')}) | "
        f"Confidence: {overall.get('confidence', '?')} | "
        f"Deal signal: {overall.get('deal_signal', '?')}",
        f"Caps applied: {', '.join(overall.get('rating_caps_applied', [])) or '-'}",
        "",
        "## Executive summary",
        "",
        digest.get("narrative", {}).get("executive_summary", "-"),
        "",
        "## Findings",
        "",
        "| ID | Severity | Title | Cost |",
        "|---|---|---|---|",
    ]
    for finding in digest.get("findings", []):
        remediation = finding.get("remediation", {})
        lines.append(
            f"| {finding.get('finding_id')} | {finding.get('severity')} | "
            f"{finding.get('title')} | "
            f"{_money(remediation.get('cost_low_usd'))} - "
            f"{_money(remediation.get('cost_high_usd'))} |"
        )
    lines.extend(["", "## Contradictions", ""])
    contradictions = digest.get("contradictions", [])
    if not contradictions:
        lines.append("-")
    for item in contradictions:
        claim = item.get("claim", {})
        lines.append(
            f"- {item.get('contradiction_id')} "
            f"[{item.get('verdict')}/{item.get('severity')}] "
            f"refs={', '.join(item.get('evidence_refs', [])) or '-'}: "
            f"{claim.get('text')}"
        )
        lines.append(f"  {item.get('explanation', '')}")
    lines.extend(["", "## 100-day plan", ""])
    plan_items = [
        item
        for item in digest.get("remediation_plan", {}).get("items", [])
        if item.get("window") in _PLAN_WINDOWS
    ]
    if not plan_items:
        lines.append("-")
    else:
        lines.append("| Window | Action | Owner | Cost |")
        lines.append("|---|---|---|---|")
        for item in plan_items:
            lines.append(
                f"| {_WINDOW_LABELS.get(item.get('window'), item.get('window'))} | "
                f"{item.get('action')} | {item.get('owner_role')} | "
                f"{_money(item.get('cost_low_usd'))} - "
                f"{_money(item.get('cost_high_usd'))} |"
            )
    lines.extend(["", "## Deal recommendations", ""])
    recs = digest.get("deal_recommendations", [])
    if not recs:
        lines.append("-")
    for rec in recs:
        lines.append(
            f"- [{rec.get('type')}] {rec.get('text')} "
            f"(basis: {', '.join(rec.get('basis_ids', []))})"
        )
    lines.extend(["", "## Limitations", ""])
    limitations = digest.get("limitations", [])
    if not limitations:
        lines.append("-")
    for entry in limitations:
        lines.append(f"- {entry}")
    lines.append("")
    return "\n".join(lines)
