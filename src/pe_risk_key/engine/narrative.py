"""Narrative engine (SPEC §4.6): IC memo summary, questions, deal recs.

One Muse Wonder call drafts the investment-committee narrative from the
scored digest; code then validates citations, grounding, and references,
regenerating once on failure.
"""

from __future__ import annotations

import json
import re
from typing import Any

from pe_risk_key.engine.scoring import SEVERITY_RANK
from pe_risk_key.providers import (
    WONDER_USD_PER_MTOK,
    Mode,
    ModelClient,
    estimate_token_cost_usd,
)
from pe_risk_key.schemas import deal_recommendation_type_enum

SYSTEM_PROMPT = """You write the investment-committee narrative for a cyber-risk digest. Rules:
1. executive_summary (max 1200 characters) has four labeled paragraphs: "Bottom line:" the decision in one sentence, then the rating and why, with the caps in plain words; "Key risks:" the top 3-4; "Management credibility:" the contradiction pattern, with counts taken from the input; "Next steps:" what to do next.
2. Every sentence that asserts a risk must cite at least one finding or contradiction id in square brackets, e.g. [F-001] [C-002].
3. Never state numbers (costs, counts, dates, scores) that aren't in the input; use the scored values exactly as given, in the input's money style.
4. Deal recommendations: write exactly one recommendation per required type, following its guidance. Recommendations must reference the remediation windows and the deal signal.
5. key_questions_for_management: 5 to 8 questions, each tied to specific findings or contradictions via bracket citations. Use neutral diligence phrasing ("Provide...", "Reconcile...", "Confirm..."), never "Why did...".
6. Write plain IC prose: no enum strings, cap ids, control codes, or evidence locators. Cite [F-xxx]/[C-xxx] instead."""

MAX_SUMMARY_CHARS = 1200

RISK_KEYWORDS = (
    "exception",
    "contradict",
    "breach",
    "kev",
    "not enforced",
    "gap",
    "exposure",
)

SUMMARY_SECTIONS = (
    "bottom line:",
    "key risks:",
    "management credibility:",
    "next steps:",
)

DEAL_SIGNAL_LABELS = {
    "escalate_full_diligence": "Escalate: full cyber diligence required before signing",
    "reprice_or_restructure": "Reprice or restructure",
    "proceed_with_conditions": "Proceed with conditions",
    "proceed": "Proceed",
}

CAP_LABELS = {
    "CAP-CRIT": "a critical, potentially exploitable exposure",
    "CAP-INCIDENT": "a publicly disclosed incident within 24 months",
    "CAP-CONTRADICTION": "multiple management statements contradicted by evidence",
    "CAP-SOC2-QUAL": "a qualified SOC 2 opinion",
}

WINDOW_LABELS = {
    "days_0_30": "Days 0–30",
    "days_31_60": "Days 31–60",
    "days_61_100": "Days 61–100",
    "post_100": "After day 100",
}

FUNCTION_NAMES = {
    "GV": "Govern",
    "ID": "Identify",
    "PR": "Protect",
    "DE": "Detect",
    "RS": "Respond",
    "RC": "Recover",
}

CLAIM_TYPE_LABELS = {
    "control_exists": "control exists",
    "control_coverage": "control coverage",
    "incident_history": "incident history",
    "third_party_assurance": "third-party assurance",
    "process_maturity": "process maturity",
}

DEAL_TYPE_LABELS = {
    "closing_condition": "Closing condition",
    "specific_indemnity": "Specific indemnity",
    "escrow_or_holdback": "Escrow / holdback",
    "price_adjustment": "Price adjustment",
    "rw_insurance_note": "R&W insurance note",
    "cyber_insurance": "Cyber insurance",
    "post_close_covenant": "Post-close covenant",
    "full_diligence_scope": "Full diligence scope",
}

_CITE_RE = re.compile(r"\[(F|C)-(\d{3})\]")
_NUMBER_RE = re.compile(r"\d[\d,]*(?:\.\d+)?")
_CAP_ID_RE = re.compile(r"\bCAP-[A-Z0-9-]+\b")
_SNAKE_RE = re.compile(r"\b[A-Za-z0-9]+_[A-Za-z0-9_]+\b")
_FUNCTION_CODE_RE = re.compile(
    r"\b(GV|PR|DE|RS|RC)\b|\b(GV|ID|PR|DE|RS|RC)\.[A-Z]{2,3}\b"
)
_WHY_DID_RE = re.compile(r"\bwhy did\b", re.IGNORECASE)
_FUNCTION_WORD_RE = re.compile(r"\b(GV|ID|PR|DE|RS|RC)\b")

_WINDOW_ORDER = {
    window: index
    for index, window in enumerate(
        ("days_0_30", "days_31_60", "days_61_100", "post_100")
    )
}
_VERDICT_ORDER = {"contradicted": 0, "unsupported": 1, "supported": 2}


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


def _format_money(value: Any) -> str:
    """Triage cost as $142K (nearest thousand) or $800."""
    try:
        amount = float(value)
    except (TypeError, ValueError):
        return "-"
    if amount >= 1000:
        return f"${amount / 1000:.0f}K"
    return f"${amount:.0f}"


def _format_range(low: Any, high: Any) -> str:
    return f"{_format_money(low)}–{_format_money(high)}"


def _label_text(text: Any) -> Any:
    """Replace bare CSF function codes with full names in prose."""
    if not isinstance(text, str):
        return text
    return _FUNCTION_WORD_RE.sub(
        lambda match: FUNCTION_NAMES[match.group(0)], text
    )


def _label_payload(payload: dict[str, Any]) -> dict[str, Any]:
    """Model input with display labels instead of enums and cap ids.

    Severities, confidences, verdicts, and opinions stay as plain words;
    rule ids, control categories, and locators are dropped so the model
    cannot echo them. Counts and window names are included so grounded
    numbers validate.
    """
    overall = payload.get("overall", {})
    findings = []
    for finding in payload.get("findings", []):
        remediation = finding.get("remediation", {})
        findings.append(
            {
                "finding_id": finding.get("finding_id"),
                "title": finding.get("title"),
                "severity": finding.get("severity"),
                "confidence": finding.get("confidence"),
                "function": FUNCTION_NAMES.get(
                    finding.get("csf_function"), finding.get("csf_function")
                ),
                "deal_impact": finding.get("deal_impact"),
                "evidence": [
                    {"excerpt": item.get("excerpt")}
                    for item in finding.get("evidence", [])
                ],
                "remediation": {
                    "summary": remediation.get("summary"),
                    "cost": _format_range(
                        remediation.get("cost_low_usd"),
                        remediation.get("cost_high_usd"),
                    ),
                    "effort_weeks": remediation.get("effort_weeks"),
                },
            }
        )
    contradictions = []
    for item in payload.get("contradictions", []):
        claim = item.get("claim", {})
        contradictions.append(
            {
                "contradiction_id": item.get("contradiction_id"),
                "claim": {
                    "speaker": claim.get("speaker"),
                    "timestamp": claim.get("timestamp"),
                    "text": claim.get("text"),
                    "claim_type": CLAIM_TYPE_LABELS.get(
                        claim.get("claim_type"), claim.get("claim_type")
                    ),
                },
                "verdict": item.get("verdict"),
                "severity": item.get("severity"),
                "evidence_refs": item.get("evidence_refs", []),
                "explanation": item.get("explanation"),
            }
        )
    plan = payload.get("remediation_plan", {})
    verdicts = [item.get("verdict") for item in contradictions]
    return {
        "target": payload.get("target", {}),
        "overall": {
            "score": overall.get("score"),
            "rating": overall.get("rating"),
            "confidence": overall.get("confidence"),
            "decision": DEAL_SIGNAL_LABELS.get(
                overall.get("deal_signal"), overall.get("deal_signal")
            ),
            "caps": [
                CAP_LABELS.get(cap_id, cap_id)
                for cap_id in overall.get("rating_caps_applied", [])
            ],
        },
        "function_scores": [
            {
                "function": FUNCTION_NAMES.get(
                    entry.get("function"), entry.get("function")
                ),
                "score": entry.get("score"),
                "assessed": entry.get("assessed"),
                "finding_count": entry.get("finding_count"),
            }
            for entry in payload.get("function_scores", [])
        ],
        "findings": findings,
        "contradictions": contradictions,
        "remediation_plan": {
            "total": _format_range(
                plan.get("total_cost_low_usd"), plan.get("total_cost_high_usd")
            ),
            "items": [
                {
                    "action": item.get("action"),
                    "finding_ids": item.get("finding_ids", []),
                    "window": WINDOW_LABELS.get(
                        item.get("window"), item.get("window")
                    ),
                    "cost": _format_range(
                        item.get("cost_low_usd"), item.get("cost_high_usd")
                    ),
                    "owner": item.get("owner_role"),
                }
                for item in plan.get("items", [])
            ],
        },
        "windows": list(WINDOW_LABELS.values()),
        "totals": {
            "findings": len(findings),
            "contradictions": len(contradictions),
            "contradicted": sum(
                1 for verdict in verdicts if verdict == "contradicted"
            ),
            "unsupported": sum(
                1 for verdict in verdicts if verdict == "unsupported"
            ),
            "supported": sum(
                1 for verdict in verdicts if verdict == "supported"
            ),
        },
        "soc2_summary": payload.get("soc2_summary"),
        "limitations": [
            _label_text(entry) for entry in payload.get("limitations", [])
        ],
        "required_recommendations": payload.get("required_recommendations", {}),
    }


def required_recommendation_types(
    *,
    findings: list[dict[str, Any]],
    caps_applied: list[str],
    remediation_plan: dict[str, Any],
    revenue_midpoint_usd: float,
    soc2_analysis: dict[str, Any] | None,
) -> dict[str, list[str]]:
    """Deterministic deal-recommendation triggers: type -> guidance."""
    required: dict[str, list[str]] = {}

    def add(rec_type: str, guidance: str) -> None:
        guidance_list = required.setdefault(rec_type, [])
        if guidance not in guidance_list:
            guidance_list.append(guidance)

    rules = {finding.get("rule_id") for finding in findings}
    if "KEV-POTENTIAL" in rules:
        add(
            "closing_condition",
            "verification and compromise assessment before signing",
        )
        add("full_diligence_scope", "scope review of KEV-listed exposure")
    if "PUB-INCIDENT-RECENT" in rules:
        add("specific_indemnity", "pre-closing incident losses")
        add(
            "rw_insurance_note",
            "known incident likely excluded from R&W coverage",
        )
    if "CAP-CONTRADICTION" in caps_applied:
        add(
            "full_diligence_scope",
            "independent validation of management representations",
        )
        add("closing_condition", "bring-down of security reps")
    soc2_exceptions = (
        soc2_analysis.get("exceptions", []) if soc2_analysis else []
    )
    if (
        "EMAIL-DMARC-NONE" in rules
        or "SOC2-EXCEPTION-ACCESS" in rules
        or any(
            exception.get("control_id") == "CC6.1"
            for exception in soc2_exceptions
        )
    ):
        add(
            "cyber_insurance",
            "likely underwriting requirement; confirm insurability "
            "before close",
        )
    windows = {
        item.get("window") for item in remediation_plan.get("items", [])
    }
    if soc2_exceptions or windows & {"days_31_60", "days_61_100"}:
        add("post_close_covenant", "complete remediation after close")
    total_high = remediation_plan.get("total_cost_high_usd", 0) or 0
    if total_high > 0.01 * revenue_midpoint_usd:
        add(
            "price_adjustment",
            "cite remediation totals relative to revenue",
        )
    else:
        add(
            "price_adjustment",
            "state no adjustment is warranted; remediation immaterial "
            "relative to revenue, citing totals",
        )
    return required


def _leak_errors(label: str, text: str) -> list[str]:
    """Enum, cap-id, and snake_case leaks in IC prose."""
    leaks = []
    for token in sorted(set(_CAP_ID_RE.findall(text))):
        leaks.append(f"{label} leaks cap id {token}.")
    for token in sorted(set(_SNAKE_RE.findall(text))):
        leaks.append(f"{label} leaks enum string {token}.")
    matches = sorted(
        {match.group(0) for match in _FUNCTION_CODE_RE.finditer(text)}
    )
    for token in matches:
        leaks.append(f"{label} leaks control code {token}.")
    return leaks


def validate_narrative(
    output: Any,
    *,
    finding_ids: set[str],
    contradiction_ids: set[str],
    input_numbers: set[str],
    required_types: set[str] | None = None,
) -> list[str]:
    """Human-readable validation errors; empty means valid."""
    errors: list[str] = []
    if not isinstance(output, dict):
        return ["narrative output is not an object."]
    summary = output.get("executive_summary")
    if not isinstance(summary, str):
        errors.append("executive_summary is not a string.")
        summary = ""
    else:
        if len(summary) > MAX_SUMMARY_CHARS:
            errors.append(
                f"executive_summary is {len(summary)} chars "
                f"(max {MAX_SUMMARY_CHARS})."
            )
        lowered = summary.lower()
        for section in SUMMARY_SECTIONS:
            if section not in lowered:
                errors.append(
                    f"executive_summary is missing {section!r} section."
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
        errors.extend(_leak_errors(label, text))
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
        label = f"question {index + 1}"
        check_text(label, question, require_citation=True)
        if isinstance(question, str) and _WHY_DID_RE.search(question):
            errors.append(
                f"{label} uses 'why did' phrasing; use neutral diligence "
                "phrasing."
            )
    valid_types = set(deal_recommendation_type_enum())
    seen_types: set[str] = set()
    for index, rec in enumerate(recs):
        label = f"deal_recommendations[{index}]"
        if not isinstance(rec, dict):
            errors.append(f"{label} is not an object.")
            continue
        if rec.get("type") not in valid_types:
            errors.append(f"{label} has unknown type {rec.get('type')!r}.")
        else:
            seen_types.add(rec["type"])
        check_text(label, rec.get("text"), require_citation=False)
        basis = rec.get("basis_ids")
        if not isinstance(basis, list) or not basis:
            errors.append(f"{label} has no basis_ids.")
        else:
            for ref in basis:
                if ref in finding_ids or ref in contradiction_ids:
                    continue
                errors.append(f"{label} cites unknown id {ref!r}.")
    for rec_type in sorted((required_types or set()) - seen_types):
        errors.append(f"missing required {rec_type} recommendation.")
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
    contradictions, remediation_plan, soc2_summary, limitations, and
    required_recommendations. The model sees a labeled view (display
    labels instead of enums); numbers validate against that view.
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
    required_types = set(payload.get("required_recommendations", {}) or {})
    labeled = _label_payload(payload)
    input_numbers = _number_tokens(json.dumps(labeled))
    client = ModelClient(role="narrative", mode=mode)
    messages: list[dict[str, Any]] = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": json.dumps(labeled, indent=2)},
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
        required_types=required_types,
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
            required_types=required_types,
        )
    valid = not errors
    summary = output.get("executive_summary", "")
    questions = output.get("key_questions_for_management", [])
    valid_types = set(deal_recommendation_type_enum())
    merged_recs: dict[str, dict[str, Any]] = {}
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
        text = (
            rec.get("text", "")
            if isinstance(rec.get("text"), str)
            else ""
        )
        if rec["type"] in merged_recs:
            existing = merged_recs[rec["type"]]
            existing["basis_ids"] = list(
                dict.fromkeys([*existing["basis_ids"], *basis])
            )
            existing["text"] = f"{existing['text']} {text}".strip()
        else:
            merged_recs[rec["type"]] = {
                "type": rec["type"],
                "text": text,
                "basis_ids": basis,
            }
    recs = list(merged_recs.values())
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


def _score_text(value: Any) -> str:
    try:
        return f"{float(value):.1f}"
    except (TypeError, ValueError):
        return "?"


def _title_case(value: Any) -> str:
    return str(value).capitalize() if value else "?"


def _ref_excerpt(
    ref: str,
    finding_by_id: dict[str, dict],
    pool_by_id: dict[str, dict],
    limit: int = 160,
) -> str:
    """One-line evidence text for a contradiction ref."""
    if ref in finding_by_id:
        return f"{ref}: {finding_by_id[ref].get('title', '')}"[:limit]
    excerpt = pool_by_id.get(ref, {}).get("excerpt")
    if excerpt:
        return f"{ref}: {excerpt}"[:limit]
    for finding in finding_by_id.values():
        for item in finding.get("evidence", []):
            if item.get("evidence_id") == ref:
                return f"{ref}: {item.get('excerpt', '')}"[:limit]
    return ref


def render_ic_memo(
    digest: dict[str, Any],
    evidence_pool: list[dict[str, Any]] | None = None,
    run_cost_usd: float | None = None,
) -> str:
    """Render the digest as an IC memo markdown document."""
    target = digest.get("target", {})
    overall = digest.get("overall", {})
    inputs = digest.get("inputs", {})
    findings = digest.get("findings", [])
    finding_by_id = {
        finding.get("finding_id"): finding for finding in findings
    }
    pool_by_id = {
        item.get("evidence_id"): item for item in (evidence_pool or [])
    }
    generated = str(digest.get("generated_at", ""))[:10] or "?"
    caps = [
        CAP_LABELS.get(cap_id, cap_id)
        for cap_id in overall.get("rating_caps_applied", [])
    ]
    basis_parts = []
    if inputs.get("domain_scan"):
        basis_parts.append("outside-in scan")
    if inputs.get("documents"):
        basis_parts.append("SOC 2 report")
    if inputs.get("interviews"):
        basis_parts.append("management interview")
    lines = [
        f"# IC Memo: {target.get('name', '?')} ({target.get('domain', '?')})",
        "",
        f"Date: {generated} | Digest: {digest.get('digest_id', '?')}",
        f"Rating: {overall.get('rating', '?')} | "
        f"Decision: {DEAL_SIGNAL_LABELS.get(overall.get('deal_signal'), overall.get('deal_signal', '?'))}",
        "",
        "## Executive summary",
        "",
        digest.get("narrative", {}).get("executive_summary", "-"),
        "",
        "## Why the rating",
        "",
        f"Score {_score_text(overall.get('score'))} reflects "
        f"{'; '.join(caps) if caps else 'no capped findings'}.",
        f"Confidence {overall.get('confidence', '?')}, based on "
        f"{', '.join(basis_parts) if basis_parts else 'limited inputs'}.",
        "",
        "## Function scores",
        "",
        "| Function | Score | Findings |",
        "|---|---|---|",
    ]
    for entry in digest.get("function_scores", []):
        score = (
            _score_text(entry.get("score"))
            if entry.get("assessed")
            else "Not assessed"
        )
        lines.append(
            f"| {FUNCTION_NAMES.get(entry.get('function'), entry.get('function'))} | "
            f"{score} | {entry.get('finding_count', 0)} |"
        )
    lines.extend(["", "## Key risks", ""])
    top = sorted(
        findings,
        key=lambda f: SEVERITY_RANK.get(f.get("severity"), -1),
        reverse=True,
    )[:5]
    if not top:
        lines.append("-")
    for finding in top:
        remediation = finding.get("remediation", {})
        lines.append(
            f"- [{_title_case(finding.get('severity'))}] "
            f"{finding.get('title')} ({finding.get('finding_id')}, "
            f"{_format_range(remediation.get('cost_low_usd'), remediation.get('cost_high_usd'))})"
        )
    lines.extend(["", "## Management claims vs. evidence", ""])
    contradictions = sorted(
        digest.get("contradictions", []),
        key=lambda c: _VERDICT_ORDER.get(c.get("verdict"), 9),
    )
    if not contradictions:
        lines.append("-")
    for item in contradictions:
        claim = item.get("claim", {})
        lines.append(
            f"- [{_title_case(item.get('verdict'))}/"
            f"{_title_case(item.get('severity'))}] "
            f"{item.get('contradiction_id')}: {claim.get('text')}"
        )
        refs = [
            _ref_excerpt(ref, finding_by_id, pool_by_id)
            for ref in item.get("evidence_refs", [])
        ]
        lines.append(f"  Evidence: {'; '.join(refs) if refs else '-'}")
    lines.extend(["", "## SOC 2 summary", ""])
    soc2 = digest.get("soc2_analysis")
    if not soc2:
        lines.append("No SOC 2 report provided.")
    else:
        lines.append(
            f"Opinion {_title_case(soc2.get('opinion'))}; period "
            f"{soc2.get('period_start')} to {soc2.get('period_end')}; "
            f"auditor {soc2.get('auditor')}."
        )
        lines.append("Exceptions:")
        exceptions = soc2.get("exceptions", [])
        if not exceptions:
            lines.append("- None")
        for exception in exceptions:
            deviations = exception.get("deviations")
            sample = exception.get("sample_size")
            if deviations is None or sample is None:
                counts = "counts not stated"
            else:
                counts = f"{deviations}/{sample} deviations"
            lines.append(f"- {exception.get('control_id')}: {counts}")
        carve_outs = [
            org.get("name")
            for org in soc2.get("subservice_orgs", [])
            if org.get("method") == "carve_out"
        ]
        lines.append(f"Carve-outs: {', '.join(carve_outs) if carve_outs else 'none'}.")
        lines.append(f"Bridge gap: {soc2.get('bridge_gap_days', '?')} days.")
    lines.extend(["", "## 100-day plan", ""])
    plan = digest.get("remediation_plan", {})
    plan_items = sorted(
        plan.get("items", []),
        key=lambda i: _WINDOW_ORDER.get(i.get("window"), 99),
    )
    if not plan_items:
        lines.append("-")
    else:
        lines.append("| Window | Action | Owner | Cost |")
        lines.append("|---|---|---|---|")
        for item in plan_items:
            lines.append(
                f"| {WINDOW_LABELS.get(item.get('window'), item.get('window'))} | "
                f"{item.get('action')} | {item.get('owner_role')} | "
                f"{_format_range(item.get('cost_low_usd'), item.get('cost_high_usd'))} |"
            )
        lines.append(
            f"| Total | | | {_format_range(plan.get('total_cost_low_usd'), plan.get('total_cost_high_usd'))} |"
        )
    lines.extend(["", "## Deal recommendations", ""])
    recs = digest.get("deal_recommendations", [])
    if not recs:
        lines.append("-")
    else:
        by_type: dict[str, list[dict]] = {}
        for rec in recs:
            by_type.setdefault(rec.get("type"), []).append(rec)
        for rec_type, group in by_type.items():
            lines.append(
                f"### {DEAL_TYPE_LABELS.get(rec_type, rec_type)}"
            )
            for rec in group:
                lines.append(
                    f"- {rec.get('text')} "
                    f"(basis: {', '.join(rec.get('basis_ids', []))})"
                )
    lines.extend(["", "## Questions for management", ""])
    questions = digest.get("narrative", {}).get(
        "key_questions_for_management", []
    )
    if not questions:
        lines.append("-")
    for index, question in enumerate(questions, 1):
        lines.append(f"{index}. {question}")
    lines.extend(["", "## Limitations", ""])
    limitations = list(digest.get("limitations", []))
    if "Remediation costs are triage estimates" not in limitations:
        limitations.append("Remediation costs are triage estimates")
    for entry in limitations:
        lines.append(f"- {entry}")
    lines.extend(["", "---", ""])
    sources = []
    if inputs.get("domain_scan"):
        sources.append(f"outside-in scan of {target.get('domain', '?')}")
    for doc in inputs.get("documents", []):
        sources.append(
            f"{doc.get('filename')} (sha256 {str(doc.get('sha256', ''))[:12]})"
        )
    for interview in inputs.get("interviews", []):
        sources.append(
            f"{interview.get('filename')} (sha256 {str(interview.get('sha256', ''))[:12]})"
        )
    lines.append(f"Inputs: {'; '.join(sources) if sources else '-'}")
    providers = [
        f"{entry.get('role')}: {entry.get('model')} "
        f"({entry.get('provider')})"
        for entry in digest.get("mode", {}).get("providers", [])
    ]
    lines.append(f"Models: {'; '.join(providers) if providers else '-'}")
    lines.append(
        f"Run cost: ${run_cost_usd:.4f}"
        if isinstance(run_cost_usd, (int, float))
        else "Run cost: n/a"
    )
    lines.append("Generated by PE Risk Key")
    lines.append("")
    return "\n".join(lines)
