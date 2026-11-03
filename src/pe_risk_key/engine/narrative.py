# SPDX-License-Identifier: AGPL-3.0-or-later
"""Narrative engine (SPEC §4.6): IC memo summary, questions, deal recs.

One Muse Wonder call drafts the investment-committee narrative from the
scored digest; code then validates citations, grounding, and references,
regenerating once on failure.
"""

from __future__ import annotations

import copy
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

SYSTEM_PROMPT = """You write the investment-committee narrative for a cyber-risk digest. Rules:
1. Write four summary fields as plain prose: bottom_line (max 300 chars: the decision in one sentence, then the rating and why, with the caps in plain words); key_risks (max 400 chars: the top 3-4); management_credibility (max 250 chars: at most one sentence interpreting the claim verdicts, whose counts are computed separately; empty string when no interview was provided); next_steps (max 300 chars: what to do next).
2. Never write [F-xxx]/[C-xxx] ids in prose. Instead choose basis_ids for each field and question from the available_ids in the input; citations are rendered from those.
3. Never state numbers (costs, counts, dates, scores) that aren't in the input; use the scored values exactly as given, in the input's money style.
4. recommendation_slots lists one slot per required recommendation, each with an index, type, guidance, and basis. Return exactly one text per slot, in slot order: text only, referencing the remediation windows. The overall decision is shown separately and must not be restated in any recommendation; give each recommendation a distinct opening, and never start one with its own type name.
5. key_questions_for_management: 5 to 8 questions (each with basis_ids), using neutral diligence phrasing ("Provide...", "Reconcile...", "Confirm..."), never "Why did...".
6. Write plain IC prose: no enum strings, cap ids, control codes, or evidence locators."""

SHORT_EVIDENCE_FINDINGS = 3
SHORT_QUESTION_RANGE = (3, 4)
FULL_QUESTION_RANGE = (5, 8)
NO_INTERVIEW_CREDIBILITY = "Not assessed: no management interview provided."
NO_CLAIMS_CREDIBILITY = "No management claims were assessed."

# Model-written summary fields: (key, digest label, max chars). Code
# assembles them into executive_summary; each field is trimmed at a
# sentence boundary, never removed.
SUMMARY_FIELDS: tuple[tuple[str, str, int], ...] = (
    ("bottom_line", "Bottom line:", 300),
    ("key_risks", "Key risks:", 400),
    ("management_credibility", "Management credibility:", 250),
    ("next_steps", "Next steps:", 300),
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
    "CAP-LOW-COVERAGE": "limited evidence: outside-in signals only",
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
_OVER_PRECISE_RE = re.compile(r"\d+\.\d{2,}")
_CAP_ID_RE = re.compile(r"\bCAP-[A-Z0-9-]+\b")
_SNAKE_RE = re.compile(r"\b[A-Za-z0-9]+_[A-Za-z0-9_]+\b")
_SPECULATION_RE = re.compile(r"\b(if present|may contain)\b", re.IGNORECASE)
_SOC_TWO_RE = re.compile(r"soc 2", re.IGNORECASE)
_DECISION_CUT_RE = re.compile(r",|;|\b(?:and|or)\b", re.IGNORECASE)
_DECISION_AFTER_CONJ_RE = re.compile(
    r"\s*(?:and|or)\b\s*(.*)$", re.IGNORECASE | re.DOTALL
)
_DECISION_CITATION_ONLY_RE = re.compile(
    r"^(?:\s*\[[FC]-\d{3}\]\s*)*[.?!]?\s*$"
)
_DECISION_BEFORE_RE = re.compile(
    r"(?:^|[,\-–—:;(/]|\b(?:and|or)\b)\s*$", re.IGNORECASE
)
_DECISION_DANGLING_PREP_RE = re.compile(
    r"\s+(?:about|after|against|as|at|before|between|by|during|for|"
    r"from|in|into|of|on|through|to|under|with|within|without)$",
    re.IGNORECASE,
)
_DECISION_AFTER_CITE_RE = re.compile(r"^(?:\s*\[[FC]-\d{3}\])*\s*")
_SIGNAL_RESTATED_LE_RE = re.compile(
    r"\b(consistent with|in line with|supporting|aligned with|"
    r"reflecting|in keeping with|under|per)\b"
)
_DEAL_KEYWORD_STOPWORDS = frozenset({"with"})
_REPAIR_TOKEN_LABELS = {
    **DEAL_SIGNAL_LABELS,
    **WINDOW_LABELS,
    **DEAL_TYPE_LABELS,
    **CLAIM_TYPE_LABELS,
}
_MECHANICAL_ERROR_MARKERS = (
    "with 2+ decimals",
    "leaks ",
)
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
    """Strict-ready schema for the IC narrative output.

    Code owns structure, citations, and recommendation slots: the
    model writes field prose plus basis ids, interpretation, and one
    recommendation text per slot, by index.
    """
    field = {
        "type": "object",
        "additionalProperties": False,
        "required": ["text", "basis_ids"],
        "properties": {
            "text": {"type": "string"},
            "basis_ids": {
                "type": "array",
                "items": {"type": "string"},
            },
        },
    }
    return {
        "type": "object",
        "additionalProperties": False,
        "required": [
            "bottom_line",
            "key_risks",
            "management_credibility",
            "next_steps",
            "key_questions_for_management",
            "deal_recommendations",
        ],
        "properties": {
            "bottom_line": field,
            "key_risks": field,
            "management_credibility": {
                "type": "object",
                "additionalProperties": False,
                "required": ["text"],
                "properties": {"text": {"type": "string"}},
            },
            "next_steps": field,
            "key_questions_for_management": {
                "type": "array",
                "items": field,
            },
            "deal_recommendations": {
                "type": "array",
                "items": {
                    "type": "object",
                    "additionalProperties": False,
                    "required": ["text"],
                    "properties": {"text": {"type": "string"}},
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


def _shared_prefix_words(first: str, second: str) -> int:
    """Leading word run shared by two texts (lowercased, unpunctuated)."""
    table = str.maketrans("", "", ".,;:!?()\"'")

    def words(text: str) -> list[str]:
        return [
            word.translate(table).lower()
            for word in text.split()
            if word.translate(table)
        ]

    count = 0
    for left, right in zip(words(first), words(second)):
        if left != right:
            break
        count += 1
    return count


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


def _decimal_text(value: Any) -> Any:
    """Scores as one-decimal strings; anything else passes through."""
    try:
        return f"{float(value):.1f}"
    except (TypeError, ValueError):
        return value


def _label_payload(
    payload: dict[str, Any], slots: list[dict[str, Any]]
) -> dict[str, Any]:
    """Model input with display labels instead of enums and cap ids.

    Severities, confidences, verdicts, and opinions stay as plain words;
    rule ids, control categories, and locators are dropped so the model
    cannot echo them. Counts and window names are included so grounded
    numbers validate. Recommendation slots carry plain type labels.
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
            "score": _decimal_text(overall.get("score")),
            "rating": overall.get("rating"),
            "confidence": overall.get("confidence"),
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
                "score": _decimal_text(entry.get("score")),
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
        "has_interview": payload.get("has_interview", True),
        "has_soc2": payload.get("soc2_summary", True) is not None,
        "available_ids": sorted(
            [
                finding.get("finding_id")
                for finding in payload.get("findings", [])
                if isinstance(finding.get("finding_id"), str)
            ]
            + [
                item.get("contradiction_id")
                for item in payload.get("contradictions", [])
                if isinstance(item.get("contradiction_id"), str)
            ]
        ),
        "recommendation_slots": [
            {
                "index": index,
                "type": DEAL_TYPE_LABELS.get(
                    slot["type"], slot["type"]
                ),
                "guidance": slot["guidance"],
                "basis_ids": slot["basis_ids"],
            }
            for index, slot in enumerate(slots)
        ],
    }


def required_recommendation_types(
    *,
    findings: list[dict[str, Any]],
    caps_applied: list[str],
    remediation_plan: dict[str, Any],
    revenue_midpoint_usd: float,
    soc2_analysis: dict[str, Any] | None,
) -> dict[str, dict[str, list[str]]]:
    """Deterministic deal-recommendation triggers.

    Returns type -> {"guidance": [...], "trigger_findings": [...]} where
    trigger_findings are the finding ids whose rules fired the trigger.
    Cap- and totals-driven triggers carry no finding ids.
    """
    required: dict[str, dict[str, list[str]]] = {}

    def add(
        rec_type: str, guidance: str, trigger_ids: list[str] | None = None
    ) -> None:
        entry = required.setdefault(
            rec_type, {"guidance": [], "trigger_findings": []}
        )
        if guidance not in entry["guidance"]:
            entry["guidance"].append(guidance)
        for finding_id in trigger_ids or []:
            if finding_id not in entry["trigger_findings"]:
                entry["trigger_findings"].append(finding_id)

    def with_rule(*rule_ids: str) -> list[str]:
        return [
            finding["finding_id"]
            for finding in findings
            if finding.get("rule_id") in rule_ids
            and isinstance(finding.get("finding_id"), str)
        ]

    kev_ids = with_rule("KEV-POTENTIAL")
    if kev_ids:
        add(
            "closing_condition",
            "verification and compromise assessment before signing",
            kev_ids,
        )
        add(
            "full_diligence_scope",
            "scope review of KEV-listed exposure",
            kev_ids,
        )
    incident_ids = with_rule("PUB-INCIDENT-RECENT")
    if incident_ids:
        add("specific_indemnity", "pre-closing incident losses", incident_ids)
        add(
            "rw_insurance_note",
            "known incident likely excluded from R&W coverage",
            incident_ids,
        )
    if "CAP-CONTRADICTION" in caps_applied:
        add(
            "full_diligence_scope",
            "independent validation of management representations",
        )
        add("closing_condition", "bring-down of security reps")
    if "CAP-LOW-COVERAGE" in caps_applied:
        add(
            "closing_condition",
            "obtain the current SOC 2 Type II report and a management "
            "security interview before relying on this rating",
        )
    soc2_exceptions = (
        soc2_analysis.get("exceptions", []) if soc2_analysis else []
    )
    access_ids = with_rule("EMAIL-DMARC-NONE", "SOC2-EXCEPTION-ACCESS")
    has_cc61 = any(
        exception.get("control_id") == "CC6.1" for exception in soc2_exceptions
    )
    if access_ids or has_cc61:
        add(
            "cyber_insurance",
            "likely underwriting requirement; confirm insurability "
            "before close",
            access_ids,
        )
    plan_items = remediation_plan.get("items", [])
    late_ids = [
        finding_id
        for item in plan_items
        if item.get("window") in ("days_31_60", "days_61_100")
        for finding_id in (item.get("finding_ids") or [])
        if isinstance(finding_id, str)
    ]
    soc2_ids = [
        finding["finding_id"]
        for finding in findings
        if str(finding.get("rule_id", "")).startswith("SOC2-EXCEPTION")
        and isinstance(finding.get("finding_id"), str)
    ]
    if soc2_exceptions or late_ids:
        add(
            "post_close_covenant",
            "complete remediation after close",
            soc2_ids + [i for i in late_ids if i not in soc2_ids],
        )
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


def _render_prose(text: str, basis_ids: list[str], terminal: str) -> str:
    """Prose plus trailing [F-xxx]/[C-xxx] chips and terminal punctuation."""
    stripped = re.sub(r"[.!?]+$", "", (text or "").strip()).rstrip()
    if basis_ids:
        chips = " ".join(f"[{ref}]" for ref in basis_ids)
        stripped = f"{stripped} {chips}" if stripped else chips
    if terminal and stripped and not stripped.endswith(terminal):
        stripped += terminal
    return stripped


def _credibility_counts(contradictions: list[dict[str, Any]]) -> str:
    """Code-computed claim-verdict counts sentence."""
    if not contradictions:
        return NO_CLAIMS_CREDIBILITY
    verdicts = [item.get("verdict") for item in contradictions]
    contradicted = sum(1 for verdict in verdicts if verdict == "contradicted")
    unsupported = sum(1 for verdict in verdicts if verdict == "unsupported")
    supported = sum(1 for verdict in verdicts if verdict == "supported")
    return (
        f"Of {len(contradictions)} claims assessed, {contradicted} were "
        f"contradicted, {unsupported} unsupported, {supported} supported."
    )


def recommendation_slots(
    required_map: dict[str, Any], finding_ids: list[str]
) -> list[dict[str, Any]]:
    """Deterministic recommendation slots: type plus code-owned basis.

    Trigger recommendations cite their triggering findings; slots
    without triggers (coverage-cap conditions, price adjustments) cite
    every finding. Order follows the trigger table.
    """
    slots = []
    for rec_type, entry in (required_map or {}).items():
        trigger_ids = (
            entry.get("trigger_findings", [])
            if isinstance(entry, dict)
            else []
        )
        basis = list(trigger_ids) if trigger_ids else list(finding_ids)
        guidance = (
            entry.get("guidance", [])
            if isinstance(entry, dict)
            else []
        )
        slots.append(
            {"type": rec_type, "basis_ids": basis, "guidance": guidance}
        )
    return slots


def assemble_narrative(
    output: dict[str, Any],
    *,
    slots: list[dict[str, Any]],
    contradictions: list[dict[str, Any]],
    has_interview: bool,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Assemble digest narrative + recs from repaired model output.

    Labels, credibility counts, and trailing chips are code-rendered.
    Recommendation slots with blank text are dropped.
    """
    fields = {}
    for key, label, _ in SUMMARY_FIELDS:
        entry = output.get(key) or {}
        fields[key] = (
            entry.get("text", "") if isinstance(entry, dict) else "",
            entry.get("basis_ids", []) if isinstance(entry, dict) else [],
        )
    if has_interview:
        counts = _credibility_counts(contradictions)
        interpretation = fields["management_credibility"][0].strip()
        credibility = (
            f"{counts} {interpretation}" if interpretation else counts
        )
        credibility_basis = [
            item.get("contradiction_id")
            for item in contradictions
            if item.get("verdict") == "contradicted"
            and isinstance(item.get("contradiction_id"), str)
        ]
    else:
        credibility = NO_INTERVIEW_CREDIBILITY
        credibility_basis = []
    summary = " ".join(
        f"{label} "
        + (
            _render_prose(credibility, credibility_basis, ".")
            if key == "management_credibility"
            else _render_prose(text, basis, ".")
        )
        for key, label, _ in SUMMARY_FIELDS
        for text, basis in [fields[key]]
    )
    questions = []
    for question in output.get("key_questions_for_management", []) or []:
        if not isinstance(question, dict):
            continue
        questions.append(
            _render_prose(
                question.get("text", ""),
                question.get("basis_ids", []) or [],
                "?",
            )
        )
    texts = output.get("deal_recommendations", []) or []
    recs = []
    for index, slot in enumerate(slots):
        text = (
            texts[index].get("text", "")
            if index < len(texts) and isinstance(texts[index], dict)
            else ""
        )
        if not isinstance(text, str) or not text.strip():
            continue
        recs.append(
            {
                "type": slot["type"],
                "text": _render_prose(text, slot["basis_ids"], "."),
                "basis_ids": list(slot["basis_ids"]),
            }
        )
    return (
        {
            "executive_summary": summary,
            "key_questions_for_management": questions,
        },
        recs,
    )


def validate_narrative(
    output: Any,
    *,
    finding_ids: set[str],
    contradiction_ids: set[str],
    input_numbers: set[str],
    slot_types: list[str],
    has_soc2: bool = True,
    finding_count: int | None = None,
    deal_label: str = "",
) -> list[str]:
    """Human-readable validation errors; empty means valid.

    Code owns structure, citations, and recommendation slots, so only
    model-chosen content is checked: unknown basis ids, ungrounded
    numbers, enum/decision-label leaks, speculation, and rec shape.
    """
    errors: list[str] = []
    if not isinstance(output, dict):
        return ["narrative output is not an object."]
    deal_keywords = [
        re.compile(r"\b" + re.escape(word) + r"\b")
        for word in _deal_keywords(deal_label)
    ]
    count = len(finding_ids) if finding_count is None else finding_count
    short = count <= SHORT_EVIDENCE_FINDINGS
    prose_texts: list[tuple[str, str]] = []

    def check_basis(label: str, basis: Any) -> None:
        if not isinstance(basis, list):
            errors.append(f"{label} basis_ids is not a list.")
            return
        for ref in basis:
            if ref in finding_ids or ref in contradiction_ids:
                continue
            errors.append(f"{label} cites unknown id {ref!r}.")

    def check_prose(label: str, text: Any, required: bool = True) -> str:
        if not isinstance(text, str) or not text.strip():
            if required:
                errors.append(f"{label} text is missing.")
            return ""
        errors.extend(_leak_errors(label, text))
        for phrase in sorted(
            {match.group(0).lower() for match in _SPECULATION_RE.finditer(text)}
        ):
            errors.append(
                f"{label} speculates ({phrase!r}); state what is known "
                "and what to verify."
            )
        if deal_keywords:
            tail = re.split(r"[,;]", text)[-1].strip().lower()
            if _SIGNAL_RESTATED_LE_RE.search(
                tail
            ) and any(expr.search(tail) for expr in deal_keywords):
                errors.append(
                    f"{label} ends by restating the deal signal "
                    f"({tail[:80]!r}); fold it into the substance instead."
                )
        prose_texts.append((label, text))
        return text

    fields: dict[str, str] = {}
    for key, _, _ in SUMMARY_FIELDS:
        entry = output.get(key)
        if not isinstance(entry, dict):
            errors.append(f"{key} is not an object.")
            fields[key] = ""
            continue
        fields[key] = check_prose(
            key, entry.get("text"), required=key != "management_credibility"
        )
        if key != "management_credibility":
            check_basis(key, entry.get("basis_ids"))
    if not has_soc2:
        coverage = fields["key_risks"] + fields["next_steps"]
        if "soc 2" not in coverage.lower():
            errors.append(
                "state in key risks or next steps that no SOC 2 "
                "report was provided."
            )
    questions = output.get("key_questions_for_management")
    question_range = SHORT_QUESTION_RANGE if short else FULL_QUESTION_RANGE
    if not isinstance(questions, list):
        errors.append("key_questions_for_management is not a list.")
        questions = []
    elif not question_range[0] <= len(questions) <= question_range[1]:
        errors.append(
            f"key_questions_for_management has {len(questions)} entries "
            f"(need {question_range[0]}-{question_range[1]})."
        )
    for index, question in enumerate(questions):
        label = f"question {index + 1}"
        if not isinstance(question, dict):
            errors.append(f"{label} is not an object.")
            continue
        text = check_prose(label, question.get("text"))
        check_basis(label, question.get("basis_ids"))
        if text and _WHY_DID_RE.search(text):
            errors.append(
                f"{label} uses 'why did' phrasing; use neutral diligence "
                "phrasing."
            )
    recs = output.get("deal_recommendations")
    if not isinstance(recs, list):
        errors.append("deal_recommendations is not a list.")
        recs = []
    elif len(recs) != len(slot_types):
        errors.append(
            f"deal_recommendations has {len(recs)} texts for "
            f"{len(slot_types)} slots."
        )
    rec_texts: list[tuple[int, str]] = []
    for index, rec in enumerate(recs):
        label = f"deal_recommendations[{index}]"
        if not isinstance(rec, dict):
            errors.append(f"{label} is not an object.")
            continue
        text = check_prose(label, rec.get("text"))
        if index < len(slot_types) and text:
            type_label = DEAL_TYPE_LABELS.get(slot_types[index], "")
            if type_label and text.lstrip().lower().startswith(
                type_label.lower()
            ):
                errors.append(
                    f"{label} starts with its own type label; lead with "
                    "the substance instead."
                )
            rec_texts.append((index, text))
    for left in range(len(rec_texts)):
        for right in range(left + 1, len(rec_texts)):
            shared = _shared_prefix_words(
                rec_texts[left][1], rec_texts[right][1]
            )
            if shared >= 8:
                errors.append(
                    f"deal_recommendations[{rec_texts[left][0]}] and "
                    f"[{rec_texts[right][0]}] share a {shared}-word "
                    "leading clause; give each a distinct opening."
                )
    for label, text in prose_texts:
        quantities = _SOC_TWO_RE.sub("", text)
        for token in sorted(_number_tokens(quantities) - input_numbers):
            errors.append(f"{label} states number {token} not in the input.")
        for token in sorted(set(_OVER_PRECISE_RE.findall(text))):
            errors.append(
                f"{label} states number {token} with 2+ decimals; "
                "use one-decimal scores."
            )
    return errors


def _deal_keywords(deal_label: str) -> set[str]:
    """Distinctive words of the decision label (stopwords dropped)."""
    return {
        word
        for word in re.findall(r"[a-z]+", (deal_label or "").lower())
        if len(word) >= 4
    } - _DEAL_KEYWORD_STOPWORDS


def _decision_phrases(deal_label: str) -> list[str]:
    """The decision label plus its phrasing (text after any colon)."""
    label = (deal_label or "").strip()
    if not label:
        return []
    phrases = [label]
    if ":" in label:
        tail = label.split(":", 1)[1].strip()
        if tail and tail != label:
            phrases.append(tail)
    return phrases


def _bare_decision_mention(before: str, after: str) -> bool:
    """Guard for single-word labels: only a standalone restatement.

    "Proceed" is also a verb ("Proceed on the basis that..."), so it
    counts only at a clause start and only when no word follows it.
    """
    if _DECISION_BEFORE_RE.search(before) is None:
        return False
    rest = _DECISION_AFTER_CITE_RE.sub("", after)
    return rest == "" or not (rest[0].isalnum() or rest[0] == "_")


def _cut_restatement(before: str, after: str) -> str:
    """Remove one decision-phrase occurrence, keeping the sentence whole.

    A phrase joined to following content by and/or is a list item, so
    only the phrase and the conjunction go; otherwise the cut runs back
    to the last clause boundary.
    """
    conj = _DECISION_AFTER_CONJ_RE.match(after)
    if conj and _DECISION_CITATION_ONLY_RE.match(conj.group(1)) is None:
        return before.rstrip() + " " + conj.group(1).lstrip()
    bounds = list(_DECISION_CUT_RE.finditer(before))
    head = (
        before[: bounds[-1].start()].rstrip().rstrip(",;")
        if bounds
        else before.rstrip()
    )
    head = _DECISION_DANGLING_PREP_RE.sub("", head)
    tail = after.strip()
    if not tail:
        return head
    if not head:
        return tail
    return head + " " + tail


def _tidy_text(text: str) -> str:
    """Collapse whitespace and fix punctuation left by removals."""
    text = re.sub(r"\s{2,}", " ", text)
    text = re.sub(r"\s+([.,;:!?)\]])", r"\1", text)
    text = re.sub(r"\(\s*\)", "", text)
    text = re.sub(r",\s*,", ",", text)
    text = re.sub(r"\s{2,}", " ", text.strip().rstrip(",;:")).strip()
    if text and not text.endswith((".", "?", "!")):
        text += "."
    return text


def _strip_decision_restatements(
    text: str, deal_label: str
) -> tuple[str, list[str]]:
    """Remove restated decision labels/phrasing from one rec text."""
    repairs: list[str] = []
    for phrase in _decision_phrases(deal_label):
        single_word = " " not in phrase
        pattern = re.compile(
            r"(?<!\w)" + re.escape(phrase) + r"(?!\w)", re.IGNORECASE
        )
        pos = 0
        while True:
            match = pattern.search(text, pos)
            if match is None:
                break
            before, after = text[: match.start()], text[match.end() :]
            if single_word and not _bare_decision_mention(before, after):
                pos = match.end()
                continue
            text = _cut_restatement(before, after)
            repairs.append(
                f"removed restated decision {match.group(0)!r}"
            )
            pos = 0
    if repairs:
        text = _tidy_text(text)
    return text, repairs


def repair_narrative(
    output: Any,
    *,
    deal_label: str,
) -> tuple[Any, list[str]]:
    """Deterministic fixes for mechanical narrative violations.

    Rounds over-precise scores, replaces enum/snake_case tokens via the
    label maps, strips inline bracket ids (code renders chips),
    removes restated decision labels or phrasing (except bottom_line,
    which must state the decision), trims each summary field at a
    sentence boundary, and dedupes basis arrays. Fields are never
    removed. Returns the fixed output plus the repairs applied.
    """
    fixed = copy.deepcopy(output)
    repairs: list[str] = []
    if not isinstance(fixed, dict):
        return fixed, repairs

    def detokenize(text: Any) -> Any:
        if not isinstance(text, str):
            return text

        def cap(match: re.Match) -> str:
            token = match.group(0)
            if token in CAP_LABELS:
                repairs.append(
                    f"replaced {token} with {CAP_LABELS[token]!r}"
                )
                return CAP_LABELS[token]
            return token

        text = _CAP_ID_RE.sub(cap, text)

        def func(match: re.Match) -> str:
            token = match.group(0)
            base = token.split(".")[0]
            if base in FUNCTION_NAMES:
                repairs.append(
                    f"replaced {token} with {FUNCTION_NAMES[base]!r}"
                )
                return FUNCTION_NAMES[base]
            return token

        text = _FUNCTION_CODE_RE.sub(func, text)

        def snake(match: re.Match) -> str:
            token = match.group(0)
            if token in _REPAIR_TOKEN_LABELS:
                repairs.append(
                    f"replaced {token} with "
                    f"{_REPAIR_TOKEN_LABELS[token]!r}"
                )
                return _REPAIR_TOKEN_LABELS[token]
            return token

        return _SNAKE_RE.sub(snake, text)

    def clean_prose(label: str, text: Any, strip_decision: bool) -> Any:
        if not isinstance(text, str):
            return text
        text = detokenize(text)

        def rounded(match: re.Match) -> str:
            new = f"{float(match.group(0)):.1f}"
            if new != match.group(0):
                repairs.append(f"rounded {match.group(0)} to {new}")
            return new

        text = _OVER_PRECISE_RE.sub(rounded, text)

        def strip_cite(match: re.Match) -> str:
            ref = f"{match.group(1)}-{match.group(2)}"
            repairs.append(f"stripped inline [{ref}] from {label}")
            return ""

        text = _CITE_RE.sub(strip_cite, text)
        text = re.sub(r" {2,}", " ", text).strip()
        if strip_decision:
            text, removed = _strip_decision_restatements(text, deal_label)
            repairs.extend(removed)
        return text

    def trim_field(label: str, text: str, max_chars: int) -> str:
        if len(text) <= max_chars:
            return text
        kept: list[str] = []
        total = 0
        for sentence in _split_sentences(text):
            extra = len(sentence) + (1 if kept else 0)
            if total + extra > max_chars:
                break
            kept.append(sentence)
            total += extra
        trimmed = " ".join(kept) if kept else text[:max_chars].rstrip()
        repairs.append(
            f"trimmed {label} from {len(text)} to {len(trimmed)} chars"
        )
        return trimmed

    def dedupe_basis(entry: dict) -> None:
        basis = entry.get("basis_ids")
        if not isinstance(basis, list):
            return
        seen: set[str] = set()
        unique = []
        for ref in basis:
            if isinstance(ref, str) and ref not in seen:
                seen.add(ref)
                unique.append(ref)
        if unique != basis:
            repairs.append("deduped basis_ids")
        entry["basis_ids"] = unique

    for key, _, max_chars in SUMMARY_FIELDS:
        entry = fixed.get(key)
        if not isinstance(entry, dict):
            fixed[key] = {"text": "", "basis_ids": []}
            continue
        text = clean_prose(
            key, entry.get("text"), strip_decision=key != "bottom_line"
        )
        if key == "management_credibility" and isinstance(text, str):
            sentences = _split_sentences(text)
            if len(sentences) > 1:
                repairs.append(
                    "trimmed management_credibility to one sentence"
                )
                text = sentences[0]
        if isinstance(text, str):
            text = trim_field(key, text, max_chars)
        entry["text"] = text
        dedupe_basis(entry)
    questions = fixed.get("key_questions_for_management")
    if isinstance(questions, list):
        for index, question in enumerate(questions):
            if not isinstance(question, dict):
                continue
            question["text"] = clean_prose(
                f"question {index + 1}",
                question.get("text"),
                strip_decision=True,
            )
            dedupe_basis(question)
    recs = fixed.get("deal_recommendations")
    if isinstance(recs, list):
        for index, rec in enumerate(recs):
            if not isinstance(rec, dict):
                continue
            rec["text"] = clean_prose(
                f"deal_recommendations[{index}]",
                rec.get("text"),
                strip_decision=True,
            )
    return fixed, repairs


def needs_regeneration(errors: list[str]) -> bool:
    """True when any error is substantive (not a mechanical leftover)."""
    return any(
        not any(marker in error for marker in _MECHANICAL_ERROR_MARKERS)
        for error in errors
    )


def generate_narrative(
    payload: dict[str, Any], mode: Mode = "standard"
) -> dict[str, Any]:
    """Draft, validate, and (once) regenerate the IC narrative.

    ``payload`` carries target, overall, function_scores, findings,
    contradictions, remediation_plan, soc2_summary, has_interview,
    limitations, and required_recommendations. The model sees a labeled
    view (display labels instead of enums) plus recommendation slots;
    numbers validate against that view. Code assembles the digest
    narrative (labels, credibility counts, chips, slot bases) from the
    model's field prose. Returns ``{narrative, deal_recommendations,
    valid, validation_errors, regenerated, first_attempt_errors,
    narrative_repairs, usage, estimated_cost_usd}``.
    """
    findings = payload.get("findings", [])
    contradictions = payload.get("contradictions", [])
    ordered_finding_ids = [
        finding["finding_id"]
        for finding in findings
        if isinstance(finding.get("finding_id"), str)
    ]
    finding_ids = set(ordered_finding_ids)
    contradiction_ids = {
        item["contradiction_id"]
        for item in contradictions
        if isinstance(item.get("contradiction_id"), str)
    }
    required_map = payload.get("required_recommendations", {}) or {}
    if not isinstance(required_map, dict):
        required_map = {}
    slots = recommendation_slots(required_map, ordered_finding_ids)
    slot_types = [slot["type"] for slot in slots]

    labeled = _label_payload(payload, slots)
    # ensure_ascii=False: \u2013 escapes would glue window numbers into
    # phantom tokens ("201360") and hide the real ones ("60").
    input_numbers = _number_tokens(json.dumps(labeled, ensure_ascii=False))
    has_interview = payload.get("has_interview", True)
    has_soc2 = payload.get("soc2_summary", True) is not None
    short = len(finding_ids) <= SHORT_EVIDENCE_FINDINGS
    deal_label = DEAL_SIGNAL_LABELS.get(
        (payload.get("overall") or {}).get("deal_signal"), ""
    )
    extra_rules = [
        (
            f"The overall decision is: {deal_label}. State it once in "
            "the bottom_line field. It is shown separately in the "
            "memo and must not be restated in deal recommendations."
            if deal_label
            else "State the overall decision once in the bottom_line "
            "field; it must not be restated in deal recommendations."
        ),
        "Do not speculate about conditions not in the evidence "
        '("if present", "may contain"); state what is known and what '
        "to verify.",
    ]
    if not has_soc2:
        extra_rules.append(
            "State in key_risks or next_steps that no SOC 2 report was "
            "provided."
        )
    if short:
        extra_rules.append(
            "Short evidence base: ask 3 to 4 questions."
        )
    system_prompt = SYSTEM_PROMPT + "".join(
        f"\n{index}. {rule}"
        for index, rule in enumerate(extra_rules, start=7)
    )
    client = ModelClient(role="narrative", mode=mode)
    messages: list[dict[str, Any]] = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": json.dumps(labeled, indent=2)},
    ]
    output = client.chat_json(
        messages,
        schema=narrative_schema(),
        schema_name="narrative",
        reasoning_effort="medium",
    )

    def validate_fixed(candidate: Any) -> tuple[Any, list[str], list[str]]:
        fixed, repairs = repair_narrative(
            candidate, deal_label=deal_label
        )
        return (
            fixed,
            repairs,
            validate_narrative(
                fixed,
                finding_ids=finding_ids,
                contradiction_ids=contradiction_ids,
                input_numbers=input_numbers,
                slot_types=slot_types,
                has_soc2=has_soc2,
                deal_label=deal_label,
            ),
        )

    output, repairs, errors = validate_fixed(output)
    narrative_repairs = list(repairs)
    regenerated = False
    first_attempt_errors = list(errors)
    if errors and needs_regeneration(errors):
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
        output, repairs, errors = validate_fixed(output)
        narrative_repairs.extend(repairs)
    valid = not errors
    narrative, recs = assemble_narrative(
        output if isinstance(output, dict) else {},
        slots=slots,
        contradictions=contradictions,
        has_interview=has_interview,
    )
    usage = dict(client.total_usage)
    return {
        "narrative": narrative,
        "deal_recommendations": recs,
        "valid": valid,
        "validation_errors": errors,
        "regenerated": regenerated,
        "first_attempt_errors": first_attempt_errors,
        "narrative_repairs": narrative_repairs,
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
