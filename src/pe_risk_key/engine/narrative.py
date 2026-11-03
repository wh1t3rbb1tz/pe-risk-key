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
4. Deal recommendations: write exactly one recommendation per required type, following its guidance. Recommendations must reference the remediation windows and the deal signal. Do not restate the deal signal as a shared opening clause, and never start a recommendation with its own type name.
5. key_questions_for_management: 5 to 8 questions, each tied to specific findings or contradictions via bracket citations. Use neutral diligence phrasing ("Provide...", "Reconcile...", "Confirm..."), never "Why did...".
6. Write plain IC prose: no enum strings, cap ids, control codes, or evidence locators. Cite [F-xxx]/[C-xxx] instead."""

MAX_SUMMARY_CHARS = 1200
MAX_SHORT_SUMMARY_CHARS = 600
SHORT_EVIDENCE_FINDINGS = 3
SHORT_QUESTION_RANGE = (3, 4)
FULL_QUESTION_RANGE = (5, 8)
NO_INTERVIEW_CREDIBILITY = "Not assessed: no management interview provided."

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
            "score": _decimal_text(overall.get("score")),
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
        "required_recommendations": payload.get("required_recommendations", {}),
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


def _section_text(summary: str, section: str) -> str:
    """Text of one labeled summary paragraph (label excluded)."""
    lowered = summary.lower()
    start = lowered.find(section)
    if start < 0:
        return ""
    start += len(section)
    ends = [
        lowered.find(other, start)
        for other in SUMMARY_SECTIONS
        if other != section
    ]
    ends = [position for position in ends if position >= 0]
    end = min(ends) if ends else len(summary)
    return summary[start:end].strip()


def validate_narrative(
    output: Any,
    *,
    finding_ids: set[str],
    contradiction_ids: set[str],
    input_numbers: set[str],
    required_types: set[str] | None = None,
    trigger_findings: dict[str, list[str]] | None = None,
    contradiction_verdicts: dict[str, str] | None = None,
    has_interview: bool = True,
    has_soc2: bool = True,
    finding_count: int | None = None,
) -> list[str]:
    """Human-readable validation errors; empty means valid."""
    errors: list[str] = []
    if not isinstance(output, dict):
        return ["narrative output is not an object."]
    count = len(finding_ids) if finding_count is None else finding_count
    short = count <= SHORT_EVIDENCE_FINDINGS
    max_chars = MAX_SHORT_SUMMARY_CHARS if short else MAX_SUMMARY_CHARS
    summary = output.get("executive_summary")
    if not isinstance(summary, str):
        errors.append("executive_summary is not a string.")
        summary = ""
    else:
        if len(summary) > max_chars:
            errors.append(
                f"executive_summary is {len(summary)} chars "
                f"(max {max_chars})."
            )
        lowered = summary.lower()
        for section in SUMMARY_SECTIONS:
            if section not in lowered:
                errors.append(
                    f"executive_summary is missing {section!r} section."
                )
        if not has_interview:
            credibility = _section_text(summary, "management credibility:")
            if credibility != NO_INTERVIEW_CREDIBILITY:
                errors.append(
                    "management credibility must read exactly "
                    f"{NO_INTERVIEW_CREDIBILITY!r} when no interview was "
                    "provided."
                )
        if not has_soc2:
            coverage = _section_text(
                summary, "key risks:"
            ) + _section_text(summary, "next steps:")
            if "soc 2" not in coverage.lower():
                errors.append(
                    "state in key risks or next steps that no SOC 2 "
                    "report was provided."
                )
        if short:
            cites: dict[str, int] = {}
            for kind, number in _CITE_RE.findall(summary):
                ref = f"{kind}-{number}"
                cites[ref] = cites.get(ref, 0) + 1
            for ref in sorted(cites):
                if cites[ref] > 2:
                    errors.append(
                        f"executive_summary cites {ref} {cites[ref]} "
                        "times (max 2 for a short evidence base)."
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
    recs = output.get("deal_recommendations")
    if not isinstance(recs, list):
        errors.append("deal_recommendations is not a list.")
        recs = []

    def check_text(label: str, text: Any, require_citation: bool) -> None:
        if not isinstance(text, str):
            errors.append(f"{label} is not a string.")
            return
        errors.extend(_leak_errors(label, text))
        for phrase in sorted(
            {match.group(0).lower() for match in _SPECULATION_RE.finditer(text)}
        ):
            errors.append(
                f"{label} speculates ({phrase!r}); state what is known "
                "and what to verify."
            )
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
    triggers = trigger_findings or {}
    verdicts = contradiction_verdicts or {}
    for index, rec in enumerate(recs):
        label = f"deal_recommendations[{index}]"
        if not isinstance(rec, dict):
            errors.append(f"{label} is not an object.")
            continue
        if rec.get("type") not in valid_types:
            errors.append(f"{label} has unknown type {rec.get('type')!r}.")
        else:
            seen_types.add(rec["type"])
        text = rec.get("text")
        check_text(label, text, require_citation=False)
        if isinstance(text, str) and isinstance(rec.get("type"), str):
            type_label = DEAL_TYPE_LABELS.get(rec["type"], "")
            if type_label and text.lstrip().lower().startswith(
                type_label.lower()
            ):
                errors.append(
                    f"{label} starts with its own type label; lead with "
                    "the substance instead."
                )
        basis = rec.get("basis_ids")
        if not isinstance(basis, list) or not basis:
            errors.append(f"{label} has no basis_ids.")
        else:
            for ref in basis:
                if ref in finding_ids or ref in contradiction_ids:
                    if verdicts.get(ref) == "supported":
                        errors.append(
                            f"{label} cites supported contradiction {ref}; "
                            "basis must contradict or be silent."
                        )
                    continue
                errors.append(f"{label} cites unknown id {ref!r}.")
            needed = triggers.get(rec.get("type"), [])
            if needed and not (set(basis) & set(needed)):
                errors.append(
                    f"{label} basis must include trigger finding(s) "
                    f"{', '.join(needed)}."
                )
    for rec_type in sorted((required_types or set()) - seen_types):
        errors.append(f"missing required {rec_type} recommendation.")
    rec_texts = [
        (index, rec.get("text"))
        for index, rec in enumerate(recs)
        if isinstance(rec, dict) and isinstance(rec.get("text"), str)
    ]
    for left in range(len(rec_texts)):
        for right in range(left + 1, len(rec_texts)):
            shared = _shared_prefix_words(
                rec_texts[left][1], rec_texts[right][1]
            )
            if shared >= 8:
                errors.append(
                    f"deal_recommendations[{rec_texts[left][0]}] and "
                    f"[{rec_texts[right][0]}] share a {shared}-word "
                    "leading clause; restate the deal signal once at most."
                )
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
    summary_quantities = _SOC_TWO_RE.sub("", summary)
    for token in sorted(_number_tokens(summary_quantities) - input_numbers):
        errors.append(
            f"executive_summary states number {token} not in the input."
        )
    for token in sorted(set(_OVER_PRECISE_RE.findall(summary))):
        errors.append(
            f"executive_summary states number {token} with 2+ decimals; "
            "use one-decimal scores."
        )
    return errors


def generate_narrative(
    payload: dict[str, Any], mode: Mode = "standard"
) -> dict[str, Any]:
    """Draft, validate, and (once) regenerate the IC narrative.

    ``payload`` carries target, overall, function_scores, findings,
    contradictions, remediation_plan, soc2_summary, has_interview,
    limitations, and required_recommendations. The model sees a labeled
    view (display
    labels instead of enums); numbers validate against that view.
    Returns ``{narrative, deal_recommendations, valid,
    validation_errors, regenerated, first_attempt_errors, usage,
    estimated_cost_usd}``. The narrative is sanitized for digest safety
    even when invalid.
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
    required_map = payload.get("required_recommendations", {}) or {}
    if not isinstance(required_map, dict):
        required_map = {}
    required_types = set(required_map)
    trigger_findings = {
        rec_type: entry.get("trigger_findings", [])
        for rec_type, entry in required_map.items()
        if isinstance(entry, dict)
    }
    contradiction_verdicts = {
        item.get("contradiction_id"): item.get("verdict")
        for item in contradictions
        if isinstance(item.get("contradiction_id"), str)
    }

    def add_trigger_basis(output: Any) -> None:
        """Union each rec's basis with its trigger findings, in place."""
        if not isinstance(output, dict):
            return
        for rec in output.get("deal_recommendations", []) or []:
            if not isinstance(rec, dict):
                continue
            basis = rec.get("basis_ids")
            if not isinstance(basis, list):
                continue
            for finding_id in trigger_findings.get(rec.get("type"), []):
                if finding_id not in basis:
                    basis.append(finding_id)

    labeled = _label_payload(payload)
    input_numbers = _number_tokens(json.dumps(labeled))
    has_interview = payload.get("has_interview", True)
    has_soc2 = payload.get("soc2_summary", True) is not None
    short = len(finding_ids) <= SHORT_EVIDENCE_FINDINGS
    extra_rules = [
        "Do not speculate about conditions not in the evidence "
        '("if present", "may contain"); state what is known and what '
        "to verify.",
    ]
    if not has_interview:
        extra_rules.append(
            "The Management credibility paragraph must read exactly: "
            f'"{NO_INTERVIEW_CREDIBILITY}"'
        )
    if not has_soc2:
        extra_rules.append(
            "State in Key risks or Next steps that no SOC 2 report was "
            "provided."
        )
    if short:
        extra_rules.append(
            "Short evidence base: keep executive_summary to 600 "
            "characters or fewer, ask 3 to 4 questions, and cite no "
            "finding more than twice in the summary."
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
    add_trigger_basis(output)
    errors = validate_narrative(
        output,
        finding_ids=finding_ids,
        contradiction_ids=contradiction_ids,
        input_numbers=input_numbers,
        required_types=required_types,
        trigger_findings=trigger_findings,
        contradiction_verdicts=contradiction_verdicts,
        has_interview=has_interview,
        has_soc2=has_soc2,
    )
    regenerated = False
    first_attempt_errors = list(errors)
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
        add_trigger_basis(output)
        errors = validate_narrative(
            output,
            finding_ids=finding_ids,
            contradiction_ids=contradiction_ids,
            input_numbers=input_numbers,
            required_types=required_types,
            trigger_findings=trigger_findings,
            contradiction_verdicts=contradiction_verdicts,
            has_interview=has_interview,
            has_soc2=has_soc2,
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
    summary_cap = MAX_SHORT_SUMMARY_CHARS if short else MAX_SUMMARY_CHARS
    return {
        "narrative": {
            "executive_summary": summary[:summary_cap]
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
        "first_attempt_errors": first_attempt_errors,
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
