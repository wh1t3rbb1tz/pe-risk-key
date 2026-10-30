"""SOC 2 document analyzer (SPEC §4.2).

One Muse Wonder call extracts the report into a strict schema; code then
verifies every quote against the source text, computes the bridge gap,
and builds findings deterministically from scoring.yaml rules. Not yet
wired into the orchestrator.
"""

from __future__ import annotations

import copy
import hashlib
import io
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path
from typing import Any

import jsonschema
import yaml
from pypdf import PdfReader

from pe_risk_key.analyzers.schemas import soc2_extraction_schema
from pe_risk_key.engine.rules import apply_rule_constraints
from pe_risk_key.providers import WONDER_USD_PER_MTOK, Mode, ModelClient
from pe_risk_key.schemas import subschema

ROOT = Path(__file__).resolve().parents[3]
SCORING_PATH = ROOT / "scoring.yaml"

MAX_QUOTE_CHARS = 400

# Explicit control_id -> rule mapping (mirrors the scoring.yaml match
# strings without parsing them).
CONTROL_RULE_MAP = {
    "CC6.1": "SOC2-EXCEPTION-ACCESS",
    "CC6.2": "SOC2-EXCEPTION-ACCESS",
    "CC6.3": "SOC2-EXCEPTION-ACCESS",
    "CC7.2": "SOC2-EXCEPTION-MONITORING",
    "CC7.3": "SOC2-EXCEPTION-MONITORING",
    "CC8.1": "SOC2-EXCEPTION-CHANGE",
    "CC9.2": "SOC2-EXCEPTION-VENDOR",
}

SYSTEM_PROMPT = """You extract a SOC 2 report into structured data. Rules:
1. Quote the report verbatim for every quote field. Copy exact sentences; never paraphrase, shorten, or invent text.
2. Every item must have a locator: the section, page, or control reference where it appears.
3. Opinion mapping: "except for the deviations described ... which did not modify our opinion" (and equivalent "did not rise to a level" language) means unqualified. Only a stated qualification, adverse opinion, or disclaimer maps to those values.
4. Never infer exceptions that the report does not state. A clean test table with no deviations is not an exception.
5. Normalize enums: report_type to type1/type2, trust categories to security/availability/confidentiality/processing_integrity/privacy, subservice method to carve_out/inclusive. Dates as YYYY-MM-DD.
6. critical is true for a subservice org only if it hosts production systems or processes the data in scope.
7. notable_observations are items that are not exceptions but matter for diligence: pen-test findings noted in a "no exceptions" row, unaudited management statements about bridge letters, scope limits. Each needs text, a locator, and a verbatim quote.
8. bridge_letter_provided is true only if a bridge letter covers the gap through the assessment date given with the report."""


@dataclass
class SOC2Result:
    """Validated SOC 2 analysis plus derived signals, evidence, findings."""

    doc_id: str
    filename: str
    sha256: str
    opinion_quote: str
    soc2_analysis: dict[str, Any]
    notable_observations: list[dict[str, Any]]
    signals: dict[str, Any]
    evidence_pool: list[dict[str, Any]]
    findings: list[dict[str, Any]]
    dropped_unquoted: list[dict[str, Any]] = field(default_factory=list)
    dropped_no_locator: list[dict[str, Any]] = field(default_factory=list)
    usage: dict[str, int] = field(default_factory=dict)
    estimated_cost_usd: float = 0.0


def _read_text(path: Path) -> tuple[str, bytes]:
    raw = path.read_bytes()
    suffix = path.suffix.lower()
    if suffix == ".pdf":
        reader = PdfReader(io.BytesIO(raw))
        if reader.is_encrypted:
            raise ValueError(f"Encrypted PDF is not supported: {path}.")
        pages = [
            f"[page {number}]\n{page.extract_text() or ''}"
            for number, page in enumerate(reader.pages, start=1)
        ]
        return "\n\n".join(pages), raw
    if suffix in (".md", ".txt"):
        return raw.decode("utf-8"), raw
    raise ValueError(
        f"Unsupported SOC 2 file type {path.suffix!r}; want .pdf, .md, or .txt."
    )


def _normalize(text: str) -> str:
    return " ".join(text.split())


def _verified_quote(quote: Any, source: str) -> str | None:
    """Truncated quote when it appears verbatim in the source, else None."""
    if not isinstance(quote, str):
        return None
    truncated = quote.strip()[:MAX_QUOTE_CHARS]
    if not truncated:
        return None
    if _normalize(truncated) not in _normalize(source):
        return None
    return truncated


def _has_locator(item: dict) -> bool:
    locator = item.get("locator")
    return isinstance(locator, str) and bool(locator.strip())


def _filter_items(
    items: list[dict], kind: str, source: str, ref_key: str | None
) -> tuple[list[dict], list[dict], list[dict]]:
    """Keep quoted + located items; collect unquoted and locator drops."""
    kept: list[dict] = []
    unquoted: list[dict] = []
    no_locator: list[dict] = []
    for index, item in enumerate(items):
        ref = item.get(ref_key) if ref_key else None
        ref = ref or f"#{index + 1}"
        if not _has_locator(item):
            no_locator.append({"type": kind, "ref": ref})
            continue
        if "quote" in item:
            verified = _verified_quote(item.get("quote"), source)
            if verified is None:
                unquoted.append({"type": kind, "ref": ref})
                continue
            item = {**item, "quote": verified}
        kept.append(item)
    return kept, unquoted, no_locator


def _rules_by_id(scoring_config: dict) -> dict[str, dict]:
    return {
        rule["id"]: rule
        for rule in scoring_config.get("rules", [])
        if isinstance(rule, dict) and "id" in rule
    }


def _analyze_cost_usd(usage: dict[str, int]) -> float:
    billable = max(
        0, usage.get("prompt_tokens", 0) - usage.get("cached_tokens", 0)
    )
    return round(
        (
            billable * WONDER_USD_PER_MTOK["input"]
            + usage.get("cached_tokens", 0) * WONDER_USD_PER_MTOK["cached"]
            + usage.get("completion_tokens", 0)
            * WONDER_USD_PER_MTOK["output"]
        )
        / 1_000_000,
        6,
    )


def analyze_soc2(
    path: str | Path,
    doc_id: str,
    as_of: date | str,
    mode: Mode = "standard",
    offset: int = 0,
) -> SOC2Result:
    """Analyze one SOC 2 report file into analysis, signals, and findings.

    ``as_of`` is the assessment date for bridge-gap math. ``offset``
    shifts finding/evidence numbering (``F-011``/``E-011`` first at
    ``offset=10``) so IDs merge with outside-in findings later.
    """
    file_path = Path(path)
    source_text, raw = _read_text(file_path)
    if isinstance(as_of, str):
        as_of = date.fromisoformat(as_of)

    client = ModelClient(role="document_analysis", mode=mode)
    extraction = client.chat_json(
        [
            {"role": "system", "content": SYSTEM_PROMPT},
            {
                "role": "user",
                "content": (
                    f"Assessment date: {as_of.isoformat()}.\n"
                    f"Report text:\n{source_text}"
                ),
            },
        ],
        schema=soc2_extraction_schema(),
        schema_name="soc2_extraction",
        reasoning_effort="medium",
    )

    dropped_unquoted: list[dict] = []
    dropped_no_locator: list[dict] = []
    exceptions, unquoted, no_loc = _filter_items(
        extraction.get("exceptions", []), "exception", source_text, "control_id"
    )
    dropped_unquoted.extend(unquoted)
    dropped_no_locator.extend(no_loc)
    notables, unquoted, no_loc = _filter_items(
        extraction.get("notable_observations", []),
        "notable_observation",
        source_text,
        None,
    )
    dropped_unquoted.extend(unquoted)
    dropped_no_locator.extend(no_loc)
    cuecs, _, no_loc = _filter_items(
        extraction.get("cuecs", []), "cuec", source_text, None
    )
    dropped_no_locator.extend(no_loc)
    orgs, _, no_loc = _filter_items(
        extraction.get("subservice_orgs", []), "subservice_org", source_text, "name"
    )
    dropped_no_locator.extend(no_loc)

    opinion_quote = _verified_quote(
        extraction.get("opinion_quote"), source_text
    )
    if opinion_quote is None:
        dropped_unquoted.append({"type": "opinion", "ref": "opinion"})
        opinion_quote = ""

    try:
        period_end = date.fromisoformat(extraction["period_end"])
    except (KeyError, ValueError, TypeError) as exc:
        raise ValueError(
            f"Unparseable period_end {extraction.get('period_end')!r}."
        ) from exc
    if extraction.get("bridge_letter_provided"):
        bridge_gap_days = 0
    else:
        bridge_gap_days = max(0, (as_of - period_end).days)

    scoring = yaml.safe_load(SCORING_PATH.read_text(encoding="utf-8"))
    rules = _rules_by_id(scoring)

    # Evidence pool (numbered first so findings can reference it).
    pool: list[dict] = []

    def add_evidence(locator: str, excerpt: str) -> dict:
        item = {
            "evidence_id": f"E-{offset + len(pool) + 1:03d}",
            "source_type": "document",
            "collection_method": "document_upload",
            "collector": "soc2_analyzer",
            "locator": locator,
            "excerpt": excerpt,
        }
        pool.append(item)
        return item

    exception_evidence = [
        add_evidence(item["locator"], item["quote"]) for item in exceptions
    ]
    carve_outs = [org for org in orgs if org.get("method") == "carve_out"]
    carve_evidence = [
        add_evidence(
            org["locator"],
            f"{org['name']} is carved out of scope: {org['services']}.",
        )
        for org in carve_outs
    ]
    for cuec in cuecs:
        add_evidence(cuec["locator"], cuec["text"])
    for notable in notables:
        add_evidence(notable["locator"], notable["quote"])

    # Findings, built in code from scoring.yaml rules.
    draft: list[dict] = []
    finding_for_exception: dict[int, str] = {}
    for index, item in enumerate(exceptions):
        rule_id = CONTROL_RULE_MAP.get(item["control_id"])
        if rule_id is None or rule_id not in rules:
            continue
        rule = rules[rule_id]
        finding_id = f"F-{offset + len(draft) + 1:03d}"
        finding_for_exception[index] = finding_id
        draft.append(
            {
                "finding_id": finding_id,
                "title": rule["title"],
                "severity": rule["severity"],
                "confidence": "high",
                "csf_function": rule["csf"].split(".")[0],
                "csf_category": rule["csf"],
                "source": "document",
                "evidence": [copy.deepcopy(exception_evidence[index])],
                "deal_impact": item["deal_impact"],
                "remediation": {
                    "summary": f"Remediate {item['control_id']} exception: {item['description']}",
                    "cost_low_usd": 0,
                    "cost_high_usd": 0,
                    "effort_weeks": 0,
                },
                "rule_id": rule_id,
            }
        )
    if bridge_gap_days > 90 and "SOC2-BRIDGE-GAP" in rules:
        rule = rules["SOC2-BRIDGE-GAP"]
        # Computed bridge evidence joins the pool so the finding cites it.
        bridge_item = add_evidence(
            f"{file_path.name} (report period)",
            f"Report period ended {period_end.isoformat()}; "
            f"{bridge_gap_days} days before {as_of.isoformat()}.",
        )
        draft.append(
            {
                "finding_id": f"F-{offset + len(draft) + 1:03d}",
                "title": rule["title"],
                "severity": rule["severity"],
                "confidence": "high",
                "csf_function": rule["csf"].split(".")[0],
                "csf_category": rule["csf"],
                "source": "document",
                "evidence": [copy.deepcopy(bridge_item)],
                "deal_impact": (
                    f"Report period ended {period_end.isoformat()}, "
                    f"{bridge_gap_days} days before the assessment date; "
                    "controls may have changed since."
                ),
                "remediation": {
                    "summary": f"Obtain a bridge letter covering through {as_of.isoformat()}.",
                    "cost_low_usd": 0,
                    "cost_high_usd": 0,
                    "effort_weeks": 0,
                },
                "rule_id": "SOC2-BRIDGE-GAP",
            }
        )
    for org, evidence_item in zip(carve_outs, carve_evidence):
        if not org.get("critical") or "SOC2-CARVE-OUT-CRITICAL" not in rules:
            continue
        rule = rules["SOC2-CARVE-OUT-CRITICAL"]
        draft.append(
            {
                "finding_id": f"F-{offset + len(draft) + 1:03d}",
                "title": rule["title"],
                "severity": rule["severity"],
                "confidence": "high",
                "csf_function": rule["csf"].split(".")[0],
                "csf_category": rule["csf"],
                "source": "document",
                "evidence": [copy.deepcopy(evidence_item)],
                "deal_impact": (
                    f"{org['name']} ({org['services']}) is carved out of "
                    "scope and is critical to production or in-scope data."
                ),
                "remediation": {
                    "summary": f"Obtain the {org['name']} SOC report and assess carve-out risk.",
                    "cost_low_usd": 0,
                    "cost_high_usd": 0,
                    "effort_weeks": 0,
                },
                "rule_id": "SOC2-CARVE-OUT-CRITICAL",
            }
        )
    findings, _ = apply_rule_constraints(draft, scoring, None)

    analysis_exceptions = []
    for index, item in enumerate(exceptions):
        entry: dict[str, Any] = {
            "control_id": item["control_id"],
            "description": item["description"],
            "deviations": item.get("deviations") or 0,
            "sample_size": item.get("sample_size") or 0,
            "locator": item["locator"],
        }
        if item.get("management_response"):
            entry["management_response"] = item["management_response"]
        if index in finding_for_exception:
            entry["finding_id"] = finding_for_exception[index]
        analysis_exceptions.append(entry)
    soc2_analysis = {
        "doc_id": doc_id,
        "report_type": extraction["report_type"],
        "period_start": extraction["period_start"],
        "period_end": extraction["period_end"],
        "auditor": extraction["auditor"],
        "opinion": extraction["opinion"],
        "trust_services_categories": extraction.get(
            "trust_services_categories", []
        ),
        "exceptions": analysis_exceptions,
        "subservice_orgs": [
            {
                "name": org["name"],
                "method": org["method"],
                "services": org["services"],
                "critical": bool(org.get("critical")),
            }
            for org in orgs
        ],
        "cuecs": [cuec["text"] for cuec in cuecs],
        "bridge_gap_days": bridge_gap_days,
    }
    failures = sorted(
        jsonschema.Draft202012Validator(
            subschema("soc2_analysis")
        ).iter_errors(soc2_analysis),
        key=lambda e: e.json_path,
    )
    if failures:
        raise ValueError(
            "Built soc2_analysis failed validation: "
            + "; ".join(f"{e.json_path}: {e.message}" for e in failures[:5])
        )

    usage = dict(client.total_usage)
    return SOC2Result(
        doc_id=doc_id,
        filename=file_path.name,
        sha256=hashlib.sha256(raw).hexdigest(),
        opinion_quote=opinion_quote,
        soc2_analysis=soc2_analysis,
        notable_observations=notables,
        signals={
            "exceptions": [
                {"control_id": item["control_id"]} for item in exceptions
            ],
            "subservice_orgs": [
                {
                    "name": org["name"],
                    "method": org["method"],
                    "critical": bool(org.get("critical")),
                }
                for org in orgs
            ],
            "bridge_gap_days": bridge_gap_days,
        },
        evidence_pool=pool,
        findings=findings,
        dropped_unquoted=dropped_unquoted,
        dropped_no_locator=dropped_no_locator,
        usage=usage,
        estimated_cost_usd=_analyze_cost_usd(usage),
    )
