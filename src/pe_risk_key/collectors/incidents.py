"""search_public_incidents collector: grounded public-records search."""

from __future__ import annotations

import json
import re
import sys
from datetime import date
from typing import Any

import jsonschema

from pe_risk_key.collectors.registry import register
from pe_risk_key.providers import ModelClient

COLLECTION_METHOD = "search_grounding"

# Cost control: the four fixed queries below are the whole run.
MAX_SEARCHES_PER_RUN = 4

RESULT_TYPES = (
    "sec_8k_item_105",
    "state_ag_breach_notice",
    "regulator_action",
    "press_report",
    "company_statement",
)

# Enforces SPEC §2 ("Querying breach/credential-dump data sources" is
# prohibited): results from paste sites, leak forums, breach-dump or
# combo-list sites, or credential-lookup services are dropped, never
# fetched or cited.
PROHIBITED_SOURCE_PATTERNS = [
    # Paste sites.
    r"pastebin\.com",
    r"paste\.ee",
    r"ghostbin",
    r"hastebin",
    r"ix\.io",
    r"termbin",
    r"privatebin",
    r"rentry\.",
    # Leak forums and breach-dump / combo-list sites.
    r"breachforums",
    r"raidforums",
    r"nulled",
    r"cracked\.(io|to)",
    r"ogusers",
    r"combolist",
    r"combo[_-]?list",
    r"breach[_-]?dump",
    # Credential-lookup services.
    r"dehashed",
    r"leakcheck",
    r"snusbase",
]
_PROHIBITED = [
    re.compile(pattern, re.IGNORECASE)
    for pattern in PROHIBITED_SOURCE_PATTERNS
]

RESULTS_SCHEMA: dict[str, Any] = {
    "type": "object",
    "required": ["results"],
    "additionalProperties": False,
    "properties": {
        "results": {
            "type": "array",
            "items": {
                "type": "object",
                "required": [
                    "type",
                    "date",
                    "summary",
                    "url",
                    "entity_match",
                    "match_basis",
                ],
                "additionalProperties": False,
                "properties": {
                    "type": {"enum": list(RESULT_TYPES)},
                    "date": {
                        "type": "string",
                        "pattern": r"^\d{4}-\d{2}-\d{2}$",
                    },
                    "summary": {"type": "string"},
                    "url": {"type": "string"},
                    "entity_match": {
                        "enum": ["exact", "probable", "uncertain"]
                    },
                    "match_basis": {"type": "string"},
                },
            },
        },
    },
}

INPUT_SCHEMA = {
    "type": "object",
    "properties": {
        "domain": {
            "type": "string",
            "description": "Target apex domain, e.g. acme.example.",
        },
        "company_name": {
            "type": "string",
            "description": (
                "Target company name for incident queries; "
                "defaults to the domain."
            ),
        },
    },
    "required": ["domain"],
    "additionalProperties": False,
}


def _queries(company: str, domain: str) -> list[str]:
    return [
        f"{company} data breach",
        f"{company} security incident notification",
        f"{company} 8-K Item 1.05 cybersecurity incident",
        f"{domain} breach notice attorney general",
    ]


def _instructions(company: str, domain: str) -> str:
    types = ", ".join(RESULT_TYPES)
    return (
        f"You report publicly disclosed security incidents involving "
        f"{company} ({domain}).\n"
        f"Today's date is {date.today().isoformat()}.\n"
        "Rules:\n"
        "- Report only incidents involving the named company. If a result "
        'might be a different company with a similar name, set '
        'entity_match to "uncertain" and explain in match_basis.\n'
        '- If you found nothing, return {"results": []}. No results is a '
        "valid, expected outcome.\n"
        '- Return ONLY JSON of the form {"results": [...]} with no other '
        "text. Each result has:\n"
        f"  - type: one of {types}\n"
        "  - date: disclosure date as YYYY-MM-DD\n"
        "  - summary: one or two sentences\n"
        "  - url: the source page URL\n"
        "  - entity_match: exact | probable | uncertain\n"
        "  - match_basis: why you believe this is the same company\n"
        "- Every url must be a page you actually cite. Do not invent URLs."
    )


def _field(obj: Any, name: str) -> Any:
    if isinstance(obj, dict):
        return obj.get(name)
    return getattr(obj, name, None)


def _extract_text_and_citations(response: Any) -> tuple[str, set[str]]:
    """Concatenated output_text plus url_citation URLs.

    Per https://dev.meta.ai/docs/search-grounding, grounded answers
    attach ``url_citation`` annotations (``url``, ``title``,
    ``start_index``, ``end_index``) to ``output_text`` blocks; those
    annotations are the subset of sources the model actually cited.
    """
    texts: list[str] = []
    citations: set[str] = set()
    for item in _field(response, "output") or []:
        if _field(item, "type") != "message":
            continue
        for block in _field(item, "content") or []:
            if _field(block, "type") != "output_text":
                continue
            texts.append(_field(block, "text") or "")
            for annotation in _field(block, "annotations") or []:
                if _field(annotation, "type") == "url_citation":
                    url = _field(annotation, "url")
                    if url:
                        citations.add(url)
    return "\n".join(texts), citations


def _strip_fences(text: str) -> str:
    match = re.search(
        r"```(?:json)?\s*(.*?)\s*```", text, re.IGNORECASE | re.DOTALL
    )
    return match.group(1) if match else text.strip()


def _validation_errors(parsed: Any) -> list[str]:
    validator = jsonschema.Draft202012Validator(RESULTS_SCHEMA)
    errors = [
        f"{e.json_path}: {e.message}"
        for e in sorted(
            validator.iter_errors(parsed), key=lambda e: e.json_path
        )
    ]
    if not errors and isinstance(parsed, dict):
        for index, result in enumerate(parsed.get("results", [])):
            try:
                date.fromisoformat(result["date"])
            except (ValueError, TypeError, KeyError):
                errors.append(
                    f"$.results[{index}].date: "
                    f"{result.get('date')!r} is not a calendar date"
                )
    return errors


def _months_since(iso_day: str, today: date) -> int:
    disclosed = date.fromisoformat(iso_day)
    return max(
        0, (today.year - disclosed.year) * 12 + today.month - disclosed.month
    )


def _normalize_url(url: str) -> str:
    return url.strip().rstrip("/")


def _log_drop(kind: str, url: str) -> None:
    print(
        f"[search_public_incidents] {kind}: {url}",
        file=sys.stderr,
    )


def _collect_query(
    client: ModelClient, query: str, prompt: str
) -> tuple[list[dict], set[str]]:
    """Run one grounded query; retry once on invalid JSON. May raise."""
    attempt_input = query
    citations: set[str] = set()
    for attempt in range(2):
        response = client.responses_search(
            attempt_input, instructions=prompt
        )
        text, citations = _extract_text_and_citations(response)
        try:
            parsed = json.loads(_strip_fences(text))
        except json.JSONDecodeError:
            errors = [f"(invalid JSON): {text[:200]}"]
        else:
            errors = _validation_errors(parsed)
            if not errors:
                return parsed["results"], citations
        if attempt == 1:
            raise ValueError(
                "Second structured-output attempt failed validation: "
                + "; ".join(errors[:5])
            )
        attempt_input = (
            f"{query}\n\nYour previous response did not match the "
            "required JSON schema:\n"
            + "\n".join(f"- {e}" for e in errors[:10])
            + "\nReturn only corrected JSON matching the schema."
        )
    raise AssertionError("unreachable")  # pragma: no cover


@register(
    tool_name="search_public_incidents",
    description=(
        "Search-grounded lookup of publicly disclosed security incidents "
        "(SEC 8-K Item 1.05, state AG breach notices, regulator actions, "
        "press) for the target company. Reads only public sources."
    ),
    collection_method=COLLECTION_METHOD,
    input_schema=INPUT_SCHEMA,
)
def collect(domain: str, company_name: str | None = None) -> dict:
    """Collect public incident disclosures via grounded model searches.

    Runs at most ``MAX_SEARCHES_PER_RUN`` searches, keeps only cited
    results from allowed sources, and computes
    ``disclosed_within_months`` in code. A failed query degrades to
    ``partial`` (``error`` when every query failed) rather than raising.
    """
    company = company_name or domain
    client = ModelClient(role="public_records")
    prompt = _instructions(company, domain)
    queries = _queries(company, domain)[:MAX_SEARCHES_PER_RUN]

    results: list[dict] = []
    seen: set[str] = set()
    dropped_uncited = 0
    dropped_prohibited = 0
    failed = 0
    for query in queries:
        try:
            found, citations = _collect_query(client, query, prompt)
        except Exception as exc:  # one bad query must not kill the run
            failed += 1
            print(
                f"[search_public_incidents] query failed: {query} ({exc})",
                file=sys.stderr,
            )
            continue
        cited = {_normalize_url(url) for url in citations}
        for result in found:
            url = _normalize_url(result["url"])
            if url not in cited and result["url"] not in citations:
                dropped_uncited += 1
                _log_drop("dropped_uncited", result["url"])
                continue
            if any(pattern.search(url) for pattern in _PROHIBITED):
                dropped_prohibited += 1
                _log_drop("dropped_prohibited_source", result["url"])
                continue
            if url in seen:
                continue
            seen.add(url)
            counted = result["entity_match"] in ("exact", "probable")
            results.append(
                {
                    "type": result["type"],
                    "date": result["date"],
                    "summary": result["summary"],
                    "url": result["url"],
                    "locator": result["url"],
                    "entity_match": result["entity_match"],
                    "match_basis": result["match_basis"],
                    "counts_toward_findings": counted,
                }
            )

    today = date.today()
    counted_dates = [
        result["date"] for result in results if result["counts_toward_findings"]
    ]
    if failed == len(queries):
        status = "error"
    elif failed:
        status = "partial"
    else:
        status = "ok"
    return {
        "collection_method": COLLECTION_METHOD,
        "status": status,
        "queries_run": queries,
        "dropped_uncited": dropped_uncited,
        "dropped_prohibited_source": dropped_prohibited,
        "results": results,
        "disclosed_within_months": (
            min(_months_since(day, today) for day in counted_dates)
            if counted_dates
            else None
        ),
    }
