"""search_public_incidents collector: grounded search + strict extraction.

Two phases, because single-shot structured output fails when the
web_search tool is active: the model emits progress narration
("I'll search…") around the JSON, so strict parsing fails twice and
the query errors. Docs notes (https://dev.meta.ai/docs/search-grounding,
https://dev.meta.ai/docs/structured-output):

- ``response_format`` is Chat Completions-only while web_search is
  Responses/Messages-only; the params cannot combine across endpoints.
  The Responses-side ``text.format`` + web_search combination is
  undocumented, so narration-safe parsing is not guaranteed.
- Responses examples show a single message item; narration is not
  documented as separate output items. Defensively, the LAST message
  item is treated as the final answer.

Phase 1 (search): one Responses API call per query with web_search,
asking for a plain-text incident summary. Captures the final answer
text plus the full citation list (URL + title).
Phase 2 (extract): one chat_json call (no tools, strict json_schema)
over the phase-1 texts and the union of citations.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sys
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any

from pe_risk_key.collectors.registry import register
from pe_risk_key.providers import ModelClient

COLLECTION_METHOD = "search_grounding"

# Cost control: the four fixed queries below are the whole run.
MAX_SEARCHES_PER_RUN = 4

ROOT = Path(__file__).resolve().parents[3]
CACHE_DIR = ROOT / ".cache" / "public_incidents"
CACHE_TTL_SECONDS = 7 * 24 * 3600

DEFAULT_MAX_INPUT_TOKENS = 250_000

# Standard-mode Muse Spark prices per 1M tokens, plus the web_search
# surcharge, per https://dev.meta.ai/docs/pricing-rate-limits.
SPARK_USD_PER_MTOK = {"input": 1.25, "cached": 0.15, "output": 4.25}
SEARCH_USD_PER_SEARCH = 2.50 / 1000

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
        "aliases": {
            "type": "array",
            "items": {"type": "string"},
            "description": (
                "Other names for the target company; treated as the "
                "same entity when matching incidents."
            ),
        },
    },
    "required": ["domain"],
    "additionalProperties": False,
}

_USAGE_FIELDS = ("prompt_tokens", "completion_tokens", "cached_tokens")


def _queries(company: str, domain: str) -> list[str]:
    # Ordered by value: primary-source queries first, so a token budget
    # cuts the lowest-value queries first.
    return [
        f"{company} 8-K Item 1.05 cybersecurity incident",
        f"{domain} breach notice attorney general",
        f"{company} security incident notification",
        f"{company} data breach",
    ]


def _search_instructions(company: str, domain: str) -> str:
    return (
        f"You are looking up publicly disclosed security incidents "
        f"involving {company} ({domain}).\n"
        f"Today's date is {date.today().isoformat()}.\n"
        "Summarize in plain text any security incidents involving the "
        "named company: data breaches, breach notifications, SEC 8-K "
        "Item 1.05 filings, regulator actions, press-covered incidents, "
        "or company statements. Cite every source you rely on.\n"
        "Report only incidents involving the named company; if a result "
        "might be a different company with a similar name, say so.\n"
        "If you found nothing, say that plainly. No results is a valid, "
        "expected outcome."
    )


def _extract_messages(
    texts: list[tuple[str, str]],
    citations: list[tuple[str, str]],
    company: str,
    aliases: list[str],
) -> list[dict[str, str]]:
    types = ", ".join(RESULT_TYPES)
    if aliases:
        alias_rule = (
            f"- The target company ({company}) is also known as: "
            + ", ".join(aliases)
            + ". Treat all of these names as the same entity when "
            "setting entity_match.\n"
        )
    else:
        alias_rule = ""
    summaries = "\n\n".join(
        f"Query: {query}\nSummary:\n{text}" for query, text in texts
    )
    if citations:
        cite_lines = "\n".join(
            f"- {url} ({title})" if title else f"- {url}"
            for url, title in citations
        )
    else:
        cite_lines = "(no citations)"
    return [
        {
            "role": "system",
            "content": (
                "You extract publicly disclosed security incidents "
                "from grounded search summaries.\n"
                f"Today's date is {date.today().isoformat()}.\n"
                "Rules:\n"
                '- Return ONLY JSON of the form {"results": [...]}. '
                "Each result has:\n"
                f"  - type: one of {types}\n"
                "  - date: disclosure date as YYYY-MM-DD\n"
                "  - summary: one or two sentences\n"
                "  - url: copied EXACTLY from the citation list below\n"
                "  - entity_match: exact | probable | uncertain\n"
                "  - match_basis: why you believe this is the same "
                "company\n"
                "- Use only URLs from the citation list below. Never "
                "invent, shorten, or modify a URL.\n"
                + alias_rule
                + "- Prefer primary sources (SEC filings, state AG "
                "notices, regulator actions, company statements) over "
                "press reports. When both describe the same incident, "
                "output the primary source only, and set type from the "
                "source, not the topic. Each distinct incident appears "
                "once.\n"
                "- If the summaries report no incidents involving the "
                'named company, return {"results": []}.'
            ),
        },
        {
            "role": "user",
            "content": (
                f"Search summaries:\n{summaries}\n\n"
                "Citations (the only URLs you may use):\n"
                f"{cite_lines}"
            ),
        },
    ]


def _field(obj: Any, name: str) -> Any:
    if isinstance(obj, dict):
        return obj.get(name)
    return getattr(obj, name, None)


def _extract_final_text_and_citations(
    response: Any,
) -> tuple[str, list[tuple[str, str]]]:
    """Final message text plus ordered unique (url, title) citations.

    Per https://dev.meta.ai/docs/search-grounding, grounded answers
    attach ``url_citation`` annotations to ``output_text`` blocks. The
    docs show a single message item and say nothing about narration as
    separate items, so the LAST message item is the final answer while
    citations union across every message item.
    """
    message_texts: list[str] = []
    citations: list[tuple[str, str]] = []
    seen: set[str] = set()
    for item in _field(response, "output") or []:
        if _field(item, "type") != "message":
            continue
        blocks: list[str] = []
        for block in _field(item, "content") or []:
            if _field(block, "type") != "output_text":
                continue
            blocks.append(_field(block, "text") or "")
            for annotation in _field(block, "annotations") or []:
                if _field(annotation, "type") == "url_citation":
                    url = _field(annotation, "url")
                    if url and url not in seen:
                        seen.add(url)
                        citations.append((url, _field(annotation, "title") or ""))
        message_texts.append("\n".join(blocks))
    text = message_texts[-1] if message_texts else ""
    return text, citations


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


def _empty_usage() -> dict[str, int]:
    return {field: 0 for field in _USAGE_FIELDS}


def _usage_delta(before: dict, after: dict) -> dict[str, int]:
    return {
        field: after.get(field, 0) - before.get(field, 0)
        for field in _USAGE_FIELDS
    }


def _estimated_cost_usd(
    phase1: dict, phase2: dict, searches: int
) -> float:
    prompt = phase1["prompt_tokens"] + phase2["prompt_tokens"]
    cached = phase1["cached_tokens"] + phase2["cached_tokens"]
    completion = (
        phase1["completion_tokens"] + phase2["completion_tokens"]
    )
    billable_input = max(0, prompt - cached)
    return round(
        billable_input / 1e6 * SPARK_USD_PER_MTOK["input"]
        + cached / 1e6 * SPARK_USD_PER_MTOK["cached"]
        + completion / 1e6 * SPARK_USD_PER_MTOK["output"]
        + searches * SEARCH_USD_PER_SEARCH,
        6,
    )


def _cache_path(
    domain: str, company_name: str | None, aliases: list[str]
) -> Path:
    digest = hashlib.sha256(
        f"{domain}{company_name or ''}{''.join(aliases)}".encode("utf-8")
    ).hexdigest()
    return CACHE_DIR / f"{digest}.json"


def _read_cache(path: Path) -> dict | None:
    """Cached output when the entry exists and is within TTL, else None."""
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        age = (
            datetime.now(timezone.utc)
            - datetime.fromisoformat(payload["cached_at"])
        ).total_seconds()
    except (OSError, ValueError, KeyError):
        return None
    if age > CACHE_TTL_SECONDS:
        return None
    output = payload.get("output")
    return output if isinstance(output, dict) else None


def _write_cache(path: Path, output: dict) -> None:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(
                {
                    "cached_at": datetime.now(timezone.utc).isoformat(),
                    "output": output,
                }
            ),
            encoding="utf-8",
        )
    except OSError as exc:
        print(
            f"[search_public_incidents] cache write failed ({exc})",
            file=sys.stderr,
        )


def _max_input_tokens() -> int:
    return int(
        os.getenv(
            "PUBLIC_RECORDS_MAX_INPUT_TOKENS", str(DEFAULT_MAX_INPUT_TOKENS)
        )
    )


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
def collect(
    domain: str,
    company_name: str | None = None,
    force_refresh: bool = False,
    aliases: list[str] | None = None,
) -> dict:
    """Collect public incident disclosures: search, then strict extraction.

    Phase 1 runs at most ``MAX_SEARCHES_PER_RUN`` grounded searches
    (``muse-spark-1.3``, standard mode, minimal search context) against
    the primary ``company_name`` and keeps each final answer text plus
    its citations. Phase 2 extracts ``results[]`` from those texts in a
    single strict-schema call, using only cited URLs and treating
    ``aliases`` as the same entity for ``entity_match``.
    ``disclosed_within_months`` is computed in code.

    Non-error outputs are cached for 7 days; a cache hit returns with
    ``"cached": true`` and makes no API calls. ``force_refresh``
    bypasses the cache read. Phase-1 input tokens are capped by
    ``PUBLIC_RECORDS_MAX_INPUT_TOKENS``: before each query, the run
    stops when cumulative input tokens plus the largest single-query
    input so far would exceed the budget, and the run is ``partial``
    with reason ``token_budget``.

    Status is ``ok`` when extraction succeeded (even with zero
    results), ``partial`` when some phase-1 queries failed or the
    budget cut the run short, and ``error`` when every phase-1 query
    failed or extraction failed.
    """
    company = company_name or domain
    alias_list = list(aliases or [])
    cache_path = _cache_path(domain, company_name, alias_list)
    if not force_refresh:
        cached = _read_cache(cache_path)
        if cached is not None:
            return {**cached, "cached": True}

    client = ModelClient(role="public_records")
    queries = _queries(company, domain)[:MAX_SEARCHES_PER_RUN]
    max_input_tokens = _max_input_tokens()

    usage_before = dict(client.total_usage)
    attempted: list[str] = []
    texts: list[tuple[str, str]] = []
    citations: list[tuple[str, str]] = []
    seen_citations: set[str] = set()
    failed = 0
    phase1_input_tokens = 0
    largest_query_input = 0
    budget_hit = False
    for query in queries:
        if phase1_input_tokens + largest_query_input > max_input_tokens:
            budget_hit = True
            print(
                f"[search_public_incidents] token budget would exceed "
                f"({phase1_input_tokens} + {largest_query_input} > "
                f"{max_input_tokens}); skipping {query!r} and the rest",
                file=sys.stderr,
            )
            break
        attempted.append(query)
        tokens_before = client.total_usage["prompt_tokens"]
        try:
            response = client.responses_search(
                query,
                instructions=_search_instructions(company, domain),
                # Minimal retrieved context: lowest token usage; the
                # docs' most restrictive fetch option. Citations are
                # annotations on the answer text, unaffected.
                tools=[
                    {"type": "web_search", "search_context_size": "low"}
                ],
            )
        except Exception as exc:  # one bad query must not kill the run
            failed += 1
            print(
                f"[search_public_incidents] query failed: {query} ({exc})",
                file=sys.stderr,
            )
            continue
        query_input = client.total_usage["prompt_tokens"] - tokens_before
        phase1_input_tokens += query_input
        largest_query_input = max(largest_query_input, query_input)
        text, cites = _extract_final_text_and_citations(response)
        texts.append((query, text))
        for url, title in cites:
            if url not in seen_citations:
                seen_citations.add(url)
                citations.append((url, title))
    phase1_usage = _usage_delta(usage_before, client.total_usage)

    def _base(status: str, phase2_usage: dict) -> dict:
        return {
            "collection_method": COLLECTION_METHOD,
            "status": status,
            "reason": "token_budget" if budget_hit else None,
            "cached": False,
            "queries_run": attempted,
            "dropped_uncited": 0,
            "dropped_prohibited_source": 0,
            "results": [],
            "disclosed_within_months": None,
            "usage": {
                "searches": len(attempted),
                "phase1_search": phase1_usage,
                "phase2_extract": phase2_usage,
                "estimated_cost_usd": _estimated_cost_usd(
                    phase1_usage, phase2_usage, len(attempted)
                ),
            },
        }

    if failed == len(attempted):
        return _base("error", _empty_usage())

    extract_before = dict(client.total_usage)
    try:
        extracted = client.chat_json(
            _extract_messages(texts, citations, company, alias_list),
            schema=RESULTS_SCHEMA,
            schema_name="incident_results",
        )
        found = extracted["results"]
    except Exception as exc:
        print(
            f"[search_public_incidents] extraction failed ({exc})",
            file=sys.stderr,
        )
        return _base("error", _usage_delta(extract_before, client.total_usage))
    phase2_usage = _usage_delta(extract_before, client.total_usage)

    cited = {_normalize_url(url) for url, _ in citations}
    raw_cited = {url for url, _ in citations}
    results: list[dict] = []
    seen: set[str] = set()
    dropped_uncited = 0
    dropped_prohibited = 0
    for result in found:
        try:
            date.fromisoformat(result["date"])
        except (ValueError, TypeError, KeyError):
            _log_drop("dropped_invalid_date", str(result.get("url")))
            continue
        url = _normalize_url(result["url"])
        if url not in cited and result["url"] not in raw_cited:
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
    status = "partial" if (failed or budget_hit) else "ok"
    out = _base(status, phase2_usage)
    out["dropped_uncited"] = dropped_uncited
    out["dropped_prohibited_source"] = dropped_prohibited
    out["results"] = results
    out["disclosed_within_months"] = (
        min(_months_since(day, today) for day in counted_dates)
        if counted_dates
        else None
    )
    if status != "error":
        _write_cache(cache_path, out)
    return out
