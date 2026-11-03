"""Orchestrator model loop: tools, coverage, post-processing.

``run_digest`` drives Muse Wonder through the collector tools, enforces
a code-side coverage check with one resubmission, then runs the
deterministic engine, null-stripping, and per-finding validation.
Everything lands in ``eval/runs/<digest_id>/``: ``trace.jsonl``,
``collector_outputs.json``, ``findings.json``.
"""

from __future__ import annotations

import copy
import json
import os
import re
import time
from concurrent.futures import Future, ThreadPoolExecutor
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any

import jsonschema
import yaml

import pe_risk_key.collectors as collectors
from pe_risk_key.agent.context import RunContext, new_digest_id
from pe_risk_key.analyzers.interview import (
    extract_claims,
    transcribe_interview,
)
from pe_risk_key.analyzers.soc2 import (
    SOC2Result,
    analyze_soc2,
    normalize_quote,
)
from pe_risk_key.agent.prompts import (
    coverage_followup,
    system_prompt,
    target_brief,
)
from pe_risk_key.engine.crosscheck import (
    crosscheck_claims,
    merge_contradictions,
)
from pe_risk_key.engine.narrative import (
    generate_narrative,
    render_ic_memo,
    required_recommendation_types,
)
from pe_risk_key.engine.rules import apply_rule_constraints
from pe_risk_key.engine.scoring import score_digest
from pe_risk_key.providers import (
    SPARK_MODEL,
    STANDARD_PROVIDER,
    VOICE_MODEL,
    WONDER_MODEL,
    Mode,
    ModelClient,
)
from pe_risk_key.validate import validate_digest
from pe_risk_key.schemas import (
    strict_subschema,
    strip_nullable_optionals,
    subschema,
)

ROOT = Path(__file__).resolve().parents[3]
RUNS_DIR = ROOT / "eval" / "runs"
SCORING_PATH = ROOT / "scoring.yaml"

MAX_TURNS = 6
SUBMIT_TOOL = "submit_findings"

# Muse Wonder Standard prices per 1M tokens, per
# https://dev.meta.ai/docs/pricing-rate-limits.
PRICE_PER_M = {"input": 4.0, "cached": 0.20, "output": 20.0}


def submit_tool_definition() -> dict[str, Any]:
    """Terminal tool: the model's complete findings list, strict-schema."""
    return {
        "type": "function",
        "function": {
            "name": SUBMIT_TOOL,
            "description": (
                "Submit the complete findings list once every "
                "collector has returned. Call exactly once."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "findings": {
                        "type": "array",
                        "items": strict_subschema("finding"),
                    }
                },
                "required": ["findings"],
                "additionalProperties": False,
            },
        },
    }


def agent_tools() -> list[dict[str, Any]]:
    """Collector tools plus the terminal submit_findings tool."""
    return [*collectors.tool_definitions(), submit_tool_definition()]


def collector_names() -> list[str]:
    """Registry tool names in definition order (coverage set)."""
    return [
        definition["function"]["name"]
        for definition in collectors.tool_definitions()
    ]


def _message_text(message: Any) -> str:
    if isinstance(message, dict):
        return message.get("content") or ""
    return getattr(message, "content", None) or ""


def _message_tool_calls(message: Any) -> list[dict[str, Any]]:
    """Normalize SDK/dict tool calls to ``{id, name, arguments}`` dicts."""
    if isinstance(message, dict):
        raw_calls = message.get("tool_calls") or []
    else:
        raw_calls = getattr(message, "tool_calls", None) or []
    calls: list[dict[str, Any]] = []
    for raw in raw_calls:
        if isinstance(raw, dict):
            function = raw.get("function", {})
            name = function.get("name")
            arguments = function.get("arguments", {})
            call_id = raw.get("id")
        else:
            function = getattr(raw, "function", None)
            if isinstance(function, dict):
                name = function.get("name")
                arguments = function.get("arguments", {})
            else:
                name = getattr(function, "name", None)
                arguments = getattr(function, "arguments", {})
            call_id = getattr(raw, "id", None)
        if isinstance(arguments, str):
            try:
                arguments = json.loads(arguments)
            except json.JSONDecodeError:
                arguments = {}
        calls.append(
            {
                "id": call_id or f"call_{len(calls)}",
                "name": name,
                "arguments": arguments
                if isinstance(arguments, dict)
                else {},
            }
        )
    return calls


def _usage_of(response: Any) -> dict[str, int]:
    usage = getattr(response, "usage", None)
    if usage is None and isinstance(response, dict):
        usage = response.get("usage")
    details = getattr(usage, "prompt_tokens_details", None)
    if isinstance(usage, dict):
        prompt = usage.get("prompt_tokens", 0) or 0
        completion = usage.get("completion_tokens", 0) or 0
        cached = (usage.get("prompt_tokens_details") or {}).get(
            "cached_tokens", 0
        ) or 0
    else:
        prompt = getattr(usage, "prompt_tokens", 0) or 0
        completion = getattr(usage, "completion_tokens", 0) or 0
        cached = getattr(details, "cached_tokens", 0) or 0
    return {
        "prompt_tokens": prompt,
        "completion_tokens": completion,
        "cached_tokens": cached,
    }


def estimate_cost(usage: dict[str, int]) -> float:
    """Wonder Standard cost for accumulated token usage."""
    billable_input = max(0, usage["prompt_tokens"] - usage["cached_tokens"])
    return (
        billable_input * PRICE_PER_M["input"]
        + usage["cached_tokens"] * PRICE_PER_M["cached"]
        + usage["completion_tokens"] * PRICE_PER_M["output"]
    ) / 1_000_000


def merge_usage_breakdown(
    components: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    """Combine per-component usage dicts into a breakdown plus totals.

    Each component reports its token counters and estimated_cost_usd;
    transcription reports audio_hours instead of tokens. New pipeline
    stages (transcription, claim_extraction, crosscheck, narrative) add
    entries under their own names; totals sum the shared keys.
    """
    breakdown = {name: dict(values) for name, values in components.items()}
    totals: dict[str, Any] = {
        "prompt_tokens": 0,
        "completion_tokens": 0,
        "cached_tokens": 0,
        "estimated_cost_usd": 0.0,
    }
    for values in breakdown.values():
        for key in totals:
            totals[key] += values.get(key, 0)
    return {"components": breakdown, **totals}


def _assistant_message(
    text: str, calls: list[dict[str, Any]]
) -> dict[str, Any]:
    message: dict[str, Any] = {"role": "assistant", "content": text or None}
    if calls:
        message["tool_calls"] = [
            {
                "id": call["id"],
                "type": "function",
                "function": {
                    "name": call["name"],
                    "arguments": json.dumps(call["arguments"]),
                },
            }
            for call in calls
        ]
    return message


def _execute_calls(
    pool: ThreadPoolExecutor,
    ctx: RunContext,
    calls: list[dict[str, Any]],
    group: int,
) -> list[tuple[dict[str, Any], dict]]:
    """Run one turn's tool calls concurrently; results in call order."""
    worker = lambda call: (
        call,
        ctx.run_tool(call["name"], call["arguments"], group),
    )
    return list(pool.map(worker, calls))


def _parse_submission(call: dict[str, Any]) -> list[Any]:
    findings = call["arguments"].get("findings", [])
    return findings if isinstance(findings, list) else []


_FINDING_ID_RE = re.compile(r"^F-(\d+)$")
_EVIDENCE_ID_RE = re.compile(r"^E-(\d+)$")


def _id_base(ids: list[str | None], pattern: re.Pattern, count: int) -> int:
    numbered = [
        int(match.group(1))
        for raw in ids
        if (match := pattern.match(raw or ""))
    ]
    return max([count, *numbered])


def _renumber_soc2(
    outside_findings: list[dict], soc2: SOC2Result
) -> tuple[list[dict], list[dict], dict[str, Any]]:
    """Renumber SOC 2 findings/evidence after the outside-in IDs.

    Returns (findings, evidence_pool, soc2_analysis) with new IDs and
    consistent cross-references; inputs are not mutated.
    """
    finding_base = _id_base(
        [f.get("finding_id") for f in outside_findings],
        _FINDING_ID_RE,
        len(outside_findings),
    )
    outside_evidence = [
        e.get("evidence_id")
        for f in outside_findings
        for e in f.get("evidence", [])
    ]
    evidence_base = _id_base(
        outside_evidence, _EVIDENCE_ID_RE, len(outside_evidence)
    )
    finding_map = {
        f["finding_id"]: f"F-{finding_base + index + 1:03d}"
        for index, f in enumerate(soc2.findings)
    }
    evidence_map = {
        e["evidence_id"]: f"E-{evidence_base + index + 1:03d}"
        for index, e in enumerate(soc2.evidence_pool)
    }
    findings = [
        {
            **finding,
            "finding_id": finding_map[finding["finding_id"]],
            "evidence": [
                {
                    **item,
                    "evidence_id": evidence_map.get(
                        item["evidence_id"], item["evidence_id"]
                    ),
                }
                for item in finding["evidence"]
            ],
        }
        for finding in soc2.findings
    ]
    pool = [
        {**item, "evidence_id": evidence_map[item["evidence_id"]]}
        for item in soc2.evidence_pool
    ]
    analysis = copy.deepcopy(soc2.soc2_analysis)
    for exception in analysis.get("exceptions", []):
        if exception.get("finding_id") in finding_map:
            exception["finding_id"] = finding_map[exception["finding_id"]]
    return findings, pool, analysis


def _run_soc2_analysis(
    ctx: RunContext, soc2_path: str | Path, doc_id: str, as_of: date | str
) -> SOC2Result:
    ctx.trace.event("document_analysis_start", doc_id=doc_id)
    started = time.monotonic()
    result = analyze_soc2(soc2_path, doc_id, as_of)
    duration_ms = round((time.monotonic() - started) * 1000, 1)
    ctx.trace.event(
        "document_analysis_end",
        doc_id=doc_id,
        duration_ms=duration_ms,
        tokens={
            key: result.usage.get(key, 0)
            for key in ("prompt_tokens", "completion_tokens", "cached_tokens")
        },
        finding_count=len(result.findings),
    )
    return result


_REPORT_TYPE_TO_DOC = {"type1": "soc2_type1", "type2": "soc2_type2"}


def dedupe_evidence_pool(
    findings: list[dict[str, Any]], evidence_pool: list[dict[str, Any]]
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Drop pool items duplicating an earlier id's excerpt and locator.

    Matching uses the normalized excerpt plus the exact locator; the
    first id wins and findings' evidence refs remap to it. Inputs are
    not mutated.
    """
    seen: dict[tuple[str, Any], str] = {}
    remap: dict[str, str] = {}
    deduped: list[dict[str, Any]] = []
    for item in evidence_pool:
        key = (
            normalize_quote(item.get("excerpt", "") or ""),
            item.get("locator"),
        )
        if key in seen:
            remap[item["evidence_id"]] = seen[key]
        else:
            seen[key] = item["evidence_id"]
            deduped.append(item)
    if not remap:
        return findings, evidence_pool
    merged = copy.deepcopy(findings)
    for finding in merged:
        for item in finding.get("evidence", []):
            if item.get("evidence_id") in remap:
                item["evidence_id"] = remap[item["evidence_id"]]
    return merged, deduped


def _verdict_excerpt(
    refs: list[str],
    finding_by_id: dict[str, dict[str, Any]],
    evidence_pool: list[dict[str, Any]],
) -> str:
    """First resolvable evidence text for cross-check refs."""
    pool = {
        item.get("evidence_id"): item.get("excerpt", "")
        for item in evidence_pool
    }
    for ref in refs:
        if ref in finding_by_id:
            evidence = finding_by_id[ref].get("evidence", [])
            if evidence:
                return evidence[0].get("excerpt", "")
            return finding_by_id[ref].get("title", "")
        if ref in pool:
            return pool[ref]
    return ""


def _model_invoked(tool_name: str, collector_outputs: dict[str, Any]) -> bool:
    """Whether a collector step invoked its model in this run.

    Fixture-served (DEMO_MODE), cache-served, and never-ran steps did
    not invoke anything, so they contribute no provider entry.
    """
    if os.getenv("DEMO_MODE") == "1":
        return False
    output = collector_outputs.get(tool_name)
    if not isinstance(output, dict):
        return False
    if output.get("cached") is True:
        return False
    return output.get("status") != "error" or "usage" in output


def _run_interview(
    ctx: RunContext,
    interview_path: str | Path,
    interview_id: str,
    speaker_names: list[str] | None,
    target_speakers: list[str],
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Transcribe then extract claims; returns (transcript, claims)."""
    ctx.trace.event("transcription_start", interview_id=interview_id)
    started = time.monotonic()
    transcript = transcribe_interview(
        interview_path, interview_id, speaker_names=speaker_names
    )
    duration_ms = round((time.monotonic() - started) * 1000, 1)
    ctx.trace.event(
        "transcription_end",
        interview_id=interview_id,
        duration_ms=duration_ms,
        audio_seconds=transcript["duration_seconds"],
        cached=transcript["cached"],
        estimated_cost_usd=transcript["estimated_cost_usd"],
    )
    claims_result = extract_claims(transcript, target_speakers)
    ctx.trace.event(
        "claims_extracted",
        interview_id=interview_id,
        claim_count=len(claims_result["claims"]),
        dropped_unquoted=len(claims_result["dropped_unquoted"]),
        dropped_not_target=len(claims_result["dropped_not_target"]),
        tokens={
            key: claims_result["usage"].get(key, 0)
            for key in ("prompt_tokens", "completion_tokens", "cached_tokens")
        },
    )
    return transcript, claims_result


def _assemble_digest(
    *,
    digest_id: str,
    domain: str,
    company_name: str,
    employee_band: str,
    revenue_band: str,
    industry: str | None,
    mode: str,
    client: ModelClient,
    collector_outputs: dict[str, Any],
    findings: list[dict],
    scored: dict[str, Any],
    trace_path: str,
    soc2_result: SOC2Result | None = None,
    soc2_analysis: dict[str, Any] | None = None,
    contradictions: list[dict[str, Any]] | None = None,
    interview_entry: dict[str, Any] | None = None,
    ran_crosscheck: bool = False,
    narrative: dict[str, Any] | None = None,
    deal_recommendations: list[dict[str, Any]] | None = None,
    transcript_cached: bool = False,
    include_narrative_provider: bool = True,
) -> dict[str, Any]:
    """Build the full digest dict per digest.schema.json."""
    target: dict[str, Any] = {
        "name": company_name,
        "domain": domain,
        "revenue_band": revenue_band,
        "employee_band": employee_band,
    }
    if industry is not None:
        target["industry"] = industry
    providers = [
        {
            "role": "orchestrator",
            "provider": client.provider,
            "model": client.model,
        }
    ]
    if _model_invoked("search_public_incidents", collector_outputs):
        providers.append(
            {
                "role": "public_records",
                "provider": STANDARD_PROVIDER,
                "model": SPARK_MODEL,
            }
        )
    documents: list[dict[str, Any]] = []
    if soc2_result is not None:
        providers.append(
            {
                "role": "document_analysis",
                "provider": STANDARD_PROVIDER,
                "model": WONDER_MODEL,
            }
        )
        documents.append(
            {
                "doc_id": soc2_result.doc_id,
                "type": _REPORT_TYPE_TO_DOC.get(
                    soc2_result.soc2_analysis["report_type"], "other"
                ),
                "filename": soc2_result.filename,
                "sha256": soc2_result.sha256,
            }
        )
    interviews: list[dict[str, Any]] = []
    if interview_entry is not None:
        interviews.append(interview_entry)
        if not transcript_cached:
            providers.append(
                {
                    "role": "transcription",
                    "provider": STANDARD_PROVIDER,
                    "model": VOICE_MODEL,
                }
            )
        providers.append(
            {
                "role": "claim_extraction",
                "provider": STANDARD_PROVIDER,
                "model": WONDER_MODEL,
            }
        )
        if ran_crosscheck:
            providers.append(
                {
                    "role": "crosscheck",
                    "provider": STANDARD_PROVIDER,
                    "model": WONDER_MODEL,
                }
            )
    if include_narrative_provider:
        providers.append(
            {
                "role": "narrative",
                "provider": STANDARD_PROVIDER,
                "model": WONDER_MODEL,
            }
        )
    digest = {
        "schema_version": "1.0.0",
        "digest_id": digest_id,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "target": target,
        "mode": {
            "confidential": mode == "confidential",
            "demo": os.getenv("DEMO_MODE") == "1",
            "providers": providers,
        },
        "inputs": {
            "domain_scan": True,
            "documents": documents,
            "interviews": interviews,
            **(
                {"served_from_fixture": True}
                if os.getenv("DEMO_MODE") == "1"
                else {}
            ),
        },
        "overall": scored["overall"],
        "function_scores": scored["function_scores"],
        "findings": findings,
        "contradictions": contradictions if contradictions is not None else [],
        "remediation_plan": scored["remediation_plan"],
        "deal_recommendations": deal_recommendations
        if deal_recommendations is not None
        else [],
        "narrative": narrative
        if narrative is not None
        else {"executive_summary": "Narrative pending."},
        "limitations": scored["limitations"],
        "trace_ref": trace_path,
    }
    if soc2_analysis is not None:
        digest["soc2_analysis"] = soc2_analysis
    return digest


def run_digest(
    domain: str,
    company_name: str,
    employee_band: str,
    revenue_band: str,
    aliases: list[str] | None = None,
    industry: str | None = None,
    mode: Mode = "standard",
    soc2_path: str | Path | None = None,
    as_of: date | str | None = None,
    interview_path: str | Path | None = None,
    speaker_names: list[str] | None = None,
    target_speakers: list[str] | None = None,
    digest_id: str | None = None,
) -> dict[str, Any]:
    """Run the orchestrator end to end; returns the digest result.

    When ``soc2_path`` is given, the SOC 2 analyzer runs concurrently
    with the model loop's first turn and its findings merge into the
    digest after the outside-in findings are finalized. ``as_of``
    defaults to today. When ``interview_path`` is given, transcription
    and claim extraction run concurrently too, and cross-check runs
    after all findings are merged.

    Returns ``{digest_id, findings, collector_outputs, adjustments,
    trace_path, usage, catalog}`` and writes ``trace.jsonl``,
    ``collector_outputs.json``, ``findings.json``,
    ``evidence_pool.json``, ``claims.json`` (interview runs),
    ``digest.json``, and ``ic_memo.md`` under ``eval/runs/<digest_id>/``.
    The final step drafts the IC narrative from the scored digest.
    """
    alias_list = list(aliases or [])
    if digest_id is None:
        digest_id = new_digest_id()
    elif not re.fullmatch(r"dg_[a-z0-9]{12}", digest_id):
        raise ValueError(f"Invalid digest_id: {digest_id!r}.")
    run_dir = RUNS_DIR / digest_id
    run_dir.mkdir(parents=True, exist_ok=True)
    ctx = RunContext(
        digest_id=digest_id,
        domain=domain,
        company_name=company_name,
        aliases=alias_list,
        run_dir=run_dir,
    )
    ctx.trace.event(
        "run_start",
        domain=domain,
        company_name=company_name,
        aliases=alias_list,
        employee_band=employee_band,
        revenue_band=revenue_band,
        industry=industry,
        mode=mode,
    )
    scoring = yaml.safe_load(SCORING_PATH.read_text(encoding="utf-8"))
    rules_yaml = yaml.safe_dump({"rules": scoring["rules"]}, sort_keys=False)
    tools = agent_tools()
    messages: list[dict[str, Any]] = [
        {"role": "system", "content": system_prompt()},
        {
            "role": "user",
            "content": target_brief(
                domain,
                company_name,
                alias_list,
                employee_band,
                revenue_band,
                industry,
                rules_yaml,
            ),
        },
    ]
    client = ModelClient(role="orchestrator", mode=mode)
    submitted: list[Any] | None = None
    plan_traced = False
    group = 0
    pool = ThreadPoolExecutor(max_workers=8)
    soc2_future: Future[SOC2Result] | None = None
    soc2_doc_id: str | None = None
    if soc2_path is not None:
        soc2_doc_id = "doc_" + digest_id[3:]
        ctx.trace.event("stage", stage="analyzing_documents")
        soc2_future = pool.submit(
            _run_soc2_analysis,
            ctx,
            soc2_path,
            soc2_doc_id,
            as_of or date.today(),
        )
    interview_future: Future[tuple[dict[str, Any], dict[str, Any]]] | None = (
        None
    )
    interview_id: str | None = None
    if interview_path is not None:
        interview_id = "int_" + digest_id[3:]
        ctx.trace.event("stage", stage="transcribing")
        interview_future = pool.submit(
            _run_interview,
            ctx,
            interview_path,
            interview_id,
            speaker_names,
            list(target_speakers or []),
        )
    ctx.trace.event("stage", stage="collecting")
    try:
        for turn in range(MAX_TURNS):
            ctx.trace.event("model_turn_start", turn=turn)
            response = client.chat(
                messages, reasoning_effort="medium", tools=tools
            )
            tokens = _usage_of(response)
            ctx.trace.event("model_turn_end", turn=turn, tokens=tokens)
            message = response.choices[0].message
            text = _message_text(message)
            calls = _message_tool_calls(message)
            if text and not plan_traced:
                ctx.trace.event("plan", text=text)
                plan_traced = True
            messages.append(_assistant_message(text, calls))
            regular = [c for c in calls if c["name"] != SUBMIT_TOOL]
            submit = next(
                (c for c in calls if c["name"] == SUBMIT_TOOL), None
            )
            if regular:
                group += 1
                for call, output in _execute_calls(pool, ctx, regular, group):
                    messages.append(
                        {
                            "role": "tool",
                            "tool_call_id": call["id"],
                            "content": json.dumps(output),
                        }
                    )
            if submit is not None:
                submitted = _parse_submission(submit)
                ctx.trace.event(
                    "submit_findings", turn=turn, count=len(submitted)
                )
                messages.append(
                    {
                        "role": "tool",
                        "tool_call_id": submit["id"],
                        "content": json.dumps({"received": len(submitted)}),
                    }
                )
                break

        if submitted is not None:
            missing = [
                name for name in collector_names() if name not in ctx.outputs
            ]
            if missing:
                group += 1
                results = _execute_calls(
                    pool,
                    ctx,
                    [
                        {"id": f"coverage_{i}", "name": name, "arguments": {}}
                        for i, name in enumerate(missing)
                    ],
                    group,
                )
                gap_outputs = {
                    call["name"]: output for call, output in results
                }
                ctx.trace.event("coverage_gap", missing=missing)
                messages.append(
                    {
                        "role": "user",
                        "content": coverage_followup(missing, gap_outputs),
                    }
                )
                ctx.trace.event("model_turn_start", turn="resubmission")
                response = client.chat(
                    messages, reasoning_effort="medium", tools=tools
                )
                tokens = _usage_of(response)
                ctx.trace.event(
                    "model_turn_end", turn="resubmission", tokens=tokens
                )
                message = response.choices[0].message
                resubmit_calls = _message_tool_calls(message)
                messages.append(
                    _assistant_message(_message_text(message), resubmit_calls)
                )
                regular = [
                    c for c in resubmit_calls if c["name"] != SUBMIT_TOOL
                ]
                submit = next(
                    (c for c in resubmit_calls if c["name"] == SUBMIT_TOOL),
                    None,
                )
                if regular:
                    group += 1
                    for call, output in _execute_calls(
                        pool, ctx, regular, group
                    ):
                        messages.append(
                            {
                                "role": "tool",
                                "tool_call_id": call["id"],
                                "content": json.dumps(output),
                            }
                        )
                if submit is not None:
                    submitted = _parse_submission(submit)
                    ctx.trace.event(
                        "submit_findings",
                        turn="resubmission",
                        count=len(submitted),
                    )
    finally:
        pool.shutdown(wait=True)

    soc2_result: SOC2Result | None = None
    if soc2_future is not None:
        try:
            soc2_result = soc2_future.result()
        except Exception as exc:
            ctx.trace.event(
                "document_analysis_end",
                doc_id=soc2_doc_id,
                status="error",
                error=f"{type(exc).__name__}: {exc}",
            )
            raise

    interview_data: tuple[dict[str, Any], dict[str, Any]] | None = None
    if interview_future is not None:
        try:
            interview_data = interview_future.result()
        except Exception as exc:
            ctx.trace.event(
                "interview_error",
                interview_id=interview_id,
                error=f"{type(exc).__name__}: {exc}",
            )
            raise

    findings_in = submitted if submitted is not None else []
    constrained, adjustments = apply_rule_constraints(
        findings_in, scoring, employee_band
    )
    for adjustment in adjustments:
        ctx.trace.event("engine_adjustment", **adjustment)
    validator = jsonschema.Draft202012Validator(subschema("finding"))
    findings: list[dict] = []
    for finding in constrained:
        finding_id = (
            finding.get("finding_id", "?")
            if isinstance(finding, dict)
            else "?"
        )
        if not isinstance(finding, dict):
            ctx.trace.event(
                "validation_error",
                finding_id=finding_id,
                errors=["finding is not an object"],
            )
            continue
        stripped = strip_nullable_optionals(finding, "finding")
        errors = sorted(
            validator.iter_errors(stripped), key=lambda e: e.json_path
        )
        if errors:
            ctx.trace.event(
                "validation_error",
                finding_id=finding_id,
                errors=[f"{e.json_path}: {e.message}" for e in errors],
            )
            continue
        findings.append(stripped)

    (run_dir / "collector_outputs.json").write_text(
        json.dumps(ctx.outputs, indent=2), encoding="utf-8"
    )
    (run_dir / "findings.json").write_text(
        json.dumps({"findings": findings}, indent=2), encoding="utf-8"
    )

    soc2_analysis: dict[str, Any] | None = None
    evidence_pool = [
        {**item}
        for finding in findings
        for item in finding.get("evidence", [])
    ]
    merged = list(findings)
    if soc2_result is not None:
        soc2_findings, soc2_pool, soc2_analysis = _renumber_soc2(
            findings, soc2_result
        )
        merged.extend(soc2_findings)
        evidence_pool.extend(soc2_pool)
    merged, evidence_pool = dedupe_evidence_pool(merged, evidence_pool)
    (run_dir / "evidence_pool.json").write_text(
        json.dumps({"evidence": evidence_pool}, indent=2), encoding="utf-8"
    )

    contradictions: list[dict[str, Any]] = []
    crosscheck_result: dict[str, Any] | None = None
    interview_entry: dict[str, Any] | None = None
    if interview_data is not None:
        transcript, claims_result = interview_data
        interview_entry = {
            "interview_id": interview_id,
            "filename": Path(interview_path).name,
            "sha256": transcript["sha256"],
            "duration_seconds": int(round(transcript["duration_seconds"])),
        }
        if speaker_names:
            interview_entry["speakers"] = list(speaker_names)
        claims = claims_result["claims"]
        (run_dir / "claims.json").write_text(
            json.dumps({"claims": claims}, indent=2), encoding="utf-8"
        )
        if claims:
            ctx.trace.event("stage", stage="cross_checking")
            crosscheck_result = crosscheck_claims(
                claims, merged, evidence_pool
            )
            pre_merge = crosscheck_result["contradictions"]
            contradictions, members = merge_contradictions(
                pre_merge, claims, merged
            )
            ctx.trace.event(
                "claims_merged", before=len(pre_merge), after=len(contradictions)
            )
            finding_by_id = {
                finding["finding_id"]: finding for finding in merged
            }
            for indices, contradiction in zip(members, contradictions):
                ctx.trace.event(
                    "crosscheck_verdict",
                    claim_index=indices[0] if indices else None,
                    contradiction_id=contradiction["contradiction_id"],
                    text=contradiction["claim"]["text"],
                    verdict=contradiction["verdict"],
                    severity=contradiction["severity"],
                    refs=contradiction["evidence_refs"],
                    excerpt=_verdict_excerpt(
                        contradiction["evidence_refs"],
                        finding_by_id,
                        evidence_pool,
                    ),
                )

    ctx.trace.event("stage", stage="scoring")
    scored = score_digest(
        merged,
        contradictions,
        scoring,
        domain_scan=True,
        has_soc2=soc2_analysis is not None,
        has_interview=interview_data is not None,
        soc2_opinion=soc2_analysis["opinion"] if soc2_analysis else None,
        revenue_band=revenue_band,
    )
    ctx.trace.event(
        "scoring_complete",
        overall=scored["overall"],
        function_scores=scored["function_scores"],
    )
    digest_args: dict[str, Any] = dict(
        digest_id=digest_id,
        domain=domain,
        company_name=company_name,
        employee_band=employee_band,
        revenue_band=revenue_band,
        industry=industry,
        mode=mode,
        client=client,
        collector_outputs=ctx.outputs,
        findings=merged,
        scored=scored,
        trace_path=str(run_dir / "trace.jsonl"),
        soc2_result=soc2_result,
        soc2_analysis=soc2_analysis,
        contradictions=contradictions,
        interview_entry=interview_entry,
        ran_crosscheck=crosscheck_result is not None,
        transcript_cached=bool(
            interview_data is not None and interview_data[0].get("cached")
        ),
    )
    ctx.trace.event(
        "digest_preview",
        digest=_assemble_digest(
            **digest_args, include_narrative_provider=False
        ),
    )
    soc2_summary = None
    if soc2_analysis is not None:
        soc2_summary = {
            "opinion": soc2_analysis["opinion"],
            "period_start": soc2_analysis["period_start"],
            "period_end": soc2_analysis["period_end"],
            "exception_count": len(soc2_analysis["exceptions"]),
            "bridge_gap_days": soc2_analysis["bridge_gap_days"],
        }
    ctx.trace.event("stage", stage="writing_narrative")
    narrative_started = time.monotonic()
    narrative_result = generate_narrative(
        {
            "target": {
                "name": company_name,
                "domain": domain,
                "employee_band": employee_band,
                "revenue_band": revenue_band,
                "industry": industry,
            },
            "overall": scored["overall"],
            "function_scores": scored["function_scores"],
            "findings": merged,
            "contradictions": contradictions,
            "remediation_plan": scored["remediation_plan"],
            "soc2_summary": soc2_summary,
            "limitations": scored["limitations"],
            "required_recommendations": required_recommendation_types(
                findings=merged,
                caps_applied=scored["overall"]["rating_caps_applied"],
                remediation_plan=scored["remediation_plan"],
                revenue_midpoint_usd=scoring["revenue_midpoint_usd"][
                    revenue_band
                ],
                soc2_analysis=soc2_analysis,
            ),
        }
    )
    if not narrative_result["valid"]:
        scored["limitations"].append("narrative validation incomplete")
        ctx.trace.event(
            "narrative_validation_failed",
            errors=narrative_result["validation_errors"],
        )
    narrative_duration_ms = round(
        (time.monotonic() - narrative_started) * 1000, 1
    )
    attempts = 2 if narrative_result["regenerated"] else 1
    ctx.trace.event(
        "narrative_complete",
        valid=narrative_result["valid"],
        regenerated=narrative_result["regenerated"],
        attempts=attempts,
        duration_ms=narrative_duration_ms,
        usage=narrative_result["usage"],
        **(
            {
                "first_attempt_errors": narrative_result[
                    "first_attempt_errors"
                ]
            }
            if attempts == 2
            else {}
        ),
    )
    digest = _assemble_digest(
        **digest_args,
        narrative=narrative_result["narrative"],
        deal_recommendations=narrative_result["deal_recommendations"],
    )
    digest_errors = validate_digest(digest, evidence_pool=evidence_pool)
    (run_dir / "digest.json").write_text(
        json.dumps(digest, indent=2), encoding="utf-8"
    )
    ctx.trace.event(
        "digest_validated",
        valid=not digest_errors,
        errors=digest_errors,
    )
    if digest_errors:
        raise ValueError(
            "Assembled digest failed validation: " + "; ".join(digest_errors)
        )
    ctx.trace.event("digest_final", digest=digest)
    components: dict[str, dict[str, Any]] = {
        "orchestrator": {
            **client.total_usage,
            "estimated_cost_usd": estimate_cost(client.total_usage),
        }
    }
    if soc2_result is not None:
        components["document_analysis"] = {
            **soc2_result.usage,
            "estimated_cost_usd": soc2_result.estimated_cost_usd,
        }
    if interview_data is not None:
        transcript, claims_result = interview_data
        components["transcription"] = {
            **transcript["usage"],
            "estimated_cost_usd": transcript["estimated_cost_usd"],
        }
        components["claim_extraction"] = {
            **claims_result["usage"],
            "estimated_cost_usd": claims_result["estimated_cost_usd"],
        }
    if crosscheck_result is not None:
        components["crosscheck"] = {
            **crosscheck_result["usage"],
            "estimated_cost_usd": crosscheck_result["estimated_cost_usd"],
        }
    components["narrative"] = {
        **narrative_result["usage"],
        "estimated_cost_usd": narrative_result["estimated_cost_usd"],
    }
    usage = merge_usage_breakdown(components)
    ctx.trace.event("stage", stage="complete")
    (run_dir / "ic_memo.md").write_text(
        render_ic_memo(
            digest,
            evidence_pool=evidence_pool,
            run_cost_usd=usage["estimated_cost_usd"],
        ),
        encoding="utf-8",
    )
    ctx.trace.event("run_end", usage=usage)
    return {
        "digest_id": digest_id,
        "findings": merged,
        "collector_outputs": ctx.outputs,
        "adjustments": adjustments,
        "trace_path": str(run_dir / "trace.jsonl"),
        "usage": usage,
        "catalog": (
            crosscheck_result["catalog"]
            if crosscheck_result is not None
            else None
        ),
    }
