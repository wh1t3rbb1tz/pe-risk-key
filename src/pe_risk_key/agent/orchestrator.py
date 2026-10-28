"""Orchestrator model loop: tools, coverage, post-processing.

``run_digest`` drives Muse Wonder through the collector tools, enforces
a code-side coverage check with one resubmission, then runs the
deterministic engine, null-stripping, and per-finding validation.
Everything lands in ``eval/runs/<digest_id>/``: ``trace.jsonl``,
``collector_outputs.json``, ``findings.json``.
"""

from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

import jsonschema
import yaml

import pe_risk_key.collectors as collectors
from pe_risk_key.agent.context import RunContext, new_digest_id
from pe_risk_key.agent.prompts import (
    coverage_followup,
    system_prompt,
    target_brief,
)
from pe_risk_key.engine.rules import apply_rule_constraints
from pe_risk_key.providers import Mode, ModelClient
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


def run_digest(
    domain: str,
    company_name: str,
    employee_band: str,
    revenue_band: str,
    aliases: list[str] | None = None,
    industry: str | None = None,
    mode: Mode = "standard",
) -> dict[str, Any]:
    """Run the orchestrator end to end; returns the digest result.

    Returns ``{digest_id, findings, collector_outputs, adjustments,
    trace_path, usage}`` and writes ``trace.jsonl``,
    ``collector_outputs.json``, and ``findings.json`` under
    ``eval/runs/<digest_id>/``.
    """
    alias_list = list(aliases or [])
    digest_id = new_digest_id()
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
    usage = {
        **client.total_usage,
        "estimated_cost_usd": estimate_cost(client.total_usage),
    }
    ctx.trace.event("run_end", usage=usage)
    return {
        "digest_id": digest_id,
        "findings": findings,
        "collector_outputs": ctx.outputs,
        "adjustments": adjustments,
        "trace_path": str(run_dir / "trace.jsonl"),
        "usage": usage,
    }
