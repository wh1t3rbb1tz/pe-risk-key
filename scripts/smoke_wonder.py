"""Wonder smoke test: fixture signals -> schema-valid findings.

Loads the Brightwater outside-in fixture, asks Muse Wonder for findings
constrained to the finding schema, applies deterministic rule constraints,
strips strict nulls, validates each finding against the original subschema,
and scores rule_id recall against fixtures/expected/brightwaterfleet.example.yaml.

Makes a live API call; run manually, not from the test suite.
"""

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import jsonschema
import yaml

from pe_risk_key.engine.rules import apply_rule_constraints
from pe_risk_key.providers import ModelClient
from pe_risk_key.schemas import (
    strict_subschema,
    strip_nullable_optionals,
    subschema,
)

ROOT = Path(__file__).resolve().parents[1]
FIXTURE_PATH = ROOT / "fixtures/outside_in/brightwaterfleet.example.json"
SCORING_PATH = ROOT / "scoring.yaml"
EXPECTED_PATH = ROOT / "fixtures/expected/brightwaterfleet.example.yaml"
RUNS_DIR = ROOT / "eval/runs"

SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]
PRICE_PER_M = {"input": 4.0, "cached": 0.20, "output": 20.0}

SYSTEM_PROMPT = """You are a cybersecurity analyst producing triage-grade findings from passive collector signals for a PE deal team. Output a JSON object with a "findings" list.

1. Map collector signals to findings using the rules in scoring.yaml. For each finding, set rule_id, baseline severity, csf_category, and title from the matching rule.
2. You may adjust severity by at most one level from the baseline, and only with a justification in deal_impact.
3. Cite evidence using only data in the fixture. Every evidence item must have a specific locator (DNS record, hostname, header name, URL, or version string) and the collection_method recorded in the fixture for that collector. Never invent evidence. Copy evidence locators exactly from the collector output fields (queried_name + record_type, URL, hostname); never construct or shorten them.
4. Cap KEV-based findings (KEV-POTENTIAL) at confidence medium and phrase them as "potential exposure".
5. Number findings F-001, F-002, ... and evidence items E-001, E-002, ... uniquely across the response.

Also: set finding source to "outside_in" (evidence source_type "outside_in", except "public_record" for the breach notice) and csf_function to the prefix of csf_category. Fill remediation with a brief summary and effort estimate, but set cost_low_usd, cost_high_usd, and effort_weeks to 0; the engine assigns costs and effort."""

RESPONSE_SCHEMA = {
    "type": "object",
    "properties": {
        "findings": {"type": "array", "items": strict_subschema("finding")}
    },
    "required": ["findings"],
    "additionalProperties": False,
}


def load_inputs() -> tuple[dict, dict, dict]:
    fixture = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))
    scoring = yaml.safe_load(SCORING_PATH.read_text(encoding="utf-8"))
    expected = yaml.safe_load(EXPECTED_PATH.read_text(encoding="utf-8"))
    return fixture, scoring, expected


def expected_outside_in(expected: dict) -> list[dict]:
    """Expected findings with source outside_in."""
    return [
        entry
        for entry in expected["expected_findings"]
        if entry.get("source") == "outside_in"
    ]


def build_messages(fixture: dict, scoring: dict) -> list[dict]:
    rules_yaml = yaml.safe_dump({"rules": scoring["rules"]}, sort_keys=False)
    return [
        {"role": "system", "content": SYSTEM_PROMPT},
        {
            "role": "user",
            "content": (
                f"Collector signals for {fixture['target']['domain']}:\n"
                f"```json\n{json.dumps(fixture, indent=2)}\n```\n"
                f"Scoring rules:\n```yaml\n{rules_yaml}```\n"
                "Return the findings list."
            ),
        },
    ]


def validate_findings(findings: list[dict]) -> list[dict]:
    """Strip strict nulls and validate each finding; never raises."""
    validator = jsonschema.Draft202012Validator(subschema("finding"))
    results = []
    for finding in findings:
        if not isinstance(finding, dict):
            results.append(
                {
                    "finding_id": "?",
                    "rule_id": None,
                    "severity": "?",
                    "valid": False,
                    "stripped": None,
                    "errors": ["finding is not an object"],
                }
            )
            continue
        stripped = strip_nullable_optionals(finding, "finding")
        errors = sorted(
            validator.iter_errors(stripped), key=lambda e: e.json_path
        )
        results.append(
            {
                "finding_id": stripped.get("finding_id", "?"),
                "rule_id": stripped.get("rule_id"),
                "severity": stripped.get("severity", "?"),
                "valid": not errors,
                "stripped": stripped,
                "errors": [f"{e.json_path}: {e.message}" for e in errors],
            }
        )
    return results


def severity_delta(got: Any, want: str) -> int | None:
    try:
        return SEVERITY_ORDER.index(got) - SEVERITY_ORDER.index(want)
    except ValueError:
        return None


def score(
    results: list[dict], expected_entries: list[dict], must_not_find: list[str]
) -> dict:
    expected_severity = {e["rule_id"]: e["severity"] for e in expected_entries}
    expected_ids = set(expected_severity)
    returned_ids = {r["rule_id"] for r in results if r["valid"] and r["rule_id"]}
    return {
        "expected_severity": expected_severity,
        "expected_ids": expected_ids,
        "matched": expected_ids & returned_ids,
        "missing": expected_ids - returned_ids,
        "unexpected": returned_ids - expected_ids,
        "must_hits": {r["rule_id"] for r in results if r["rule_id"]}
        & set(must_not_find),
        "no_rule": [r["finding_id"] for r in results if not r["rule_id"]],
    }


def estimate_cost(usage: dict[str, int]) -> float:
    billable_input = max(0, usage["prompt_tokens"] - usage["cached_tokens"])
    return (
        billable_input * PRICE_PER_M["input"]
        + usage["cached_tokens"] * PRICE_PER_M["cached"]
        + usage["completion_tokens"] * PRICE_PER_M["output"]
    ) / 1_000_000


def print_report(
    results: list[dict],
    summary: dict,
    adjustments: list[dict],
    usage: dict[str, int],
    model: str,
    domain: str,
    run_path: Path,
) -> None:
    valid = [r for r in results if r["valid"]]
    print(f"=== smoke_wonder: {domain} ===")
    print(f"model: {model}")
    print(f"\nfindings ({len(results)} returned, {len(valid)} valid):")
    for r in results:
        status = "PASS" if r["valid"] else "FAIL"
        line = (
            f"[{status}] {r['finding_id']} "
            f"rule_id={r['rule_id'] or '-'} severity={r['severity']}"
        )
        want = summary["expected_severity"].get(r["rule_id"] or "")
        if want:
            delta = severity_delta(r["severity"], want)
            if delta == 0:
                line += f" (expected {want}, exact)"
            elif delta is None:
                line += f" (expected {want})"
            else:
                line += f" (expected {want}, {delta:+d})"
        elif r["rule_id"]:
            line += " (unexpected rule)"
        print(line)
        for err in r["errors"][:3]:
            print(f"    {err}")
    print(f"\nengine adjustments ({len(adjustments)}):")
    if adjustments:
        for a in adjustments:
            print(
                f"  {a['finding_id']} {a['field']}: "
                f"{a['from']} -> {a['to']} ({a['reason']})"
            )
    else:
        print("  -")
    total = len(summary["expected_ids"])
    print(
        f"\nrecall (valid findings): {len(summary['matched'])}/{total} = "
        f"{len(summary['matched']) / total * 100:.1f}%"
    )
    print(f"missing expected rules: {sorted(summary['missing']) or '-'}")
    print(f"unexpected rules: {sorted(summary['unexpected']) or '-'}")
    print(f"must_not_find hits: {sorted(summary['must_hits']) or '-'}")
    print(f"findings with no rule_id: {summary['no_rule'] or '-'}")
    print(
        f"\ntokens: input={usage['prompt_tokens']} "
        f"output={usage['completion_tokens']} cached={usage['cached_tokens']}"
    )
    print(f"estimated cost: ${estimate_cost(usage):.4f}")
    print(f"saved: {run_path.relative_to(ROOT)}")


def main() -> int:
    fixture, scoring, expected = load_inputs()
    expected_entries = expected_outside_in(expected)
    must_not_find = expected.get("must_not_find", [])

    client = ModelClient("orchestrator")
    try:
        parsed = client.chat_json(
            build_messages(fixture, scoring),
            schema=RESPONSE_SCHEMA,
            schema_name="Findings",
            reasoning_effort="medium",
        )
    except (jsonschema.ValidationError, ValueError) as exc:
        print(f"FATAL: structured output failed validation twice: {exc}")
        return 1
    employee_band = fixture.get("target", {}).get("employee_band")
    findings, adjustments = apply_rule_constraints(
        parsed.get("findings", []), scoring, employee_band
    )
    results = validate_findings(findings)
    summary = score(results, expected_entries, must_not_find)

    RUNS_DIR.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    run_path = RUNS_DIR / f"smoke_{stamp}.json"
    run_path.write_text(
        json.dumps(
            {
                "created_at": stamp,
                "model": client.model,
                "usage": client.total_usage,
                "response_raw": parsed,
                "response_final": {
                    "findings": [
                        r["stripped"]
                        for r in results
                        if r["valid"] and r["stripped"] is not None
                    ]
                },
                "adjustments": adjustments,
            },
            indent=2,
        ),
        encoding="utf-8",
    )

    print_report(
        results,
        summary,
        adjustments,
        client.total_usage,
        client.model,
        fixture["target"]["domain"],
        run_path,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
