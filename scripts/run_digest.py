"""Run the orchestrator agent end to end and print a report.

Makes live API calls unless --demo serves collectors from fixtures;
run manually, not from the test suite.
"""

import argparse
import json
import os
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]


def print_tool_groups(trace: list[dict]) -> None:
    ends = [e for e in trace if e["type"] == "tool_call_end"]
    groups: dict[int, list[dict]] = {}
    for event in ends:
        groups.setdefault(event["parallel_group"], []).append(event)
    print("tool calls by parallel group:")
    for group in sorted(groups):
        print(f"  group {group}:")
        for event in groups[group]:
            print(
                f"    {event['tool']}: "
                f"{event['duration_ms']}ms {event['status']}"
            )


def print_findings(findings: list[dict]) -> None:
    print(f"\nfindings ({len(findings)}):")
    if not findings:
        print("  -")
        return
    for finding in findings:
        title = finding.get("title", "")[:60]
        print(
            f"  {finding.get('finding_id')} "
            f"rule_id={finding.get('rule_id') or '-'} "
            f"severity={finding.get('severity')} "
            f"confidence={finding.get('confidence')} {title}"
        )


def print_adjustments(adjustments: list[dict]) -> None:
    print(f"\nengine adjustments ({len(adjustments)}):")
    if not adjustments:
        print("  -")
        return
    for adjustment in adjustments:
        print(
            f"  {adjustment['finding_id']} {adjustment['field']}: "
            f"{adjustment['from']} -> {adjustment['to']} "
            f"({adjustment['reason']})"
        )


def print_recall(findings: list[dict], domain: str) -> None:
    expected_path = ROOT / "fixtures" / "expected" / f"{domain}.yaml"
    if not expected_path.exists():
        print(f"\nrecall: no expected file for {domain}, skipped")
        return
    expected = yaml.safe_load(expected_path.read_text(encoding="utf-8"))
    want = {
        entry["rule_id"]
        for entry in expected.get("expected_findings", [])
        if entry.get("source") == "outside_in"
    }
    got = {
        f.get("rule_id")
        for f in findings
        if f.get("rule_id") and f.get("source") != "document"
    }
    must = set(expected.get("must_not_find", []))
    matched = want & got
    print(
        f"\nrecall: {len(matched)}/{len(want)} = "
        f"{len(matched) / len(want) * 100:.1f}%"
        if want
        else "\nrecall: no outside-in expectations"
    )
    print(f"missing expected rules: {sorted(want - got) or '-'}")
    print(f"unexpected rules: {sorted(got - want) or '-'}")
    print(f"must_not_find hits: {sorted(got & must) or '-'}")


def print_soc2_summary(digest: dict) -> None:
    analysis = digest.get("soc2_analysis")
    if analysis is None:
        return
    soc2_findings = sum(
        1 for f in digest["findings"] if f.get("source") == "document"
    )
    print(
        f"\nsoc2: opinion={analysis['opinion']} "
        f"exceptions={len(analysis['exceptions'])} "
        f"findings={soc2_findings} "
        f"bridge_gap={analysis['bridge_gap_days']}d"
    )


def print_usage(usage: dict) -> None:
    print("\ncost by component:")
    for name, component in usage.get("components", {}).items():
        if "audio_hours" in component:
            detail = f"audio={component['audio_hours']:.2f}h"
        else:
            detail = (
                f"input={component.get('prompt_tokens', 0)} "
                f"output={component.get('completion_tokens', 0)} "
                f"cached={component.get('cached_tokens', 0)}"
            )
        print(
            f"  {name}: {detail} "
            f"cost=${component.get('estimated_cost_usd', 0):.4f}"
        )
    print(
        f"tokens: input={usage['prompt_tokens']} "
        f"output={usage['completion_tokens']} cached={usage['cached_tokens']}"
    )
    print(f"estimated cost: ${usage['estimated_cost_usd']:.4f}")


def print_digest_summary(digest: dict) -> None:
    overall = digest["overall"]
    plan = digest["remediation_plan"]
    print(
        f"\noverall: score={overall['score']:.1f} rating={overall['rating']} "
        f"confidence={overall['confidence']} "
        f"deal_signal={overall['deal_signal']}"
    )
    print(f"caps applied: {overall['rating_caps_applied'] or '-'}")
    print(
        f"remediation total: ${plan['total_cost_low_usd']:,.0f} - "
        f"${plan['total_cost_high_usd']:,.0f}"
    )
    print("function scores:")
    for entry in digest["function_scores"]:
        if entry["assessed"]:
            print(
                f"  {entry['function']}: {entry['score']:.1f} "
                f"({entry['finding_count']} findings)"
            )
        else:
            print(f"  {entry['function']}: not assessed")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--domain", required=True)
    parser.add_argument("--company", required=True)
    parser.add_argument("--employee-band", required=True)
    parser.add_argument("--revenue-band", required=True)
    parser.add_argument("--aliases", default="")
    parser.add_argument("--industry", default=None)
    parser.add_argument("--demo", action="store_true")
    parser.add_argument("--soc2", default=None, help="Path to a SOC 2 report")
    parser.add_argument("--as-of", default=None, help="YYYY-MM-DD")
    args = parser.parse_args()
    if args.demo:
        os.environ["DEMO_MODE"] = "1"

    from pe_risk_key.agent import run_digest

    aliases = [a for a in args.aliases.split(",") if a] if args.aliases else []
    result = run_digest(
        args.domain,
        args.company,
        args.employee_band,
        args.revenue_band,
        aliases=aliases,
        industry=args.industry,
        soc2_path=args.soc2,
        as_of=args.as_of,
    )
    print(f"=== run_digest: {args.domain} ({result['digest_id']}) ===")
    trace = [
        json.loads(line)
        for line in Path(result["trace_path"]).read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    print_tool_groups(trace)
    print_findings(result["findings"])
    print_adjustments(result["adjustments"])
    print_recall(result["findings"], args.domain)
    print_usage(result["usage"])
    digest_path = Path(result["trace_path"]).parent / "digest.json"
    digest = json.loads(digest_path.read_text(encoding="utf-8"))
    print_soc2_summary(digest)
    print_digest_summary(digest)
    print(f"saved: {Path(result['trace_path']).parent.relative_to(ROOT)}/")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
