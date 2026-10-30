"""Analyze one SOC 2 report file and print the result.

Makes one live Muse Wonder call; run manually, not from the test suite.
"""

import argparse
import dataclasses
import json
import re
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RUNS_DIR = ROOT / "eval" / "runs"


def print_report(result) -> None:
    analysis = result.soc2_analysis
    print(f"=== analyze_soc2: {result.filename} ({result.doc_id}) ===")
    print(f"\nopinion: {analysis['opinion']}")
    if result.opinion_verified:
        print(f"  quote: {result.opinion_quote or '-'}")
    else:
        print("  WARNING: opinion quote could not be verified against the source text.")
        print(f"  quote (unverified): {result.opinion_quote or '-'}")
    print(
        f"\nperiod: {analysis['period_start']} to {analysis['period_end']} "
        f"({analysis['auditor']}, {analysis['report_type']})"
    )
    print(f"\nexceptions ({len(analysis['exceptions'])}):")
    if not analysis["exceptions"]:
        print("  -")
    for item in analysis["exceptions"]:
        print(
            f"  {item['control_id']}: {item['deviations']}/"
            f"{item['sample_size']} deviations "
            f"[{item['locator']}]"
            + (f" -> {item['finding_id']}" if "finding_id" in item else "")
        )
        print(f"    {item['description'][:100]}")
    carve_outs = [
        org
        for org in analysis["subservice_orgs"]
        if org["method"] == "carve_out"
    ]
    print(f"\ncarve-outs ({len(carve_outs)}):")
    if not carve_outs:
        print("  -")
    for org in carve_outs:
        print(
            f"  {org['name']}: {org['services']} "
            f"(critical: {org['critical']})"
        )
    print(f"\nCUECs: {len(analysis['cuecs'])}")
    print(f"\nnotable observations ({len(result.notable_observations)}):")
    if not result.notable_observations:
        print("  -")
    for notable in result.notable_observations:
        print(f"  [{notable['locator']}] {notable['text'][:100]}")
    print(f"\nbridge gap: {analysis['bridge_gap_days']} days")
    print(f"\nfindings ({len(result.findings)}):")
    if not result.findings:
        print("  -")
    for finding in result.findings:
        print(
            f"  {finding['finding_id']} rule_id={finding.get('rule_id')} "
            f"severity={finding['severity']} {finding['title'][:60]}"
        )
    print(
        f"\ndrops: {len(result.dropped_unquoted)} unquoted, "
        f"{len(result.dropped_no_locator)} without locator"
    )
    for drop in result.dropped_unquoted:
        print(f"  {drop['type']}: {drop['ref']}")
        print(f"    closest window: {drop.get('closest_window', '')[:160]}")
        print(f"    similarity: {drop.get('similarity_ratio', 0.0)}")
    for drop in result.dropped_no_locator:
        print(f"  {drop['type']}: {drop['ref']} (no locator)")
    usage = result.usage
    print(
        f"\ntokens: input={usage['prompt_tokens']} "
        f"output={usage['completion_tokens']} cached={usage['cached_tokens']}"
    )
    print(f"estimated cost: ${result.estimated_cost_usd:.4f}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--file", required=True)
    parser.add_argument("--as-of", required=True)
    args = parser.parse_args()

    from pe_risk_key.analyzers import analyze_soc2

    doc_id = "doc_" + re.sub(
        r"[^a-z0-9]+", "", Path(args.file).stem.lower()
    )
    result = analyze_soc2(args.file, doc_id, args.as_of)
    RUNS_DIR.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    run_path = RUNS_DIR / f"soc2_{stamp}.json"
    run_path.write_text(
        json.dumps(
            {
                "created_at": stamp,
                "as_of": args.as_of,
                "result": dataclasses.asdict(result),
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    print_report(result)
    print(f"saved: {run_path.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
