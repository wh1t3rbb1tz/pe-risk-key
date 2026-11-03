# SPDX-License-Identifier: AGPL-3.0-or-later
"""Transcribe an interview and extract security claims.

Makes live API calls (transcription + one Muse Wonder call);
run manually, not from the test suite.
"""

import argparse
import json
import re
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RUNS_DIR = ROOT / "eval" / "runs"


def print_turns(transcript) -> None:
    turns = transcript["turns"]
    print(f"\nturns ({len(turns)}):")
    if not turns:
        print("  -")
        return
    for turn in turns:
        speaker = turn["speaker_name"] or turn["speaker_label"]
        print(f"  [{turn['start']}] {speaker}: {turn['text']}")
    labels = {turn["speaker_label"] for turn in turns}
    print(
        f"\nparse diagnostics: skipped_empty="
        f"{transcript.get('skipped_empty', 0)} "
        f"speaker_inferred={transcript.get('speaker_inferred', 0)} "
        f"speaker_labels={len(labels)}"
    )


def print_debug(transcript) -> None:
    raw_path = (
        ROOT
        / ".cache"
        / "transcripts"
        / f"{transcript['sha256']}.raw.json"
    )
    if not raw_path.exists():
        print("\ndebug: no raw response saved for this transcript")
        return
    raw = json.loads(raw_path.read_text(encoding="utf-8"))
    print(f"\ndebug: top-level keys: {sorted(raw)}")
    for turn in raw.get("turns", [])[:3]:
        print(f"  {json.dumps(turn)[:200]}")


def print_claims(claims) -> None:
    print(f"\nclaims ({len(claims)}):")
    if not claims:
        print("  -")
        return
    for claim in claims:
        print(
            f"  C-{claim['claim_index']:03d} [{claim['timestamp']}] "
            f"{claim['speaker']} ({claim['claim_type']})"
        )
        print(f"    {claim['text'][:200]}")


def print_drops(result) -> None:
    dropped = result["dropped_unquoted"] + result["dropped_not_target"]
    print(f"\ndrops ({len(dropped)}):")
    if not dropped:
        print("  -")
        return
    for drop in result["dropped_unquoted"]:
        print(f"  unquoted: {(drop.get('text') or '')[:120]}")
        print(f"    closest window: {drop.get('closest_window', '')[:160]}")
        print(f"    similarity: {drop.get('similarity_ratio', 0.0)}")
    for drop in result["dropped_not_target"]:
        print(
            f"  turn {drop.get('turn_index', '?')}: {drop['reason']} "
            f"({drop.get('speaker')})"
        )
        print(f"    {(drop.get('text') or '')[:120]}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--file", required=True)
    parser.add_argument("--speakers", default="")
    parser.add_argument("--target", required=True, action="append")
    parser.add_argument("--debug", action="store_true")
    args = parser.parse_args()

    from pe_risk_key.analyzers import extract_claims, transcribe_interview

    interview_id = "iv_" + re.sub(
        r"[^a-z0-9]+", "", Path(args.file).stem.lower()
    )
    speaker_names = (
        [name for name in args.speakers.split(",") if name]
        if args.speakers
        else None
    )
    transcript = transcribe_interview(
        args.file, interview_id, speaker_names=speaker_names
    )
    result = extract_claims(transcript, args.target)
    RUNS_DIR.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    run_path = RUNS_DIR / f"interview_{stamp}.json"
    run_path.write_text(
        json.dumps(
            {
                "created_at": stamp,
                "interview_id": interview_id,
                "transcript": transcript,
                "claims": result,
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    print(f"=== analyze_interview: {args.file} ({interview_id}) ===")
    print(
        f"\nduration: {transcript['duration_seconds']:.1f}s"
        + (" (cached transcript)" if transcript["cached"] else "")
    )
    print_turns(transcript)
    if args.debug:
        print_debug(transcript)
    print_claims(result["claims"])
    print_drops(result)
    total = transcript["estimated_cost_usd"] + result["estimated_cost_usd"]
    print(f"\ncost: transcription=${transcript['estimated_cost_usd']:.4f} "
          f"extraction=${result['estimated_cost_usd']:.4f} "
          f"total=${total:.4f}")
    print(f"saved: {run_path.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
