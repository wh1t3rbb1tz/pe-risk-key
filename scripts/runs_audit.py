# SPDX-License-Identifier: AGPL-3.0-or-later
"""Audit eval/runs/: table every run, optionally archive invalid/stray ones.

Lists each run with target, inputs, schema validity, completeness, and
authoritative status, flagging company names that differ from the
fixture target name for the same domain. With --archive, moves runs
with an invalid/unreadable digest and stray runs without any digest to
eval/runs/_archive/ (moved, never deleted). Honors PE_RISK_KEY_RUNS_DIR.
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]

from pe_risk_key.api import app as api_app


def fixture_names() -> dict[str, str]:
    """Canonical company name per fixture domain."""
    names: dict[str, str] = {}
    fixtures = ROOT / "fixtures" / "outside_in"
    if not fixtures.is_dir():
        return names
    for path in sorted(fixtures.glob("*.json")):
        try:
            target = json.loads(path.read_text(encoding="utf-8")).get(
                "target", {}
            )
        except (json.JSONDecodeError, OSError):
            continue
        if target.get("domain") and target.get("name"):
            names[target["domain"]] = target["name"]
    return names


def audit_rows() -> list[dict[str, Any]]:
    """One row per run dir: status, inputs, validity, authority, flags."""
    runs_dir = api_app.RUNS_DIR
    entries = {
        entry["digest_id"]: entry
        for entry in api_app.list_digests()["digests"]
    }
    canonical = fixture_names()
    rows: list[dict[str, Any]] = []
    if not runs_dir.is_dir():
        return rows
    for run_dir in sorted(
        d
        for d in runs_dir.iterdir()
        if d.is_dir() and d.name != "_archive"
    ):
        entry = entries.get(run_dir.name)
        if entry is None:
            rows.append(
                {
                    "digest_id": run_dir.name,
                    "company": "-",
                    "domain": "-",
                    "inputs": "-",
                    "schema_valid": "-",
                    "complete": False,
                    "authority": "stray",
                    "flags": [],
                    "archivable": True,
                }
            )
            continue
        target = entry.get("target") or {}
        company = target.get("name") or "-"
        domain = target.get("domain") or "-"
        inputs = "outside-in"
        if entry.get("has_soc2"):
            inputs += "+soc2"
        if entry.get("has_interview"):
            inputs += "+interview"
        if entry.get("authoritative"):
            authority = "authoritative"
        elif entry.get("superseded_by"):
            authority = f"superseded by {entry['superseded_by']}"
        elif entry["complete"]:
            authority = "complete"
        else:
            authority = entry.get("status", "?")
        flags: list[str] = []
        if (
            domain != "-"
            and domain in canonical
            and company != canonical[domain]
        ):
            flags.append(f"name differs from fixture ({canonical[domain]!r})")
        has_digest = (run_dir / "digest.json").exists()
        live = entry.get("status") == "running"
        rows.append(
            {
                "digest_id": run_dir.name,
                "company": company,
                "domain": domain,
                "inputs": inputs if has_digest else "-",
                "schema_valid": entry.get("schema_valid"),
                "complete": entry["complete"],
                "authority": authority,
                "flags": flags,
                "archivable": not live
                and (
                    (has_digest and not entry.get("schema_valid"))
                    or not has_digest
                ),
            }
        )
    return rows


def print_table(rows: list[dict[str, Any]]) -> None:
    header = (
        f"{'digest_id':<18}{'company':<32}{'inputs':<24}"
        f"{'valid':<7}{'complete':<10}{'authority'}"
    )
    print(header)
    print("-" * len(header))
    for row in rows:
        print(
            f"{row['digest_id']:<18}{str(row['company'])[:30]:<32}"
            f"{row['inputs']:<24}{str(row['schema_valid']):<7}"
            f"{str(row['complete']):<10}{row['authority']}"
        )
        for flag in row["flags"]:
            print(f"{'':<18}FLAG: {flag}")


def archive_runs(rows: list[dict[str, Any]]) -> list[str]:
    """Move archivable run dirs to _archive/; returns moved ids."""
    runs_dir = api_app.RUNS_DIR
    archive = runs_dir / "_archive"
    archive.mkdir(parents=True, exist_ok=True)
    moved: list[str] = []
    for row in rows:
        if not row["archivable"]:
            continue
        source = runs_dir / row["digest_id"]
        dest = archive / row["digest_id"]
        suffix = 2
        while dest.exists():
            dest = archive / f"{row['digest_id']}-{suffix}"
            suffix += 1
        shutil.move(str(source), str(dest))
        moved.append(row["digest_id"])
        print(f"archived {row['digest_id']} -> _archive/{dest.name}")
    return moved


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--archive",
        action="store_true",
        help="move invalid/stray runs to eval/runs/_archive/",
    )
    args = parser.parse_args(argv)
    rows = audit_rows()
    if not rows:
        print("no runs found")
        return 0
    print_table(rows)
    if args.archive:
        moved = archive_runs(rows)
        print(f"archived {len(moved)} run(s)")
    else:
        pending = sum(1 for row in rows if row["archivable"])
        if pending:
            print(
                f"{pending} invalid/stray run(s); "
                "re-run with --archive to move them"
            )
    return 0


if __name__ == "__main__":
    sys.exit(main())
