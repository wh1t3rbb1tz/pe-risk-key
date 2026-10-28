"""Digest validation: JSON Schema plus cross-reference checks (SPEC §9).

Every digest must validate against ``digest.schema.json``. Beyond the
schema, IDs that reference other parts of the digest must resolve:

- contradiction ``evidence_refs`` (``E-NNN`` / ``F-NNN``) must exist,
- deal recommendation ``basis_ids`` (``F-NNN`` / ``C-NNN``) must exist,
- remediation plan ``finding_ids`` (``F-NNN``) must exist.
"""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any

import jsonschema

SCHEMA_PATH = Path(__file__).resolve().parents[2] / "digest.schema.json"


@lru_cache(maxsize=4)
def _load_schema(path: str) -> dict[str, Any]:
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def validate_digest(
    digest: Any, schema_path: Path | str | None = None
) -> list[str]:
    """Validate a digest dict.

    Returns a list of human-readable errors; empty means valid. Runs both
    JSON Schema validation and the cross-reference checks.
    """
    if not isinstance(digest, dict):
        return [f"digest must be an object, got {type(digest).__name__}."]
    schema = _load_schema(str(schema_path or SCHEMA_PATH))
    validator = jsonschema.Draft202012Validator(
        schema, format_checker=jsonschema.FormatChecker()
    )
    errors = [
        f"{err.json_path}: {err.message}"
        for err in sorted(validator.iter_errors(digest), key=lambda e: e.json_path)
    ]
    errors.extend(_check_cross_references(digest))
    return errors


def _id_set(items: Any, key: str) -> set[str]:
    ids: set[str] = set()
    if isinstance(items, list):
        for item in items:
            if isinstance(item, dict) and isinstance(item.get(key), str):
                ids.add(item[key])
    return ids


def _check_cross_references(digest: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    findings = digest.get("findings")
    finding_ids = _id_set(findings, "finding_id")
    evidence_ids: set[str] = set()
    if isinstance(findings, list):
        for finding in findings:
            if isinstance(finding, dict):
                evidence_ids.update(_id_set(finding.get("evidence"), "evidence_id"))
    contradiction_ids = _id_set(digest.get("contradictions"), "contradiction_id")

    def check(
        location: str, ref: Any, pools: dict[str, tuple[str, set[str]]]
    ) -> None:
        prefix = ref.split("-", 1)[0] if isinstance(ref, str) else ""
        if prefix not in pools:
            # Malformed refs are reported by schema validation; skip here.
            return
        label, pool = pools[prefix]
        if ref not in pool:
            errors.append(
                f"{location}: {ref!r} does not match any {label} in this digest."
            )

    contradictions = digest.get("contradictions")
    if isinstance(contradictions, list):
        for i, contradiction in enumerate(contradictions):
            if not isinstance(contradiction, dict):
                continue
            cid = contradiction.get("contradiction_id", "?")
            refs = contradiction.get("evidence_refs")
            if isinstance(refs, list):
                for ref in refs:
                    check(
                        f"contradictions[{i}] ({cid}).evidence_refs",
                        ref,
                        {
                            "E": ("evidence_id", evidence_ids),
                            "F": ("finding_id", finding_ids),
                        },
                    )

    recommendations = digest.get("deal_recommendations")
    if isinstance(recommendations, list):
        for i, rec in enumerate(recommendations):
            if not isinstance(rec, dict):
                continue
            refs = rec.get("basis_ids")
            if isinstance(refs, list):
                for ref in refs:
                    check(
                        f"deal_recommendations[{i}].basis_ids",
                        ref,
                        {
                            "F": ("finding_id", finding_ids),
                            "C": ("contradiction_id", contradiction_ids),
                        },
                    )

    plan = digest.get("remediation_plan")
    items = plan.get("items") if isinstance(plan, dict) else None
    if isinstance(items, list):
        for i, item in enumerate(items):
            if not isinstance(item, dict):
                continue
            refs = item.get("finding_ids")
            if isinstance(refs, list):
                for ref in refs:
                    check(
                        f"remediation_plan.items[{i}].finding_ids",
                        ref,
                        {"F": ("finding_id", finding_ids)},
                    )

    return errors
