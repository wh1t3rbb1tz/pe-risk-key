"""Tests for pe_risk_key.schemas: inlining and strict-mode transform."""

import json

import jsonschema
import pytest

from pe_risk_key.schemas import (
    strict_subschema,
    strip_nullable_optionals,
    subschema,
)
from pe_risk_key.validate import SCHEMA_PATH


def _find_refs(node) -> list:
    refs = []
    if isinstance(node, dict):
        for key, value in node.items():
            if key == "$ref":
                refs.append(value)
            else:
                refs.extend(_find_refs(value))
    elif isinstance(node, list):
        for item in node:
            refs.extend(_find_refs(item))
    return refs


def _walk_objects(node):
    if isinstance(node, dict):
        if isinstance(node.get("properties"), dict):
            yield node
        for value in node.values():
            yield from _walk_objects(value)
    elif isinstance(node, list):
        for item in node:
            yield from _walk_objects(item)


def test_subschema_inlines_all_refs():
    finding = subschema("finding")
    assert _find_refs(finding) == []
    # Spot-checks that refs resolved to the right targets.
    assert finding["properties"]["finding_id"] == {
        "type": "string",
        "pattern": "^F-[0-9]{3}$",
    }
    assert finding["properties"]["severity"]["enum"] == [
        "critical",
        "high",
        "medium",
        "low",
        "info",
    ]
    evidence = finding["properties"]["evidence"]["items"]
    assert evidence["properties"]["evidence_id"]["pattern"] == "^E-[0-9]{3}$"


def test_subschema_unknown_definition():
    with pytest.raises(KeyError, match="nope"):
        subschema("nope")


def test_subschema_does_not_mutate_source_file():
    subschema("finding")
    strict_subschema("finding")
    raw = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    assert _find_refs(raw) != []
    assert "rule_id" not in raw["$defs"]["finding"]["required"]


def test_strict_subschema_has_no_refs_and_all_required():
    strict = strict_subschema("finding")
    assert _find_refs(strict) == []
    assert strict["additionalProperties"] is False
    for obj in _walk_objects(strict):
        assert obj["additionalProperties"] is False
        assert sorted(obj["required"]) == sorted(obj["properties"].keys())


def test_strict_subschema_widens_optional_to_nullable():
    strict = strict_subschema("finding")
    # rule_id is optional in digest.schema.json: now required but nullable.
    assert strict["properties"]["rule_id"]["type"] == ["string", "null"]
    assert "rule_id" in strict["required"]
    # Required properties are untouched.
    assert strict["properties"]["severity"] == {
        "type": "string",
        "enum": ["critical", "high", "medium", "low", "info"],
    }
    # Nested optional fields are widened too (evidence.collector).
    evidence = strict["properties"]["evidence"]["items"]
    assert evidence["properties"]["collector"]["type"] == ["string", "null"]


def _finding() -> dict:
    return {
        "finding_id": "F-001",
        "title": "DMARC policy missing",
        "severity": "medium",
        "confidence": "high",
        "csf_function": "PR",
        "csf_category": "PR.AC",
        "source": "outside_in",
        "evidence": [
            {
                "evidence_id": "E-001",
                "source_type": "outside_in",
                "collection_method": "dns_query",
                "locator": "_dmarc.acme.example TXT",
                "excerpt": "No DMARC record published.",
            }
        ],
        "deal_impact": "Phishing risk.",
        "remediation": {
            "summary": "Publish a DMARC reject policy.",
            "cost_low_usd": 2000,
            "cost_high_usd": 5000,
            "effort_weeks": 1,
        },
    }


def test_original_and_strict_accept_their_shapes():
    original = subschema("finding")
    strict = strict_subschema("finding")
    base = _finding()
    jsonschema.Draft202012Validator(original).validate(base)
    strict_instance = {
        **base,
        "rule_id": None,
        "evidence": [
            {**base["evidence"][0], "collector": None, "collected_at": None}
        ],
    }
    jsonschema.Draft202012Validator(strict).validate(strict_instance)
    # Each rejects the other's shape: strict requires the key present,
    # original rejects the explicit null.
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.Draft202012Validator(strict).validate(base)
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.Draft202012Validator(original).validate(strict_instance)


def test_strip_removes_top_level_optional_null():
    finding = {**_finding(), "rule_id": None}
    cleaned = strip_nullable_optionals(finding, "finding")
    assert "rule_id" not in cleaned
    assert cleaned == _finding()
    assert finding["rule_id"] is None  # input not mutated


def test_strip_removes_nested_optional_null():
    finding = _finding()
    finding["evidence"][0]["collector"] = None
    finding["evidence"][0]["collected_at"] = None
    cleaned = strip_nullable_optionals(finding, "finding")
    assert cleaned["evidence"][0] == _finding()["evidence"][0]


def test_strip_handles_arrays_item_by_item():
    finding = _finding()
    second = {**_finding()["evidence"][0], "evidence_id": "E-002"}
    finding["evidence"].append(second)
    finding["evidence"][0]["collector"] = None
    finding["remediation"]["effort_weeks"] = 2  # non-null values untouched
    cleaned = strip_nullable_optionals(finding, "finding")
    assert "collector" not in cleaned["evidence"][0]
    assert cleaned["evidence"][1] == second
    assert cleaned["remediation"]["effort_weeks"] == 2


def test_strip_preserves_required_null_for_validation():
    finding = {**_finding(), "title": None, "rule_id": None}
    cleaned = strip_nullable_optionals(finding, "finding")
    assert cleaned["title"] is None  # still caught by validation
    assert "rule_id" not in cleaned
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.Draft202012Validator(subschema("finding")).validate(cleaned)


def test_strip_keeps_non_null_optionals():
    finding = {**_finding(), "rule_id": "EMAIL-DMARC-ABSENT"}
    cleaned = strip_nullable_optionals(finding, "finding")
    assert cleaned["rule_id"] == "EMAIL-DMARC-ABSENT"


def test_strip_unknown_definition():
    with pytest.raises(KeyError, match="nope"):
        strip_nullable_optionals({}, "nope")
