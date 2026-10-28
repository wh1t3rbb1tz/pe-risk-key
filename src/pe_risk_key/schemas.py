"""Schema helpers: API-ready subschemas from digest.schema.json.

``subschema()`` pulls one ``$def`` (e.g. ``finding``) out of
``digest.schema.json`` with all ``$ref``\\ s inlined. ``strict_subschema()``
additionally applies the Meta Model API strict subset (per
https://dev.meta.ai/docs/structured-output): every object sets
``additionalProperties: false`` and lists every property in ``required``,
with originally-optional properties widened to a nullable type. The
source file is never modified.
"""

from __future__ import annotations

import copy
import json
from functools import lru_cache
from typing import Any

from pe_risk_key.validate import SCHEMA_PATH


@lru_cache(maxsize=1)
def _load_root() -> dict[str, Any]:
    with open(SCHEMA_PATH, encoding="utf-8") as fh:
        return json.load(fh)


def subschema(def_name: str) -> dict[str, Any]:
    """Return the named ``$def`` with all local ``$ref``\\ s fully inlined."""
    defs = _load_root().get("$defs", {})
    if def_name not in defs:
        raise KeyError(
            f"Unknown schema definition: {def_name!r}. "
            f"Available: {sorted(defs)}."
        )
    return _resolve_refs(copy.deepcopy(defs[def_name]), _load_root(), ())


def strict_subschema(def_name: str) -> dict[str, Any]:
    """Return ``subschema(def_name)`` transformed for strict-mode requests."""
    return _strict_transform(subschema(def_name))


def strip_nullable_optionals(obj: Any, def_name: str) -> Any:
    """Drop null-valued optional fields from strict-mode output.

    Under strict mode the model emits explicit ``null`` for absent
    optional fields; the original definition wants them absent instead.
    Fields that are ``required`` in the original definition are left
    alone (even when null) so validation still catches them. Returns a
    new object; the input is not mutated.
    """
    return _strip_nulls(obj, subschema(def_name))


def _strip_nulls(node: Any, schema: Any) -> Any:
    if isinstance(node, dict) and isinstance(schema, dict):
        properties = schema.get("properties")
        if not isinstance(properties, dict):
            return node
        required = set(schema.get("required") or [])
        cleaned = {}
        for key, value in node.items():
            if value is None and key not in required:
                continue
            cleaned[key] = _strip_nulls(value, properties.get(key))
        return cleaned
    if isinstance(node, list) and isinstance(schema, dict):
        items = schema.get("items")
        if not isinstance(items, dict):
            return node
        return [_strip_nulls(item, items) for item in node]
    return node


def _pointer_target(root: dict[str, Any], ref: str) -> Any:
    if not ref.startswith("#/"):
        raise ValueError(f"Only local refs are supported, got {ref!r}.")
    target: Any = root
    for part in ref[2:].split("/"):
        part = part.replace("~1", "/").replace("~0", "~")
        target = target[part]
    return target


def _resolve_refs(
    node: Any, root: dict[str, Any], stack: tuple[str, ...]
) -> Any:
    if isinstance(node, dict):
        if "$ref" in node:
            ref = node["$ref"]
            if ref in stack:
                raise ValueError(
                    f"Recursive schema ($ref cycle at {ref!r}); the API "
                    "rejects recursive schemas."
                )
            resolved = _resolve_refs(
                copy.deepcopy(_pointer_target(root, ref)), root, stack + (ref,)
            )
            for key, value in node.items():
                if key != "$ref":
                    resolved[key] = _resolve_refs(value, root, stack)
            return resolved
        return {
            key: _resolve_refs(value, root, stack) for key, value in node.items()
        }
    if isinstance(node, list):
        return [_resolve_refs(item, root, stack) for item in node]
    return node


def _make_nullable(prop: dict[str, Any]) -> dict[str, Any]:
    """Widen an optional property so it accepts explicit null."""
    prop_type = prop.get("type")
    if "enum" not in prop and "const" not in prop:
        if isinstance(prop_type, str):
            return {**prop, "type": [prop_type, "null"]}
        if isinstance(prop_type, list):
            if "null" in prop_type:
                return prop
            return {**prop, "type": [*prop_type, "null"]}
    # enum/const/typeless nodes can't take a null type; anyOf is allowed
    # below the root in strict mode.
    return {"anyOf": [prop, {"type": "null"}]}


def _strict_transform(node: Any) -> Any:
    if isinstance(node, dict):
        transformed = {
            key: _strict_transform(value) for key, value in node.items()
        }
        properties = transformed.get("properties")
        if isinstance(properties, dict):
            originally_required = set(transformed.get("required", []))
            transformed["properties"] = {
                name: (
                    prop
                    if name in originally_required
                    else _make_nullable(prop)
                )
                for name, prop in properties.items()
            }
            transformed["required"] = list(properties)
        if isinstance(properties, dict) or transformed.get("type") == "object":
            transformed["additionalProperties"] = False
        return transformed
    if isinstance(node, list):
        return [_strict_transform(item) for item in node]
    return node
