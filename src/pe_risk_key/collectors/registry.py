"""Collector registry: tool definitions for the orchestrator + run dispatch.

Each collector module registers itself with :func:`register`, giving its
tool name, description, and ``collection_method`` (which must be a member
of the ``collection_method`` enum in ``digest.schema.json``).
:func:`tool_definitions` exposes the registry in OpenAI function-calling
format; :func:`run` executes one collector live, or from fixtures when
``DEMO_MODE=1``.
"""

from __future__ import annotations

import copy
import json
import os
from pathlib import Path
from typing import Any, Callable

from pe_risk_key.collectors.net import begin_run
from pe_risk_key.validate import SCHEMA_PATH

ROOT = Path(__file__).resolve().parents[3]
FIXTURES_DIR = ROOT / "fixtures" / "outside_in"


def _allowed_methods() -> frozenset[str]:
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    methods = schema["$defs"]["evidence"]["properties"]["collection_method"][
        "enum"
    ]
    return frozenset(methods)


ALLOWED_METHODS = _allowed_methods()

INPUT_SCHEMA = {
    "type": "object",
    "properties": {
        "domain": {
            "type": "string",
            "description": "Target apex domain, e.g. acme.example.",
        }
    },
    "required": ["domain"],
    "additionalProperties": False,
}

_REGISTRY: dict[str, dict[str, Any]] = {}


def register(
    *, tool_name: str, description: str, collection_method: str
) -> Callable[[Callable[[str], dict]], Callable[[str], dict]]:
    """Register a ``collect(domain) -> dict`` collector function."""
    if collection_method not in ALLOWED_METHODS:
        raise ValueError(
            f"collection_method {collection_method!r} is not one of "
            f"{sorted(ALLOWED_METHODS)}."
        )

    def decorator(
        func: Callable[[str], dict],
    ) -> Callable[[str], dict]:
        if tool_name in _REGISTRY:
            raise ValueError(f"Duplicate tool name: {tool_name!r}.")
        _REGISTRY[tool_name] = {
            "collect": func,
            "description": description,
            "collection_method": collection_method,
        }
        return func

    return decorator


def tool_definitions() -> list[dict[str, Any]]:
    """Registry in OpenAI function-calling format for the orchestrator."""
    return [
        {
            "type": "function",
            "function": {
                "name": name,
                "description": entry["description"],
                "parameters": copy.deepcopy(INPUT_SCHEMA),
            },
        }
        for name, entry in _REGISTRY.items()
    ]


def run(tool_name: str, domain: str, **kwargs: Any) -> dict:
    """Run one collector live, or from fixtures when ``DEMO_MODE=1``.

    Extra keyword arguments pass through to ``collect`` (e.g. the
    orchestrator chaining fingerprints into ``match_known_exploited``);
    they are ignored on the fixture path.
    """
    if tool_name not in _REGISTRY:
        raise KeyError(
            f"Unknown tool: {tool_name!r}. Known: {sorted(_REGISTRY)}."
        )
    if os.getenv("DEMO_MODE") == "1":
        if "/" in domain or "\\" in domain or ".." in domain:
            raise ValueError(f"Bad domain for fixture lookup: {domain!r}.")
        data = json.loads(
            (FIXTURES_DIR / f"{domain}.json").read_text(encoding="utf-8")
        )
        return data[tool_name]
    begin_run(domain)
    entry = _REGISTRY[tool_name]
    try:
        return entry["collect"](domain, **kwargs)
    except Exception as exc:
        return {
            "status": "error",
            "error": f"{type(exc).__name__}: {exc}",
            "collection_method": entry["collection_method"],
        }
