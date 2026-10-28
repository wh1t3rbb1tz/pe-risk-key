"""Per-run orchestrator state: outputs cache, net limits, trace writer."""

from __future__ import annotations

import json
import random
import string
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pe_risk_key.collectors as collectors
from pe_risk_key.collectors.net import begin_run
from pe_risk_key.collectors.registry import run as registry_run


def new_digest_id() -> str:
    """Fresh ``dg_`` + 12 lowercase alphanumeric digest id."""
    alphabet = string.ascii_lowercase + string.digits
    return "dg_" + "".join(random.choices(alphabet, k=12))


class TraceWriter:
    """Append-only JSONL trace; every event gets ``seq``, ``ts``, ``type``.

    Thread-safe: parallel tool calls trace through one lock so sequence
    numbers stay contiguous.
    """

    def __init__(self, path: Path) -> None:
        self.path = path
        self._seq = 0
        self._lock = threading.Lock()

    def event(self, type: str, **fields: Any) -> dict[str, Any]:
        record = {
            "seq": 0,
            "ts": datetime.now(timezone.utc).isoformat(),
            "type": type,
            **fields,
        }
        with self._lock:
            self._seq += 1
            record["seq"] = self._seq
            with open(self.path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(record) + "\n")
        return record


def _tool_params() -> dict[str, set[str]]:
    return {
        definition["function"]["name"]: set(
            definition["function"]["parameters"].get("properties", {})
        )
        for definition in collectors.tool_definitions()
    }


def _fingerprints_for_kev(posture: dict) -> list[dict]:
    """Flatten cached web-posture fingerprints for KEV matching."""
    fingerprints: list[dict] = []
    for host in posture.get("hosts", []) or []:
        hostname = host.get("host")
        for fingerprint in host.get("fingerprints", []) or []:
            if isinstance(fingerprint, dict):
                fingerprints.append({**fingerprint, "host": hostname})
    return fingerprints


class RunContext:
    """Holds one digest run: outputs cache, net limits, trace writer.

    Constructing the context resets the per-run ``net.py`` request
    limits for the target domain.
    """

    def __init__(
        self,
        *,
        digest_id: str,
        domain: str,
        company_name: str,
        aliases: list[str],
        run_dir: Path,
    ) -> None:
        self.digest_id = digest_id
        self.domain = domain
        self.company_name = company_name
        self.aliases = aliases
        self.run_dir = run_dir
        self.outputs: dict[str, dict] = {}
        self.trace = TraceWriter(run_dir / "trace.jsonl")
        self._params = _tool_params()
        begin_run(domain)

    def run_tool(
        self, tool_name: str, args: dict[str, Any], parallel_group: int
    ) -> dict:
        """Execute one collector call, traced and cached by tool name.

        The run's domain always wins over a model-supplied one, and
        unknown tools fail as error outputs rather than raising.
        """
        self.trace.event(
            "tool_call_start",
            tool=tool_name,
            args=args,
            parallel_group=parallel_group,
        )
        started = time.monotonic()
        try:
            output = self._execute(tool_name, args or {}, parallel_group)
            status = output.get("status", "ok")
        except Exception as exc:  # never let one tool kill the run
            output = {
                "status": "error",
                "error": f"{type(exc).__name__}: {exc}",
            }
            status = "error"
        duration_ms = round((time.monotonic() - started) * 1000, 1)
        self.trace.event(
            "tool_call_end",
            tool=tool_name,
            parallel_group=parallel_group,
            duration_ms=duration_ms,
            status=status,
        )
        self.outputs[tool_name] = output
        return output

    def _execute(
        self, tool_name: str, args: dict[str, Any], parallel_group: int
    ) -> dict:
        allowed = self._params.get(tool_name)
        if allowed is None:
            return {
                "status": "error",
                "error": f"unknown tool: {tool_name}",
            }
        call_args = {
            key: value
            for key, value in args.items()
            if key in allowed and key != "domain"
        }
        if tool_name == "search_public_incidents":
            call_args["company_name"] = self.company_name
            call_args["aliases"] = self.aliases
        if tool_name == "match_known_exploited":
            return self._run_kev(parallel_group)
        return registry_run(tool_name, self.domain, **call_args)

    def _run_kev(self, parallel_group: int) -> dict:
        """KEV matching over cached web-posture fingerprints.

        Runs web posture through this context first when absent, so the
        result is cached; either way no host is fetched twice.
        """
        posture = self.outputs.get("check_web_posture")
        if posture is None:
            posture = self.run_tool("check_web_posture", {}, parallel_group)
        fingerprints = _fingerprints_for_kev(posture)
        return registry_run(
            "match_known_exploited", self.domain, fingerprints=fingerprints
        )
