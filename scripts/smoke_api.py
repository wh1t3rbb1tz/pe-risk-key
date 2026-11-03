# SPDX-License-Identifier: AGPL-3.0-or-later
"""End-to-end smoke test against a running API server (127.0.0.1:8000).

Fetches demo inputs, uploads the demo fixtures, posts a digest run,
streams its events, prints the result, then replays the trace.
Exits non-zero on error or if the live run or the replay exceeds
3 minutes each.
"""

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Any

import httpx

ROOT = Path(__file__).resolve().parents[1]
TIMEOUT_S = 180.0


def _detail(event: dict[str, Any]) -> str:
    """One short detail per event type for the stream printout."""
    event_type = event.get("type", "?")
    if event_type in ("tool_call_start", "tool_call_end"):
        detail = str(event.get("tool", ""))
        if event.get("status"):
            detail += f" {event['status']}"
        if event.get("duration_ms") is not None:
            detail += f" {event['duration_ms']}ms"
        return detail
    if event_type == "stage":
        return str(event.get("stage", ""))
    if event_type == "crosscheck_verdict":
        return (
            f"{event.get('contradiction_id', '')} "
            f"{event.get('verdict', '')} {event.get('severity', '')}"
        ).strip()
    if event_type in ("model_turn_start", "model_turn_end"):
        return f"turn={event.get('turn', '?')}"
    if event_type == "plan":
        return str(event.get("text", ""))[:60].replace("\n", " ")
    if event_type == "submit_findings":
        return f"count={event.get('count', '?')}"
    if event_type == "coverage_gap":
        return ",".join(event.get("missing", []))
    if event_type == "validation_error":
        return str(event.get("finding_id", ""))
    if event_type == "engine_adjustment":
        return f"{event.get('finding_id', '')} {event.get('field', '')}"
    if event_type == "claims_merged":
        return f"{event.get('before', '?')}->{event.get('after', '?')}"
    if event_type == "crosscheck_complete":
        return (
            f"{event.get('contradiction_count', '?')} verdicts "
            f"cost=${event.get('cost_usd', '?')}"
        )
    if event_type == "scoring_complete":
        overall = event.get("overall") or {}
        return f"rating={overall.get('rating', '?')}"
    if event_type == "narrative_complete":
        return (
            f"valid={event.get('valid', '?')} "
            f"attempts={event.get('attempts', '?')}"
        )
    if event_type in ("digest_preview", "digest_final"):
        overall = (event.get("digest") or {}).get("overall", {})
        return f"rating={overall.get('rating', '?')}"
    if event_type in ("document_analysis_start", "document_analysis_end"):
        return str(event.get("doc_id", ""))
    if event_type in ("transcription_start", "transcription_end"):
        return str(event.get("interview_id", ""))
    if event_type == "run_end":
        usage = event.get("usage") or {}
        return f"cost=${usage.get('estimated_cost_usd', '?')}"
    return ""


def _upload(
    client: httpx.Client, kind: str, path: str
) -> dict[str, Any]:
    file_path = ROOT / path
    with open(file_path, "rb") as handle:
        response = client.post(
            "/api/uploads", files={"file": (file_path.name, handle)}
        )
    response.raise_for_status()
    body = response.json()
    print(f"uploaded {kind}: {body['filename']} ({body['upload_id'][:12]}…)")
    return body


def _stream_events(
    client: httpx.Client, url: str, deadline: float, verbose: bool
) -> tuple[str, int, dict[str, Any] | None]:
    """Follow one SSE stream; returns (terminal, event count, run_end)."""
    started = time.monotonic()
    count = 0
    run_end: dict[str, Any] | None = None
    terminal = "timeout"
    with client.stream("GET", url) as response:
        response.raise_for_status()
        frame_event: str | None = None
        frame_data: list[str] = []
        for line in response.iter_lines():
            if time.monotonic() > deadline:
                return terminal, count, run_end
            if line:
                if line.startswith("event:"):
                    frame_event = line[len("event:"):].strip()
                elif line.startswith("data:"):
                    frame_data.append(line[len("data:"):].strip())
                continue
            if not frame_event and not frame_data:
                continue
            payload = "".join(frame_data)
            if frame_event in ("done", "error"):
                terminal = frame_event
                if frame_event == "error":
                    print(f"server error event: {payload}", file=sys.stderr)
                break
            count += 1
            try:
                event = json.loads(payload)
            except json.JSONDecodeError:
                event = {"seq": "?", "type": "?"}
            if event.get("type") == "run_end":
                run_end = event
            if verbose:
                elapsed = time.monotonic() - started
                detail = _detail(event)
                print(
                    f"{elapsed:7.2f}s seq={event.get('seq', '?')} "
                    f"{event.get('type', '?')} {detail}".rstrip()
                )
            frame_event, frame_data = None, []
    return terminal, count, run_end


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--base-url", default="http://127.0.0.1:8000",
        help="running API server",
    )
    args = parser.parse_args()
    try:
        with httpx.Client(
            base_url=args.base_url,
            timeout=httpx.Timeout(10.0, read=TIMEOUT_S),
        ) as client:
            demo = client.get("/api/demo-inputs")
            demo.raise_for_status()
            demo_inputs = demo.json()
            print(
                f"demo target: {demo_inputs['company']} "
                f"({demo_inputs['domain']})"
            )
            soc2 = _upload(client, "soc2", demo_inputs["soc2"]["path"])
            interview = _upload(
                client, "interview", demo_inputs["interview"]["path"]
            )
            posted = client.post(
                "/api/digests",
                json={
                    "domain": demo_inputs["domain"],
                    "company": demo_inputs["company"],
                    "aliases": demo_inputs["aliases"],
                    "employee_band": demo_inputs["employee_band"],
                    "revenue_band": demo_inputs["revenue_band"],
                    "soc2_upload_id": soc2["upload_id"],
                    "interview_upload_id": interview["upload_id"],
                    "speaker_names": demo_inputs["speaker_names"],
                    "target_speaker": demo_inputs["target_speaker"],
                    "as_of": demo_inputs["as_of"],
                    "demo": True,
                },
            )
            posted.raise_for_status()
            digest_id = posted.json()["digest_id"]
            print(f"digest_id: {digest_id}")

            terminal, count, run_end = _stream_events(
                client,
                f"/api/digests/{digest_id}/events",
                time.monotonic() + TIMEOUT_S,
                verbose=True,
            )
            if terminal == "timeout":
                print("timed out waiting for run", file=sys.stderr)
                return 1
            if terminal == "error":
                return 1
            print(f"stream done: {count} events")

            digest_response = client.get(f"/api/digests/{digest_id}")
            digest_response.raise_for_status()
            digest = digest_response.json()
            from pe_risk_key.engine.narrative import DEAL_SIGNAL_LABELS

            overall = digest.get("overall", {})
            decision = DEAL_SIGNAL_LABELS.get(
                overall.get("deal_signal", ""), overall.get("deal_signal")
            )
            usage = (run_end or {}).get("usage") or {}
            print(f"rating: {overall.get('rating')}")
            print(f"decision: {decision}")
            print(
                "contradictions: "
                f"{len(digest.get('contradictions', []))}"
            )
            print(f"cost: ${usage.get('estimated_cost_usd', '?')}")

            replay_started = time.monotonic()
            terminal, replay_count, _ = _stream_events(
                client,
                f"/api/digests/{digest_id}/events?replay=1",
                time.monotonic() + TIMEOUT_S,
                verbose=False,
            )
            if terminal != "done":
                print(f"replay ended with {terminal}", file=sys.stderr)
                return 1
            replay_elapsed = time.monotonic() - replay_started
            print(
                f"replay: {replay_elapsed:.1f}s, {replay_count} events"
            )
    except httpx.HTTPError as exc:
        print(f"http error: {exc}", file=sys.stderr)
        return 1
    except FileNotFoundError as exc:
        print(f"missing fixture: {exc.filename}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
