# SPDX-License-Identifier: AGPL-3.0-or-later
"""Local REST + SSE API for digests (dashboard backend)."""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import re
import threading
from datetime import date, datetime
from pathlib import Path
from typing import Any

from fastapi import (
    FastAPI,
    File,
    Header,
    HTTPException,
    Query,
    Request,
    UploadFile,
)
from fastapi.responses import FileResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from pe_risk_key.agent.context import new_digest_id
from pe_risk_key.agent.orchestrator import run_digest
from pe_risk_key.engine.narrative import DEAL_SIGNAL_LABELS
from pe_risk_key.validate import validate_digest

NARRATIVE_PENDING = "Narrative pending."

ROOT = Path(__file__).resolve().parents[3]
RUNS_DIR = ROOT / "eval" / "runs"
UPLOAD_DIR = ROOT / ".uploads"
WEB_DIR = ROOT / "web"

AUDIO_SUFFIXES = {".wav", ".mp3", ".m4a", ".flac", ".ogg", ".opus"}
REPLAY_MIN_SECONDS = 0.15
REPLAY_MAX_SECONDS = 3.0

app = FastAPI(title="PE Risk Key")

jobs: dict[str, dict[str, Any]] = {}
_jobs_lock = threading.Lock()


class DigestRequest(BaseModel):
    domain: str
    company: str
    aliases: list[str] = []
    employee_band: str
    revenue_band: str
    industry: str | None = None
    soc2_upload_id: str | None = None
    interview_upload_id: str | None = None
    speaker_names: list[str] | None = None
    target_speaker: str | None = None
    as_of: date | None = None
    demo: bool = False


def _run_dir_or_404(digest_id: str) -> Path:
    if not re.fullmatch(r"dg_[a-z0-9]{12}", digest_id or ""):
        raise HTTPException(status_code=404, detail="Unknown digest.")
    run_dir = RUNS_DIR / digest_id
    try:
        run_dir.resolve().relative_to(RUNS_DIR.resolve())
    except (OSError, ValueError):
        raise HTTPException(status_code=404, detail="Unknown digest.")
    if not run_dir.is_dir():
        raise HTTPException(status_code=404, detail="Unknown digest.")
    return run_dir


def _read_events(run_dir: Path) -> list[dict[str, Any]]:
    trace = run_dir / "trace.jsonl"
    if not trace.exists():
        return []
    events = []
    for line in trace.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return events


def _run_cost(run_dir: Path) -> float | None:
    for event in reversed(_read_events(run_dir)):
        if event.get("type") == "run_end":
            cost = event.get("usage", {}).get("estimated_cost_usd")
            return cost if isinstance(cost, (int, float)) else None
    return None


def _run_target(run_dir: Path) -> dict[str, Any]:
    for event in _read_events(run_dir):
        if event.get("type") == "run_start":
            return {
                "domain": event.get("domain"),
                "name": event.get("company_name"),
            }
    return {}


def _job_failed(digest_id: str) -> dict[str, Any] | None:
    with _jobs_lock:
        job = jobs.get(digest_id)
    if job is not None and job.get("status") == "error":
        return job
    return None


def _store_upload(filename: str, content: bytes) -> dict[str, str]:
    """Store bytes under .uploads/<sha256>/; dedupe by sha256."""
    sha256 = hashlib.sha256(content).hexdigest()
    target_dir = UPLOAD_DIR / sha256
    clean = Path(filename or "upload").name or "upload"
    if target_dir.is_dir():
        existing = sorted(
            path.name for path in target_dir.iterdir() if path.is_file()
        )
        if existing:
            clean = existing[0]
        else:
            (target_dir / clean).write_bytes(content)
    else:
        target_dir.mkdir(parents=True, exist_ok=True)
        (target_dir / clean).write_bytes(content)
    kind = (
        "interview"
        if Path(clean).suffix.lower() in AUDIO_SUFFIXES
        else "document"
    )
    return {
        "upload_id": sha256,
        "sha256": sha256,
        "filename": clean,
        "kind": kind,
    }


def _upload_path(upload_id: str | None) -> Path | None:
    if upload_id is None:
        return None
    if not re.fullmatch(r"[a-f0-9]{64}", upload_id or ""):
        raise HTTPException(
            status_code=400, detail=f"Invalid upload id: {upload_id!r}."
        )
    target_dir = UPLOAD_DIR / upload_id
    files = (
        sorted(path for path in target_dir.iterdir() if path.is_file())
        if target_dir.is_dir()
        else []
    )
    if not files:
        raise HTTPException(
            status_code=400, detail=f"Unknown upload id: {upload_id}."
        )
    return files[0]


def _run_worker(
    digest_id: str, kwargs: dict[str, Any], demo: bool
) -> None:
    with _jobs_lock:
        jobs[digest_id] = {"status": "running"}
    try:
        # NOTE: DEMO_MODE is process-global (collectors/scoring read env),
        # so concurrent runs with mixed demo flags can interfere. Each
        # run asserts its own flag at start; single-user local use only.
        if demo:
            os.environ["DEMO_MODE"] = "1"
        else:
            os.environ.pop("DEMO_MODE", None)
        run_digest(digest_id=digest_id, **kwargs)
    except Exception as exc:
        with _jobs_lock:
            jobs[digest_id] = {
                "status": "error",
                "error": f"{type(exc).__name__}: {exc}",
            }
        return
    with _jobs_lock:
        jobs[digest_id] = {"status": "done"}


def _sse(
    data: str, event: str | None = None, id: str | None = None
) -> str:
    out = ""
    if event is not None:
        out += f"event: {event}\n"
    if id is not None:
        out += f"id: {id}\n"
    for chunk in data.split("\n"):
        out += f"data: {chunk}\n"
    return out + "\n"


def _event_ts(event: dict[str, Any]) -> float:
    try:
        return datetime.fromisoformat(event.get("ts", "")).timestamp()
    except (TypeError, ValueError):
        return 0.0


@app.post("/api/digests", status_code=202)
def create_digest(body: DigestRequest) -> dict[str, str]:
    """Start a digest run in a background thread; returns its id."""
    kwargs: dict[str, Any] = {
        "domain": body.domain,
        "company_name": body.company,
        "employee_band": body.employee_band,
        "revenue_band": body.revenue_band,
        "aliases": body.aliases,
        "industry": body.industry,
    }
    soc2_path = _upload_path(body.soc2_upload_id)
    if soc2_path is not None:
        kwargs["soc2_path"] = soc2_path
    interview_path = _upload_path(body.interview_upload_id)
    if interview_path is not None:
        kwargs["interview_path"] = interview_path
        kwargs["speaker_names"] = body.speaker_names
        kwargs["target_speakers"] = (
            [body.target_speaker] if body.target_speaker else []
        )
    if body.as_of is not None:
        kwargs["as_of"] = body.as_of
    digest_id = new_digest_id()
    thread = threading.Thread(
        target=_run_worker, args=(digest_id, kwargs, body.demo), daemon=True
    )
    thread.start()
    return {"digest_id": digest_id}


@app.post("/api/uploads")
async def upload_file(file: UploadFile = File(...)) -> dict[str, str]:
    """Store an upload content-addressed; dedupes by sha256."""
    return _store_upload(file.filename or "upload", await file.read())


@app.get("/api/digests")
def list_digests() -> dict[str, list[dict[str, Any]]]:
    """Runs from eval/runs/, newest first, with digest state."""
    runs: list[dict[str, Any]] = []
    seen: set[str] = set()
    dirs = (
        sorted(
            (d for d in RUNS_DIR.iterdir() if d.is_dir()),
            key=lambda d: d.stat().st_mtime,
            reverse=True,
        )
        if RUNS_DIR.is_dir()
        else []
    )
    for run_dir in dirs:
        seen.add(run_dir.name)
        digest_path = run_dir / "digest.json"
        if digest_path.exists():
            try:
                digest = json.loads(digest_path.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                continue
            if not isinstance(digest, dict):
                continue
            overall = digest.get("overall", {})
            inputs = digest.get("inputs", {})
            schema_valid = not validate_digest(digest)
            summary = digest.get("narrative", {}).get("executive_summary")
            complete = (
                schema_valid
                and bool(summary)
                and summary != NARRATIVE_PENDING
            )
            runs.append(
                {
                    "digest_id": run_dir.name,
                    "status": "done",
                    "target": digest.get("target", {}),
                    "rating": overall.get("rating"),
                    "decision": DEAL_SIGNAL_LABELS.get(
                        overall.get("deal_signal"), overall.get("deal_signal")
                    ),
                    "deal_signal": overall.get("deal_signal"),
                    "generated_at": digest.get("generated_at"),
                    "cost": _run_cost(run_dir),
                    "complete": complete,
                    "schema_valid": schema_valid,
                    "has_soc2": bool(inputs.get("documents")),
                    "has_interview": bool(inputs.get("interviews")),
                }
            )
            continue
        with _jobs_lock:
            job = jobs.get(run_dir.name)
        if job is not None and job.get("status") in ("running", "error"):
            runs.append(
                {
                    "digest_id": run_dir.name,
                    "status": job["status"],
                    "target": _run_target(run_dir),
                    "rating": None,
                    "decision": None,
                    "deal_signal": None,
                    "generated_at": None,
                    "cost": None,
                    "complete": False,
                    "schema_valid": False,
                    "has_soc2": False,
                    "has_interview": False,
                    **(
                        {"error": job["error"]}
                        if job.get("status") == "error"
                        else {}
                    ),
                }
            )
    with _jobs_lock:
        pending = [
            (digest_id, job)
            for digest_id, job in jobs.items()
            if digest_id not in seen and job.get("status") != "done"
        ]
    for digest_id, job in pending:
        runs.append(
            {
                "digest_id": digest_id,
                "status": job["status"],
                "target": {},
                "rating": None,
                "decision": None,
                "deal_signal": None,
                "generated_at": None,
                "cost": None,
                "complete": False,
                "schema_valid": False,
                "has_soc2": False,
                "has_interview": False,
            }
        )
    dated = sorted(
        (run for run in runs if run["generated_at"]),
        key=lambda run: run["generated_at"],
        reverse=True,
    )
    undated = [run for run in runs if not run["generated_at"]]
    return {"digests": dated + undated}


@app.get("/api/digests/{digest_id}")
def get_digest(digest_id: str) -> Any:
    """The digest.json of one run."""
    digest_path = _run_dir_or_404(digest_id) / "digest.json"
    if not digest_path.exists():
        raise HTTPException(status_code=404, detail="Digest not ready.")
    return json.loads(digest_path.read_text(encoding="utf-8"))


@app.get("/api/digests/{digest_id}/memo")
def get_memo(digest_id: str) -> FileResponse:
    """The IC memo markdown with a download filename."""
    memo_path = _run_dir_or_404(digest_id) / "ic_memo.md"
    if not memo_path.exists():
        raise HTTPException(status_code=404, detail="Memo not ready.")
    return FileResponse(
        memo_path,
        media_type="text/markdown",
        filename=f"{digest_id}_memo.md",
    )


@app.get("/api/digests/{digest_id}/trace")
def get_trace(digest_id: str) -> dict[str, Any]:
    """The full trace event list of one run."""
    return {
        "digest_id": digest_id,
        "events": _read_events(_run_dir_or_404(digest_id)),
    }


@app.get("/api/digests/{digest_id}/events")
async def stream_events(
    digest_id: str,
    request: Request,
    replay: bool = Query(False),
    last_event_id: str | None = Header(None),
) -> StreamingResponse:
    """SSE tail of trace.jsonl, then done (or error).

    Reconnects resume after Last-Event-ID. ?replay=1 replays a
    completed run's trace with original inter-event delays clamped to
    150 ms–3 s.
    """
    run_dir = _run_dir_or_404(digest_id)
    try:
        last_id = int(last_event_id) if last_event_id is not None else 0
    except ValueError:
        last_id = 0

    async def live() -> Any:
        nonlocal last_id
        trace = run_dir / "trace.jsonl"
        waited = 0.0
        while not trace.exists():
            failed = _job_failed(digest_id)
            if failed is not None:
                yield _sse(
                    json.dumps(
                        {
                            "status": "error",
                            "error": failed.get("error", "run failed"),
                        }
                    ),
                    event="error",
                )
                return
            if await request.is_disconnected():
                return
            await asyncio.sleep(0.2)
            waited += 0.2
            if waited > 30:
                yield _sse(
                    json.dumps(
                        {"status": "error", "error": "trace not started"}
                    ),
                    event="error",
                )
                return
        while True:
            if await request.is_disconnected():
                return
            for event in _read_events(run_dir):
                seq = event.get("seq", 0)
                if isinstance(seq, int) and seq > last_id:
                    last_id = seq
                    yield _sse(json.dumps(event), id=str(seq))
                    if event.get("type") == "run_end":
                        yield _sse(
                            json.dumps({"status": "done"}), event="done"
                        )
                        return
            failed = _job_failed(digest_id)
            if failed is not None:
                yield _sse(
                    json.dumps(
                        {
                            "status": "error",
                            "error": failed.get("error", "run failed"),
                        }
                    ),
                    event="error",
                )
                return
            await asyncio.sleep(0.2)

    async def replay_run() -> Any:
        events = _read_events(run_dir)
        if not any(event.get("type") == "run_end" for event in events):
            yield _sse(
                json.dumps(
                    {
                        "status": "error",
                        "error": "replay needs a completed run",
                    }
                ),
                event="error",
            )
            return
        previous: float | None = None
        for event in events:
            stamp = _event_ts(event)
            if previous is not None:
                delay = min(
                    REPLAY_MAX_SECONDS,
                    max(REPLAY_MIN_SECONDS, stamp - previous),
                )
                await asyncio.sleep(delay)
            previous = stamp
            seq = event.get("seq", "")
            yield _sse(json.dumps(event), id=str(seq))
        yield _sse(json.dumps({"status": "done"}), event="done")

    generator = replay_run() if replay else live()
    return StreamingResponse(
        generator,
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache"},
    )


@app.get("/api/demo-inputs")
def demo_inputs() -> dict[str, Any]:
    """Brightwater fixture paths plus default form values.

    Fixture files are staged as uploads so the returned ids can be
    submitted directly to POST /api/digests.
    """
    soc2_src = ROOT / "fixtures" / "documents" / "brightwater_soc2_type2.md"
    interview_src = (
        ROOT / "fixtures" / "interviews" / "brightwater_cto_interview.wav"
    )

    def staged(source: Path) -> dict[str, Any] | None:
        if not source.exists():
            return None
        stored = _store_upload(source.name, source.read_bytes())
        return {
            "path": str(source.relative_to(ROOT)),
            **stored,
        }

    return {
        "domain": "brightwaterfleet.example",
        "company": "Brightwater Fleet Systems, Inc.",
        "aliases": [],
        "employee_band": "201-1000",
        "revenue_band": "50M-250M",
        "speaker_names": ["Diligence Lead", "Dana Reyes (CTO)"],
        "target_speaker": "Dana Reyes (CTO)",
        "as_of": date.today().isoformat(),
        "soc2": staged(soc2_src),
        "interview": staged(interview_src),
    }


app.mount("/", StaticFiles(directory=WEB_DIR, html=True), name="web")
