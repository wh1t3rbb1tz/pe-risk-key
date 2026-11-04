# SPDX-License-Identifier: AGPL-3.0-or-later
"""Local REST + SSE API for digests (dashboard backend)."""

from __future__ import annotations

import asyncio
import hashlib
import ipaddress
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


def resolve_runs_dir() -> Path:
    """Runs directory, overridable via PE_RISK_KEY_RUNS_DIR."""
    override = os.getenv("PE_RISK_KEY_RUNS_DIR")
    return Path(override) if override else ROOT / "eval" / "runs"


RUNS_DIR = resolve_runs_dir()
UPLOAD_DIR = ROOT / ".uploads"
WEB_DIR = ROOT / "web"

# Server-known demo fixtures for use_demo_inputs. Clients never send
# paths; the flag resolves to these files, demo flag only.
DEMO_SOC2_PATH = ROOT / "fixtures" / "documents" / "brightwater_soc2_type2.md"
DEMO_INTERVIEW_PATH = (
    ROOT / "fixtures" / "interviews" / "brightwater_cto_interview.wav"
)

MAX_UPLOAD_BYTES = 25 * 1024 * 1024
ALLOWED_UPLOAD_SUFFIXES = frozenset({".pdf", ".md", ".txt", ".wav", ".m4a"})
UPLOAD_AUDIO_SUFFIXES = frozenset({".wav", ".m4a"})
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
    use_demo_inputs: bool = False


_DOMAIN_LABEL_RE = re.compile(r"[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?")
_DOMAIN_FORBIDDEN_CHARS = frozenset("/:@?# \t\r\n")


def validate_domain(domain: str) -> str:
    """Normalize a target domain; reject IPs, URLs, and bad hostnames."""
    value = (domain or "").strip().rstrip(".").lower()
    if not value or len(value) > 253:
        raise HTTPException(
            status_code=400, detail=f"Invalid domain: {domain!r}."
        )
    if any(char in value for char in _DOMAIN_FORBIDDEN_CHARS):
        raise HTTPException(
            status_code=400,
            detail=f"Invalid domain (URL or address): {domain!r}.",
        )
    try:
        ipaddress.ip_address(value)
    except ValueError:
        pass
    else:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid domain (IP literal): {domain!r}.",
        )
    labels = value.split(".")
    if not all(_DOMAIN_LABEL_RE.fullmatch(label) for label in labels):
        raise HTTPException(
            status_code=400, detail=f"Invalid domain: {domain!r}."
        )
    if not re.search(r"[A-Za-z]", labels[-1]):
        raise HTTPException(
            status_code=400,
            detail=f"Invalid domain (numeric TLD): {domain!r}.",
        )
    return value


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


def _trace_status(run_dir: Path) -> tuple[bool, float | None, bool | None]:
    """(has_run_end, cost, narrative_valid) from trace.jsonl.

    narrative_valid is None when the run never reached narrative_complete.
    """
    has_end = False
    cost: float | None = None
    narrative_valid: bool | None = None
    for event in _read_events(run_dir):
        if event.get("type") == "run_end":
            has_end = True
            value = event.get("usage", {}).get("estimated_cost_usd")
            if isinstance(value, (int, float)):
                cost = value
        elif event.get("type") == "narrative_complete":
            narrative_valid = event.get("valid")
    return has_end, cost, narrative_valid


def _run_cost(run_dir: Path) -> float | None:
    return _trace_status(run_dir)[1]


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


def _sanitize_filename(filename: str) -> str:
    """Display-only filename: no directories, no control characters."""
    clean = re.sub(r"[^A-Za-z0-9._-]+", "_", filename or "")
    clean = clean.strip("._")[:100] or "upload"
    return clean


def _sniff_upload(suffix: str, content: bytes) -> None:
    """Reject content that does not match its claimed extension."""
    if not content:
        raise HTTPException(status_code=400, detail="Upload is empty.")
    if suffix == ".pdf":
        if not content.startswith(b"%PDF-"):
            raise HTTPException(
                status_code=400,
                detail="Upload claims .pdf but lacks PDF magic bytes.",
            )
    elif suffix == ".wav":
        if not (
            len(content) >= 12
            and content.startswith(b"RIFF")
            and content[8:12] == b"WAVE"
        ):
            raise HTTPException(
                status_code=400,
                detail="Upload claims .wav but lacks a RIFF/WAVE header.",
            )
    elif suffix == ".m4a":
        if not (len(content) >= 8 and content[4:8] == b"ftyp"):
            raise HTTPException(
                status_code=400,
                detail="Upload claims .m4a but lacks an ftyp box.",
            )
    elif suffix in (".md", ".txt"):
        try:
            content.decode("utf-8")
        except UnicodeDecodeError:
            raise HTTPException(
                status_code=400,
                detail=f"Upload claims {suffix} but is not valid UTF-8.",
            )


def _store_upload(filename: str, content: bytes) -> dict[str, str]:
    """Validate and store bytes under .uploads/<sha256>/.

    Rejects oversized, traversal, extension, and content-mismatch
    uploads. Stored files are named by sha256 (plus the validated
    extension for downstream dispatch); the user filename is returned
    sanitized for display only.
    """
    if len(content) > MAX_UPLOAD_BYTES:
        raise HTTPException(
            status_code=413, detail="Upload exceeds the 25 MB limit."
        )
    raw = filename or "upload"
    if "/" in raw or "\\" in raw:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid filename (path separators): {raw!r}.",
        )
    suffix = Path(raw).suffix.lower()
    if suffix not in ALLOWED_UPLOAD_SUFFIXES:
        raise HTTPException(
            status_code=400,
            detail=(
                f"Extension {suffix or '(none)'} not allowed; want one of "
                f"{sorted(ALLOWED_UPLOAD_SUFFIXES)}."
            ),
        )
    _sniff_upload(suffix, content)
    sha256 = hashlib.sha256(content).hexdigest()
    target_dir = UPLOAD_DIR / sha256
    target_dir.mkdir(parents=True, exist_ok=True)
    stored = target_dir / f"{sha256}{suffix}"
    if not stored.exists():
        stored.write_bytes(content)
    kind = "interview" if suffix in UPLOAD_AUDIO_SUFFIXES else "document"
    return {
        "upload_id": sha256,
        "sha256": sha256,
        "filename": _sanitize_filename(raw),
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
        "domain": validate_domain(body.domain),
        "company_name": body.company,
        "employee_band": body.employee_band,
        "revenue_band": body.revenue_band,
        "aliases": body.aliases,
        "industry": body.industry,
    }
    if body.use_demo_inputs:
        if not body.demo:
            raise HTTPException(
                status_code=422,
                detail="use_demo_inputs requires the demo flag.",
            )
        if (
            body.soc2_upload_id is not None
            or body.interview_upload_id is not None
        ):
            raise HTTPException(
                status_code=422,
                detail=(
                    "Pass either use_demo_inputs or upload ids, not both."
                ),
            )
        missing = [
            path
            for path in (DEMO_SOC2_PATH, DEMO_INTERVIEW_PATH)
            if not path.exists()
        ]
        if missing:
            raise HTTPException(
                status_code=500,
                detail=(
                    "Demo fixture missing on server: "
                    f"{missing[0].name}."
                ),
            )
        kwargs["soc2_path"] = DEMO_SOC2_PATH
        kwargs["interview_path"] = DEMO_INTERVIEW_PATH
        kwargs["speaker_names"] = body.speaker_names
        kwargs["target_speakers"] = (
            [body.target_speaker] if body.target_speaker else []
        )
    else:
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
    if "interview_path" not in kwargs and (
        body.speaker_names or (body.target_speaker or "").strip()
    ):
        raise HTTPException(
            status_code=422,
            detail=(
                "speaker_names and target_speaker require an interview: "
                "upload interview audio or load the demo target."
            ),
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
    body = await file.read(MAX_UPLOAD_BYTES + 1)
    if len(body) > MAX_UPLOAD_BYTES:
        raise HTTPException(
            status_code=413, detail="Upload exceeds the 25 MB limit."
        )
    return _store_upload(file.filename or "upload", body)


def _mark_authoritative(runs: list[dict[str, Any]]) -> None:
    """Flag one authoritative run per target domain in place.

    Among complete, schema-valid runs for a domain, the most inputs
    wins (outside-in + SOC 2 + interview beats fewer), then the
    newest. The rest point at it via superseded_by.
    """
    by_domain: dict[str, list[dict[str, Any]]] = {}
    for run in runs:
        if not (run["complete"] and run["schema_valid"]):
            continue
        domain = (run.get("target") or {}).get("domain")
        if domain:
            by_domain.setdefault(domain, []).append(run)
    for group in by_domain.values():
        ranked = sorted(
            group,
            key=lambda r: (r["input_count"], r["generated_at"] or ""),
            reverse=True,
        )
        ranked[0]["authoritative"] = True
        for other in ranked[1:]:
            other["superseded_by"] = ranked[0]["digest_id"]


@app.get("/api/digests")
def list_digests() -> dict[str, list[dict[str, Any]]]:
    """Runs from eval/runs/, newest first, with digest state.

    A run is complete when it has digest.json, a run_end event, and a
    narrative; narrative_valid is reported separately as a warning.
    """
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
            has_run_end, _, narrative_valid = _trace_status(run_dir)
            complete = (
                has_run_end
                and bool(summary)
                and summary != NARRATIVE_PENDING
            )
            has_soc2 = bool(inputs.get("documents"))
            has_interview = bool(inputs.get("interviews"))
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
                    "narrative_valid": narrative_valid,
                    "has_soc2": has_soc2,
                    "has_interview": has_interview,
                    "input_count": (1 if inputs.get("domain_scan") else 0)
                    + has_soc2
                    + has_interview,
                    "authoritative": False,
                    "superseded_by": None,
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
                    "narrative_valid": None,
                    "has_soc2": False,
                    "has_interview": False,
                    "input_count": 0,
                    "authoritative": False,
                    "superseded_by": None,
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
                "narrative_valid": None,
                "has_soc2": False,
                "has_interview": False,
                "input_count": 0,
                "authoritative": False,
                "superseded_by": None,
            }
        )
    _mark_authoritative(runs)
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
    soc2_src = DEMO_SOC2_PATH
    interview_src = DEMO_INTERVIEW_PATH
    fixture_target = json.loads(
        (
            ROOT / "fixtures" / "outside_in" / "brightwaterfleet.example.json"
        ).read_text(encoding="utf-8")
    )["target"]

    def staged(source: Path) -> dict[str, Any] | None:
        if not source.exists():
            return None
        stored = _store_upload(source.name, source.read_bytes())
        return {
            "path": str(source.relative_to(ROOT)),
            **stored,
        }

    return {
        "domain": fixture_target["domain"],
        "company": fixture_target["name"],
        "aliases": [],
        "employee_band": fixture_target["employee_band"],
        "revenue_band": fixture_target["revenue_band"],
        "speaker_names": ["Diligence Lead", "Dana Reyes (CTO)"],
        "target_speaker": "Dana Reyes (CTO)",
        "as_of": date.today().isoformat(),
        "soc2": staged(soc2_src),
        "interview": staged(interview_src),
    }


app.mount("/", StaticFiles(directory=WEB_DIR, html=True), name="web")
