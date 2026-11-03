"""Tests for pe_risk_key.api.app (TestClient, mocked runs). No network."""

import hashlib
import json
import re
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import pe_risk_key.api.app as api


@pytest.fixture
def api_env(monkeypatch, tmp_path):
    monkeypatch.setattr(api, "RUNS_DIR", tmp_path / "runs")
    monkeypatch.setattr(api, "UPLOAD_DIR", tmp_path / "uploads")
    (tmp_path / "runs").mkdir()
    return tmp_path


@pytest.fixture
def client(api_env):
    return TestClient(api.app)


def _post_body(**overrides):
    body = {
        "domain": "acme.example",
        "company": "Acme",
        "employee_band": "201-1000",
        "revenue_band": "50M-250M",
    }
    body.update(overrides)
    return body


def _run_dir(api_env, digest_id="dg_aaaaaaaaaaaa"):
    run_dir = api_env / "runs" / digest_id
    run_dir.mkdir(parents=True, exist_ok=True)
    return run_dir


def _write_trace(run_dir, events):
    with open(run_dir / "trace.jsonl", "a", encoding="utf-8") as fh:
        for event in events:
            fh.write(json.dumps(event) + "\n")


def _event(seq, type, ts=None, **fields):
    return {
        "seq": seq,
        "ts": ts or "2026-01-01T00:00:00+00:00",
        "type": type,
        **fields,
    }


def _collect_sse(response):
    """Parse an SSE response into [(event, id, data-text)] frames."""
    frames = []
    current: dict = {}
    for line in response.iter_lines():
        if not line:
            if current:
                frames.append(current)
                current = {}
            continue
        if line.startswith("event:"):
            current["event"] = line[len("event:"):].strip()
        elif line.startswith("id:"):
            current["id"] = line[len("id:"):].strip()
        elif line.startswith("data:"):
            current.setdefault("data", []).append(
                line[len("data:"):].strip()
            )
    if current:
        frames.append(current)
    return frames


def test_upload_stores_and_dedupes(client, api_env):
    content = b"%PDF-fake-bytes"
    first = client.post(
        "/api/uploads", files={"file": ("report.pdf", content)}
    )
    assert first.status_code == 200
    sha = hashlib.sha256(content).hexdigest()
    assert first.json() == {
        "upload_id": sha,
        "sha256": sha,
        "filename": "report.pdf",
        "kind": "document",
    }
    assert (api_env / "uploads" / sha / "report.pdf").read_bytes() == content
    second = client.post(
        "/api/uploads", files={"file": ("other.pdf", content)}
    )
    assert second.json()["upload_id"] == sha
    assert second.json()["filename"] == "report.pdf"
    assert sorted(
        path.name for path in (api_env / "uploads" / sha).iterdir()
    ) == ["report.pdf"]
    audio = client.post(
        "/api/uploads", files={"file": ("iv.wav", b"RIFF-data")}
    )
    assert audio.json()["kind"] == "interview"


def test_post_starts_run_and_file_appears(client, api_env, monkeypatch):
    captured: dict = {}
    started = threading.Event()

    def fake_run_digest(**kwargs):
        captured.update(kwargs)
        started.set()
        run_dir = api_env / "runs" / kwargs["digest_id"]
        run_dir.mkdir(parents=True)
        (run_dir / "digest.json").write_text(
            json.dumps({"digest_id": kwargs["digest_id"]}),
            encoding="utf-8",
        )

    monkeypatch.setattr(api, "run_digest", fake_run_digest)
    upload = client.post(
        "/api/uploads", files={"file": ("soc2.md", b"# SOC 2")}
    )
    response = client.post(
        "/api/digests",
        json=_post_body(soc2_upload_id=upload.json()["upload_id"]),
    )
    assert response.status_code == 202
    digest_id = response.json()["digest_id"]
    assert re.fullmatch(r"dg_[a-z0-9]{12}", digest_id)
    assert started.wait(5)
    deadline = time.time() + 5
    while not (api_env / "runs" / digest_id / "digest.json").exists():
        assert time.time() < deadline
        time.sleep(0.05)
    assert captured["soc2_path"].name == "soc2.md"


def test_post_rejects_unknown_upload(client):
    response = client.post(
        "/api/digests", json=_post_body(soc2_upload_id="0" * 64)
    )
    assert response.status_code == 400


def test_sse_streams_ordered_events_and_done(client, api_env):
    run_dir = _run_dir(api_env)
    _write_trace(
        run_dir,
        [
            _event(1, "run_start"),
            _event(2, "stage", stage="collecting"),
        ],
    )

    def finish():
        time.sleep(0.5)
        _write_trace(
            run_dir, [_event(3, "run_end", usage={"a": 1})]
        )

    writer = threading.Thread(target=finish, daemon=True)
    writer.start()
    with client.stream(
        "GET", f"/api/digests/{run_dir.name}/events"
    ) as response:
        assert response.status_code == 200
        frames = _collect_sse(response)
    writer.join(timeout=5)
    assert [frame.get("id") for frame in frames[:3]] == ["1", "2", "3"]
    first = json.loads("".join(frames[0]["data"]))
    assert (first["seq"], first["type"]) == (1, "run_start")
    assert frames[-1].get("event") == "done"
    with client.stream(
        "GET",
        f"/api/digests/{run_dir.name}/events",
        headers={"Last-Event-ID": "2"},
    ) as response:
        resumed = _collect_sse(response)
    assert [frame.get("id") for frame in resumed[:1]] == ["3"]
    assert resumed[-1].get("event") == "done"


def test_replay_respects_clamps(client, api_env):
    run_dir = _run_dir(api_env, "dg_bbbbbbbbbbbb")
    base = datetime(2026, 1, 1, tzinfo=timezone.utc).timestamp()
    _write_trace(
        run_dir,
        [
            _event(
                1,
                "run_start",
                datetime.fromtimestamp(base, timezone.utc).isoformat(),
            ),
            _event(
                2,
                "stage",
                datetime.fromtimestamp(base + 0.01, timezone.utc).isoformat(),
            ),
            _event(
                3,
                "run_end",
                datetime.fromtimestamp(base + 30, timezone.utc).isoformat(),
            ),
        ],
    )
    arrivals: list[float] = []
    with client.stream(
        "GET", f"/api/digests/{run_dir.name}/events?replay=1"
    ) as response:
        assert response.status_code == 200
        for line in response.iter_lines():
            if line.startswith("data:"):
                arrivals.append(time.monotonic())
    assert len(arrivals) == 4  # 3 events + done
    assert 0.14 <= arrivals[1] - arrivals[0] <= 1.0
    assert 2.9 <= arrivals[2] - arrivals[1] <= 3.6


def test_replay_incomplete_run_errors(client, api_env):
    run_dir = _run_dir(api_env, "dg_cccccccccccc")
    _write_trace(run_dir, [_event(1, "run_start")])
    with client.stream(
        "GET", f"/api/digests/{run_dir.name}/events?replay=1"
    ) as response:
        frames = _collect_sse(response)
    assert frames[-1].get("event") == "error"


def test_list_digests(client, api_env):
    run_dir = _run_dir(api_env)
    (run_dir / "digest.json").write_text(
        json.dumps(
            {
                "digest_id": run_dir.name,
                "generated_at": "2026-01-01T00:00:00+00:00",
                "target": {"name": "Acme", "domain": "acme.example"},
                "overall": {
                    "rating": "C",
                    "deal_signal": "proceed_with_conditions",
                },
            }
        ),
        encoding="utf-8",
    )
    _write_trace(
        run_dir, [_event(9, "run_end", usage={"estimated_cost_usd": 0.5})]
    )
    body = client.get("/api/digests").json()["digests"]
    assert len(body) == 1
    (entry,) = body
    assert entry["digest_id"] == run_dir.name
    assert entry["status"] == "done"
    assert entry["target"]["domain"] == "acme.example"
    assert entry["rating"] == "C"
    assert entry["decision"] == "Proceed with conditions"
    assert entry["generated_at"] == "2026-01-01T00:00:00+00:00"
    assert entry["cost"] == 0.5


def test_root_serves_dashboard(client):
    response = client.get("/")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/html")
    assert "PE Risk Key" in response.text
    assert 'src="/app.js"' in response.text


def test_app_js_api_paths_exist_in_routes():
    web_app = (
        Path(api.__file__).resolve().parents[3] / "web" / "app.js"
    )
    refs = set(
        re.sub(r"\$\{[^}]*\}", "{}", match.rstrip("/"))
        for match in re.findall(
            r"""["'`](\/api\/[^"'`?+\s]*)""",
            web_app.read_text(encoding="utf-8"),
        )
    )
    assert refs, "no /api/ references found in app.js"
    routes = {
        re.sub(r"\{[^}]*\}", "{}", route.path)
        for route in api.app.routes
        if getattr(route, "path", "").startswith("/api")
    }
    assert refs <= routes, f"missing routes for {sorted(refs - routes)}"


def test_app_js_selectors_are_native():
    web_app = (
        Path(api.__file__).resolve().parents[3] / "web" / "app.js"
    )
    selectors = re.findall(
        r"""(?:querySelectorAll|querySelector|matches|closest)"""
        r"""\(\s*["'`]([^"'`]*)["'`]""",
        web_app.read_text(encoding="utf-8"),
    )
    assert selectors, "no selectors found in app.js"
    bad = [s for s in selectors if "!=" in s]
    assert not bad, f"non-native selectors: {bad}"


def test_digest_memo_trace_endpoints(client, api_env):
    run_dir = _run_dir(api_env)
    (run_dir / "digest.json").write_text(
        json.dumps({"digest_id": run_dir.name}), encoding="utf-8"
    )
    (run_dir / "ic_memo.md").write_text("# Memo", encoding="utf-8")
    _write_trace(run_dir, [_event(1, "run_start")])
    digest = client.get(f"/api/digests/{run_dir.name}")
    assert digest.json() == {"digest_id": run_dir.name}
    memo = client.get(f"/api/digests/{run_dir.name}/memo")
    assert memo.status_code == 200
    assert memo.headers["content-type"].startswith("text/markdown")
    assert f"{run_dir.name}_memo.md" in memo.headers["content-disposition"]
    trace = client.get(f"/api/digests/{run_dir.name}/trace")
    assert [e["seq"] for e in trace.json()["events"]] == [1]
    assert client.get("/api/digests/dg_zzzzzzzzzzzz").status_code == 404
    assert client.get("/api/digests/../app").status_code in (404, 422)
