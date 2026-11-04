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
    stored = api_env / "uploads" / sha / f"{sha}.pdf"
    assert stored.read_bytes() == content
    second = client.post(
        "/api/uploads", files={"file": ("other.pdf", content)}
    )
    assert second.json()["upload_id"] == sha
    assert second.json()["filename"] == "other.pdf"
    assert sorted(
        path.name for path in (api_env / "uploads" / sha).iterdir()
    ) == [f"{sha}.pdf"]
    audio = client.post(
        "/api/uploads",
        files={"file": ("iv.wav", b"RIFF\x24\x00\x00\x00WAVEfmt ")},
    )
    assert audio.json()["kind"] == "interview"


def test_upload_rejects_oversize(client, api_env, monkeypatch):
    monkeypatch.setattr(api, "MAX_UPLOAD_BYTES", 10)
    response = client.post(
        "/api/uploads", files={"file": ("big.pdf", b"%PDF-" + b"x" * 7)}
    )
    assert response.status_code == 413
    with pytest.raises(Exception, match="25 MB"):
        api._store_upload("big.pdf", b"x" * (api.MAX_UPLOAD_BYTES + 1))


def test_upload_rejects_bad_extension(client):
    response = client.post(
        "/api/uploads", files={"file": ("run.exe", b"MZ-bytes")}
    )
    assert response.status_code == 400
    assert "not allowed" in response.json()["detail"]
    response = client.post(
        "/api/uploads", files={"file": ("noext", b"data")}
    )
    assert response.status_code == 400


def test_upload_rejects_content_mismatch(client):
    cases = [
        ("fake.pdf", b"not a pdf at all"),
        ("fake.wav", b"RIFF-data"),
        ("fake.wav", b"too short"),
        ("fake.m4a", b"not an mp4 file...."),
        ("fake.md", b"\xff\xfe binary \x00"),
        ("empty.txt", b""),
    ]
    for filename, content in cases:
        response = client.post(
            "/api/uploads", files={"file": (filename, content)}
        )
        assert response.status_code == 400, filename


def test_upload_rejects_path_traversal(client, api_env):
    for filename in (
        "../../etc/evil.pdf",
        "..\\..\\evil.pdf",
        "/abs/path/evil.pdf",
        "sub/dir/evil.pdf",
    ):
        response = client.post(
            "/api/uploads",
            files={"file": (filename, b"%PDF-traversal")},
        )
        assert response.status_code == 400, filename
    stray = [
        path
        for path in (api_env / "uploads").rglob("*")
        if path.is_file()
    ]
    assert stray == []


def test_upload_sanitizes_display_name(client):
    response = client.post(
        "/api/uploads",
        files={"file": ("my report (final)!?.pdf", b"%PDF-bytes")},
    )
    assert response.status_code == 200
    assert response.json()["filename"] == "my_report_final_.pdf"


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
    assert captured["soc2_path"].name == (
        f"{upload.json()['upload_id']}.md"
    )


def test_post_validates_domains(client, monkeypatch):
    seen: list[str] = []
    started = threading.Event()

    def fake_run_digest(**kwargs):
        seen.append(kwargs["domain"])
        started.set()

    monkeypatch.setattr(api, "run_digest", fake_run_digest)
    assert (
        client.post(
            "/api/digests", json=_post_body(domain="Acme.Example.")
        ).status_code
        == 202
    )
    assert started.wait(5)
    assert seen == ["acme.example"]
    for bad in (
        "1.2.3.4",
        "::1",
        "http://acme.example/",
        "acme.example/path",
        "acme.example:8080",
        "not a domain",
        "-bad.example",
        "bad-.example",
        f"{'a' * 64}.example",
        "example.123",
        "12345",
        "",
    ):
        response = client.post(
            "/api/digests", json=_post_body(domain=bad)
        )
        assert response.status_code == 400, bad
    assert seen == ["acme.example"]


def test_post_rejects_unknown_upload(client):
    response = client.post(
        "/api/digests", json=_post_body(soc2_upload_id="0" * 64)
    )
    assert response.status_code == 400


def test_post_demo_inputs_resolve_fixtures(client, api_env, monkeypatch):
    assert api.DEMO_SOC2_PATH.exists()
    assert api.DEMO_INTERVIEW_PATH.exists()
    started = threading.Event()

    def fake_run_digest(**kwargs):
        run_dir = api_env / "runs" / kwargs["digest_id"]
        run_dir.mkdir(parents=True)
        (run_dir / "digest.json").write_text(
            json.dumps(
                {
                    "digest_id": kwargs["digest_id"],
                    "inputs": {
                        "documents": [
                            {"path": str(kwargs["soc2_path"])}
                        ],
                        "interviews": [
                            {
                                "path": str(kwargs["interview_path"]),
                                "speakers": kwargs["speaker_names"],
                                "targets": kwargs["target_speakers"],
                            }
                        ],
                    },
                }
            ),
            encoding="utf-8",
        )
        started.set()

    monkeypatch.setattr(api, "run_digest", fake_run_digest)
    response = client.post(
        "/api/digests",
        json=_post_body(
            demo=True,
            use_demo_inputs=True,
            speaker_names=["Diligence Lead", "Dana Reyes (CTO)"],
            target_speaker="Dana Reyes (CTO)",
        ),
    )
    assert response.status_code == 202
    assert started.wait(5)
    digest = json.loads(
        (
            api_env / "runs" / response.json()["digest_id"] / "digest.json"
        ).read_text(encoding="utf-8")
    )
    assert digest["inputs"]["documents"] == [
        {"path": str(api.DEMO_SOC2_PATH)}
    ]
    assert digest["inputs"]["interviews"][0]["path"] == str(
        api.DEMO_INTERVIEW_PATH
    )
    assert digest["inputs"]["interviews"][0]["speakers"] == [
        "Diligence Lead",
        "Dana Reyes (CTO)",
    ]
    assert digest["inputs"]["interviews"][0]["targets"] == [
        "Dana Reyes (CTO)"
    ]


def test_post_demo_inputs_requires_demo_flag(client):
    response = client.post(
        "/api/digests", json=_post_body(use_demo_inputs=True)
    )
    assert response.status_code == 422
    assert "demo flag" in response.json()["detail"]


def test_post_demo_inputs_rejects_upload_combo(client):
    upload = client.post(
        "/api/uploads", files={"file": ("soc2.md", b"# SOC 2")}
    )
    response = client.post(
        "/api/digests",
        json=_post_body(
            demo=True,
            use_demo_inputs=True,
            soc2_upload_id=upload.json()["upload_id"],
        ),
    )
    assert response.status_code == 422
    assert "not both" in response.json()["detail"]


def test_post_speakers_without_interview_is_422(client, monkeypatch):
    started = threading.Event()

    def fake_run_digest(**kwargs):
        started.set()

    monkeypatch.setattr(api, "run_digest", fake_run_digest)
    body = _post_body(
        speaker_names=["Diligence Lead", "Dana Reyes (CTO)"],
        target_speaker="Dana Reyes (CTO)",
    )
    response = client.post("/api/digests", json=body)
    assert response.status_code == 422
    assert "require an interview" in response.json()["detail"]
    assert not started.is_set()
    upload = client.post(
        "/api/uploads",
        files={"file": ("iv.wav", b"RIFF\x24\x00\x00\x00WAVEfmt ")},
    )
    body["interview_upload_id"] = upload.json()["upload_id"]
    assert client.post("/api/digests", json=body).status_code == 202
    assert started.wait(5)


def test_app_js_sends_demo_inputs_flag():
    web_app = (
        Path(api.__file__).resolve().parents[3] / "web" / "app.js"
    )
    source = web_app.read_text(encoding="utf-8")
    assert "demoAttachments" in source
    assert re.search(r"body\.use_demo_inputs = true", source)
    assert "renderDemoChips" in source


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


def test_dashboard_safety_and_provenance_strings():
    web_dir = Path(api.__file__).resolve().parents[3] / "web"
    html = (web_dir / "index.html").read_text(encoding="utf-8")
    assert 'id="live-note"' in html
    assert "passive collection will contact" in html
    assert "apex/www hosts" in html
    js = (web_dir / "app.js").read_text(encoding="utf-8")
    assert "updateLiveNote" in js
    assert "Built Oct 27 – Nov 4, 2026" in js
    assert "Meta Global AI Developer Hackathon" in js
    assert "https://github.com/wh1t3rbb1tz/pe-risk-key" in js


def _complete_digest(digest_id, generated_at, summary="Bottom line: fine."):
    functions = ["GV", "ID", "PR", "DE", "RS", "RC"]
    return {
        "schema_version": "1.0.0",
        "digest_id": digest_id,
        "generated_at": generated_at,
        "target": {
            "name": "Acme",
            "domain": "acme.example",
            "employee_band": "201-1000",
            "revenue_band": "50M-250M",
        },
        "mode": {
            "confidential": False,
            "providers": [
                {
                    "role": "orchestrator",
                    "provider": "meta_model_api",
                    "model": "muse-wonder-1.0",
                }
            ],
        },
        "inputs": {
            "domain_scan": True,
            "documents": [
                {
                    "doc_id": "doc_soc2x",
                    "type": "soc2_type2",
                    "filename": "soc2.md",
                    "sha256": "ab" * 32,
                }
            ],
            "interviews": [
                {
                    "interview_id": "int_iv01",
                    "filename": "iv.wav",
                    "sha256": "cd" * 32,
                    "duration_seconds": 60,
                }
            ],
        },
        "overall": {
            "score": 72.5,
            "rating": "C",
            "deal_signal": "proceed_with_conditions",
            "confidence": "medium",
            "rating_caps_applied": [],
        },
        "function_scores": [
            {
                "function": function,
                "score": 80.0,
                "finding_count": 0,
                "assessed": True,
            }
            for function in functions
        ],
        "findings": [],
        "contradictions": [],
        "remediation_plan": {
            "items": [],
            "total_cost_low_usd": 0,
            "total_cost_high_usd": 0,
        },
        "deal_recommendations": [],
        "narrative": {"executive_summary": summary},
        "limitations": ["Demo."],
    }


def _write_digest(api_env, digest_id, digest, narrative_valid=True):
    run_dir = api_env / "runs" / digest_id
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / "digest.json").write_text(
        json.dumps(digest), encoding="utf-8"
    )
    (run_dir / "trace.jsonl").write_text(
        json.dumps(
            {"seq": 1, "type": "narrative_complete", "valid": narrative_valid}
        )
        + "\n"
        + json.dumps({"seq": 2, "type": "run_end", "usage": {}})
        + "\n",
        encoding="utf-8",
    )


def test_list_sorts_newest_first(client, api_env, monkeypatch):
    _write_digest(
        api_env,
        "dg_000000000001",
        _complete_digest("dg_000000000001", "2026-01-01T00:00:00+00:00"),
    )
    _write_digest(
        api_env,
        "dg_000000000003",
        _complete_digest("dg_000000000003", "2026-03-01T00:00:00+00:00"),
    )
    _write_digest(
        api_env,
        "dg_000000000002",
        _complete_digest("dg_000000000002", "2026-02-01T00:00:00+00:00"),
    )
    monkeypatch.setitem(api.jobs, "dg_000000000004", {"status": "running"})
    ids = [
        entry["digest_id"]
        for entry in client.get("/api/digests").json()["digests"]
    ]
    assert ids == ["dg_000000000003", "dg_000000000002", "dg_000000000001", "dg_000000000004"]


def test_list_complete_and_schema_flags(client, api_env):
    _write_digest(
        api_env,
        "dg_000000000005",
        _complete_digest("dg_000000000005", "2026-03-01T00:00:00+00:00"),
    )
    _write_digest(
        api_env,
        "dg_000000000006",
        _complete_digest(
            "dg_000000000006", "2026-02-01T00:00:00+00:00",
            summary="Narrative pending.",
        ),
    )
    _write_digest(
        api_env,
        "dg_000000000007",
        {"digest_id": "dg_000000000007", "generated_at": "2026-01-01T00:00:00+00:00"},
    )
    _write_digest(
        api_env,
        "dg_000000000008",
        _complete_digest("dg_000000000008", "2026-04-01T00:00:00+00:00"),
        narrative_valid=False,
    )
    entries = {
        entry["digest_id"]: entry
        for entry in client.get("/api/digests").json()["digests"]
    }
    assert entries["dg_000000000005"]["complete"] is True
    assert entries["dg_000000000005"]["schema_valid"] is True
    assert entries["dg_000000000005"]["narrative_valid"] is True
    assert entries["dg_000000000005"]["has_soc2"] is True
    assert entries["dg_000000000005"]["has_interview"] is True
    assert entries["dg_000000000006"]["complete"] is False
    assert entries["dg_000000000006"]["schema_valid"] is True
    assert entries["dg_000000000007"]["complete"] is False
    assert entries["dg_000000000007"]["schema_valid"] is False
    assert entries["dg_000000000008"]["complete"] is True
    assert entries["dg_000000000008"]["narrative_valid"] is False


def _slim_digest(digest_id, generated_at):
    digest = _complete_digest(digest_id, generated_at)
    digest["inputs"] = {
        "domain_scan": True,
        "documents": [],
        "interviews": [],
    }
    return digest


def test_list_marks_authoritative_run(client, api_env):
    _write_digest(
        api_env,
        "dg_000000000001",
        _complete_digest("dg_000000000001", "2026-01-01T00:00:00+00:00"),
    )
    _write_digest(
        api_env,
        "dg_000000000002",
        _complete_digest("dg_000000000002", "2026-02-01T00:00:00+00:00"),
    )
    _write_digest(
        api_env,
        "dg_000000000003",
        _slim_digest("dg_000000000003", "2026-03-01T00:00:00+00:00"),
    )
    broken = _complete_digest(
        "dg_000000000009", "2026-04-01T00:00:00+00:00"
    )
    broken["findings"] = [{"finding_id": "F-1"}]
    _write_digest(api_env, "dg_000000000009", broken)
    entries = {
        entry["digest_id"]: entry
        for entry in client.get("/api/digests").json()["digests"]
    }
    assert entries["dg_000000000002"]["authoritative"] is True
    assert entries["dg_000000000002"]["superseded_by"] is None
    assert entries["dg_000000000001"]["authoritative"] is False
    assert (
        entries["dg_000000000001"]["superseded_by"] == "dg_000000000002"
    )
    assert entries["dg_000000000003"]["authoritative"] is False
    assert (
        entries["dg_000000000003"]["superseded_by"] == "dg_000000000002"
    )
    assert entries["dg_000000000009"]["complete"] is True
    assert entries["dg_000000000009"]["schema_valid"] is False
    assert entries["dg_000000000009"]["authoritative"] is False
    assert entries["dg_000000000009"]["superseded_by"] is None


def test_resolve_runs_dir_env_override(monkeypatch, tmp_path):
    from pe_risk_key.agent.orchestrator import (
        resolve_runs_dir as orch_resolve,
    )
    from pe_risk_key.api.app import resolve_runs_dir as api_resolve

    monkeypatch.setenv("PE_RISK_KEY_RUNS_DIR", str(tmp_path))
    assert api_resolve() == tmp_path
    assert orch_resolve() == tmp_path
    monkeypatch.delenv("PE_RISK_KEY_RUNS_DIR")
    assert (
        api_resolve()
        == Path(api.__file__).resolve().parents[3] / "eval" / "runs"
    )


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
