"""Tests for pe_risk_key.agent (mocked model + collectors). No network."""

import json
import re
import threading
import time
from pathlib import Path
from types import SimpleNamespace

import dns.resolver
import pytest

import pe_risk_key.agent.context as agent_context
import pe_risk_key.agent.orchestrator as orchestrator
from pe_risk_key.agent import run_digest
from pe_risk_key.agent.prompts import system_prompt
from pe_risk_key.collectors import incidents, kev, net, web_posture
from pe_risk_key.validate import validate_digest

DOMAIN = "brightwaterfleet.example"
KEV_MINI = Path(__file__).resolve().parent / "data" / "kev_mini.json"


def _agent_message(turn):
    calls = []
    for index, call in enumerate(turn.get("tool_calls", [])):
        calls.append(
            SimpleNamespace(
                id=call.get("id", f"call_{index}"),
                function=SimpleNamespace(
                    name=call["name"],
                    arguments=json.dumps(call.get("arguments", {})),
                ),
            )
        )
    return SimpleNamespace(
        content=turn.get("content", ""), tool_calls=calls
    )


class _ScriptedAgentClient:
    """Fake ModelClient: scripted turns, recorded chats, bumped usage."""

    turns: list = []
    chats: list = []

    def __init__(self, role, mode="standard", **kwargs):
        assert role == "orchestrator", role
        assert mode == "standard", mode
        self.provider = "meta_model_api"
        self.model = "muse-wonder-1.0"
        self.total_usage = {
            "prompt_tokens": 0,
            "completion_tokens": 0,
            "cached_tokens": 0,
        }

    def chat(self, messages, *, reasoning_effort=None, tools=None, **kwargs):
        type(self).chats.append(
            {
                "messages": messages,
                "reasoning_effort": reasoning_effort,
                "tools": tools,
            }
        )
        self.total_usage["prompt_tokens"] += 100
        self.total_usage["completion_tokens"] += 20
        turn = type(self).turns.pop(0)
        return SimpleNamespace(
            choices=[SimpleNamespace(message=_agent_message(turn))],
            usage=SimpleNamespace(prompt_tokens=100, completion_tokens=20),
        )


class _FailingSearchClient:
    """incidents.ModelClient stand-in: never touches the network."""

    def __init__(self, *args, **kwargs):
        raise RuntimeError("no live model calls in agent tests")


@pytest.fixture
def agent_env(monkeypatch, tmp_path):
    _ScriptedAgentClient.turns = []
    _ScriptedAgentClient.chats = []
    monkeypatch.setattr(orchestrator, "ModelClient", _ScriptedAgentClient)
    monkeypatch.setattr(orchestrator, "RUNS_DIR", tmp_path / "runs")
    monkeypatch.setattr(incidents, "CACHE_DIR", tmp_path / "icache")
    monkeypatch.setattr(incidents, "ModelClient", _FailingSearchClient)
    monkeypatch.delenv("DEMO_MODE", raising=False)
    return _ScriptedAgentClient


def _finding(rule_id="DNS-NO-DNSSEC", finding_id="F-001", **overrides):
    finding = {
        "finding_id": finding_id,
        "title": "DNSSEC not enabled",
        "severity": "low",
        "confidence": "high",
        "csf_function": "PR",
        "csf_category": "PR.PS",
        "source": "outside_in",
        "evidence": [
            {
                "evidence_id": "E-001",
                "source_type": "outside_in",
                "collection_method": "dns_query",
                "locator": f"{DOMAIN} DS",
                "excerpt": "No DS record published.",
            }
        ],
        "deal_impact": "Spoofing risk.",
        "remediation": {
            "summary": "Enable DNSSEC.",
            "cost_low_usd": 0,
            "cost_high_usd": 0,
            "effort_weeks": 0,
        },
        "rule_id": rule_id,
    }
    finding.update(overrides)
    return finding


def _submit(*findings):
    return {"name": "submit_findings", "arguments": {"findings": findings}}


def _read_trace(result):
    return [
        json.loads(line)
        for line in Path(result["trace_path"]).read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def test_system_prompt_has_loop_rules():
    text = system_prompt()
    for phrase in (
        "Map collector signals",
        "one-paragraph plan",
        "same turn",
        "match_known_exploited",
        "submit_findings exactly once",
    ):
        assert phrase in text


def test_tool_calls_in_one_turn_run_concurrently(agent_env, monkeypatch):
    state = {"active": 0, "max": 0}
    lock = threading.Lock()

    def fake_run(tool_name, domain, **kwargs):
        with lock:
            state["active"] += 1
            state["max"] = max(state["max"], state["active"])
        time.sleep(0.1)
        with lock:
            state["active"] -= 1
        return {"status": "ok", "collection_method": "dns_query"}

    monkeypatch.setattr(agent_context, "registry_run", fake_run)
    agent_env.turns = [
        {
            "content": "Plan: gather DNS and CT signals.",
            "tool_calls": [
                {"name": "check_dnssec", "arguments": {"domain": DOMAIN}},
                {"name": "check_email_auth", "arguments": {"domain": DOMAIN}},
                {
                    "name": "enumerate_ct_subdomains",
                    "arguments": {"domain": DOMAIN},
                },
            ],
        },
        {"content": "Done.", "tool_calls": [_submit()]},
        {"content": "Resubmitted.", "tool_calls": [_submit()]},
    ]
    result = run_digest(DOMAIN, "Acme", "201-1000", "50M-250M")
    assert state["max"] == 3
    assert result["findings"] == []


class _Rdata(str):
    def to_text(self):
        return f'"{self}"'


def test_kev_uses_cached_web_posture(agent_env, monkeypatch):
    gets: list = []
    html = (
        '<html><head><meta name="generator" content="WordPress 6.2">'
        '</head><body><a href="/examplegate/login">VPN</a></body></html>'
    )
    crt = [
        {
            "name_value": DOMAIN,
            "not_before": "2026-01-01T00:00:00",
            "not_after": "2026-12-31T00:00:00",
        }
    ]

    class FakeHttp:
        def get(self, url, timeout=None, **kwargs):
            gets.append(url)
            if "crt.sh" in url:
                return SimpleNamespace(
                    status_code=200,
                    headers={},
                    text="[]",
                    json=lambda: crt,
                    raise_for_status=lambda: None,
                )
            return SimpleNamespace(
                status_code=200, headers={}, text=html
            )

    def fake_resolve(name, rdtype):
        name = str(name)
        if (name, rdtype) == (DOMAIN, "TXT"):
            return [_Rdata("v=spf1 -all")]
        if (name, rdtype) == (f"_dmarc.{DOMAIN}", "TXT"):
            return [_Rdata("v=DMARC1; p=reject")]
        raise dns.resolver.NoAnswer()

    monkeypatch.setattr(net, "httpx", FakeHttp())
    monkeypatch.setattr(
        web_posture,
        "tls_info",
        lambda host: {
            "version": "TLSv1.3",
            "issuer": "Example Public CA",
            "not_after": "2031-01-02T00:00:00+00:00",
            "days_remaining": 800,
        },
    )
    monkeypatch.setattr(
        web_posture, "tls_accepts", lambda host, version: False
    )
    monkeypatch.setattr(kev, "KEV_SNAPSHOT_PATH", KEV_MINI)
    monkeypatch.setattr("dns.resolver.resolve", fake_resolve)
    agent_env.turns = [
        {
            "content": "Plan: posture first.",
            "tool_calls": [
                {"name": "check_web_posture", "arguments": {"domain": DOMAIN}}
            ],
        },
        {
            "content": "Now KEV.",
            "tool_calls": [
                {
                    "name": "match_known_exploited",
                    "arguments": {"domain": DOMAIN},
                }
            ],
        },
        {"content": "Submitting.", "tool_calls": [_submit(_finding())]},
        {"content": "Resub.", "tool_calls": [_submit(_finding())]},
    ]
    result = run_digest(DOMAIN, "Acme", "201-1000", "50M-250M")
    apex_gets = [u for u in gets if u == f"https://{DOMAIN}/"]
    www_gets = [u for u in gets if u == f"https://www.{DOMAIN}/"]
    assert len(apex_gets) == 1
    assert len(www_gets) == 1
    kev_out = result["collector_outputs"]["match_known_exploited"]
    assert kev_out["status"] == "ok"
    assert kev_out["matches_count"] >= 1
    assert any(
        match["match_tier"] == "appliance_exposed"
        for match in kev_out["matches"]
    )


def test_coverage_gap_triggers_missing_collectors_and_resubmission(
    agent_env, monkeypatch
):
    seen: list = []

    def fake_run(tool_name, domain, **kwargs):
        seen.append(tool_name)
        return {"status": "ok", "collection_method": "dns_query"}

    monkeypatch.setattr(agent_context, "registry_run", fake_run)
    agent_env.turns = [
        {
            "content": "Plan: quick check.",
            "tool_calls": [{"name": "check_dnssec", "arguments": {}}],
        },
        {"content": "Submitting.", "tool_calls": [_submit(_finding())]},
        {
            "content": "Resubmitting.",
            "tool_calls": [_submit(_finding(title="Updated title"))],
        },
    ]
    result = run_digest(DOMAIN, "Acme", "201-1000", "50M-250M")
    assert set(seen) == {
        "check_email_auth",
        "check_dnssec",
        "enumerate_ct_subdomains",
        "check_web_posture",
        "match_known_exploited",
        "search_public_incidents",
    }
    trace = _read_trace(result)
    gaps = [e for e in trace if e["type"] == "coverage_gap"]
    assert len(gaps) == 1
    assert set(gaps[0]["missing"]) == set(seen) - {"check_dnssec"}
    submits = [e for e in trace if e["type"] == "submit_findings"]
    assert len(submits) == 2
    assert result["findings"][0]["title"] == "Updated title"


def test_max_turns_limit_enforced(agent_env):
    agent_env.turns = [{"content": f"Still thinking {i}."} for i in range(8)]
    result = run_digest(DOMAIN, "Acme", "201-1000", "50M-250M")
    assert len(agent_env.chats) == 6
    assert result["findings"] == []
    assert result["adjustments"] == []
    assert re.fullmatch(r"dg_[a-z0-9]{12}", result["digest_id"])
    first = agent_env.chats[0]
    assert first["reasoning_effort"] == "medium"
    names = [t["function"]["name"] for t in first["tools"]]
    assert "submit_findings" in names
    assert "check_dnssec" in names
    assert set(result) == {
        "digest_id",
        "findings",
        "collector_outputs",
        "adjustments",
        "trace_path",
        "usage",
    }


def test_invalid_finding_dropped_and_traced(agent_env, monkeypatch):
    monkeypatch.setattr(
        agent_context,
        "registry_run",
        lambda *args, **kwargs: {"status": "ok"},
    )
    bad = {"finding_id": "F-002", "title": "Broken"}
    agent_env.turns = [
        {"content": "Plan.", "tool_calls": [_submit(_finding(), bad)]},
        {"content": "Again.", "tool_calls": [_submit(_finding(), bad)]},
    ]
    result = run_digest(DOMAIN, "Acme", "201-1000", "50M-250M")
    assert [f["finding_id"] for f in result["findings"]] == ["F-001"]
    trace = _read_trace(result)
    errors = [e for e in trace if e["type"] == "validation_error"]
    assert len(errors) == 1
    assert errors[0]["finding_id"] == "F-002"
    assert errors[0]["errors"]
    findings_file = json.loads(
        (
            Path(result["trace_path"]).parent / "findings.json"
        ).read_text(encoding="utf-8")
    )
    assert [f["finding_id"] for f in findings_file["findings"]] == ["F-001"]


def test_incidents_receives_forced_company_and_aliases(
    agent_env, monkeypatch
):
    captured: dict = {}

    def fake_run(tool_name, domain, **kwargs):
        captured[tool_name] = {"domain": domain, **kwargs}
        return {"status": "ok"}

    monkeypatch.setattr(agent_context, "registry_run", fake_run)
    agent_env.turns = [
        {
            "content": "Plan.",
            "tool_calls": [
                {
                    "name": "search_public_incidents",
                    "arguments": {
                        "domain": "evil.example",
                        "company_name": "Evil Corp",
                        "aliases": ["Wrong"],
                    },
                }
            ],
        },
        {"content": "Submitting.", "tool_calls": [_submit()]},
        {"content": "Resub.", "tool_calls": [_submit()]},
    ]
    run_digest(
        DOMAIN, "Acme", "201-1000", "50M-250M", aliases=["Acme Corp"]
    )
    assert captured["search_public_incidents"] == {
        "domain": DOMAIN,
        "company_name": "Acme",
        "aliases": ["Acme Corp"],
    }


def test_assembled_brightwater_digest_validates(agent_env, monkeypatch):
    monkeypatch.setenv("DEMO_MODE", "1")
    agent_env.turns = [
        {
            "content": "Plan: run every collector.",
            "tool_calls": [
                {"name": "check_email_auth", "arguments": {}},
                {"name": "check_dnssec", "arguments": {}},
                {"name": "enumerate_ct_subdomains", "arguments": {}},
                {"name": "check_web_posture", "arguments": {}},
                {"name": "match_known_exploited", "arguments": {}},
                {"name": "search_public_incidents", "arguments": {}},
            ],
        },
        {
            "content": "Submitting.",
            "tool_calls": [
                _submit(
                    _finding(),
                    _finding(
                        rule_id="EMAIL-DMARC-NONE",
                        finding_id="F-002",
                        title="DMARC not enforced",
                        severity="high",
                        csf_category="PR.DS",
                        csf_function="PR",
                    ),
                )
            ],
        },
    ]
    result = run_digest(
        DOMAIN, "Brightwater Fleet Systems, Inc.", "201-1000", "50M-250M"
    )
    digest = json.loads(
        (Path(result["trace_path"]).parent / "digest.json").read_text(
            encoding="utf-8"
        )
    )
    assert validate_digest(digest) == []
    assert digest["schema_version"] == "1.0.0"
    assert digest["digest_id"] == result["digest_id"]
    assert digest["target"]["name"] == "Brightwater Fleet Systems, Inc."
    assert digest["target"]["domain"] == DOMAIN
    assert digest["mode"]["confidential"] is False
    assert digest["mode"]["demo"] is True
    assert digest["mode"]["providers"] == [
        {
            "role": "orchestrator",
            "provider": "meta_model_api",
            "model": "muse-wonder-1.0",
        },
        {
            "role": "public_records",
            "provider": "meta_model_api",
            "model": "muse-spark-1.3",
        },
    ]
    assert digest["inputs"] == {
        "domain_scan": True,
        "documents": [],
        "interviews": [],
    }
    assert [f["finding_id"] for f in digest["findings"]] == ["F-001", "F-002"]
    assert digest["contradictions"] == []
    assert digest["deal_recommendations"] == []
    assert digest["narrative"] == {"executive_summary": "Narrative pending."}
    assert digest["trace_ref"] == result["trace_path"]
    assert digest["overall"]["rating"] == "A"
    assert digest["overall"]["deal_signal"] == "proceed_with_conditions"
    assert digest["overall"]["rating_caps_applied"] == []
    assert digest["overall"]["confidence"] == "low"
    by_function = {e["function"]: e for e in digest["function_scores"]}
    assert by_function["PR"]["score"] == 79.0
    assert by_function["PR"]["finding_count"] == 2
    plan = digest["remediation_plan"]
    assert plan["total_cost_low_usd"] == 10000
    assert plan["total_cost_high_usd"] == 40000
    assert "Demo mode: signals from fixtures" in digest["limitations"]
    assert "No SOC 2 report provided" in digest["limitations"]
    trace = _read_trace(result)
    assert any(e["type"] == "scoring_complete" for e in trace)
    validated = [e for e in trace if e["type"] == "digest_validated"]
    assert len(validated) == 1
    assert validated[0]["valid"] is True


def test_trace_file_complete_and_ordered(agent_env, monkeypatch):
    monkeypatch.setattr(
        agent_context,
        "registry_run",
        lambda *args, **kwargs: {
            "status": "ok",
            "collection_method": "dns_query",
        },
    )
    submitted = _finding(rule_id="NOPE-1", finding_id="F-009")
    agent_env.turns = [
        {
            "content": "Plan: dns then submit.",
            "tool_calls": [{"name": "check_dnssec", "arguments": {}}],
        },
        {"content": "Submitting.", "tool_calls": [_submit(submitted)]},
        {"content": "Final.", "tool_calls": [_submit(submitted)]},
    ]
    result = run_digest(
        DOMAIN, "Acme", "201-1000", "50M-250M", aliases=["Acme Corp"]
    )
    trace = _read_trace(result)
    assert [e["seq"] for e in trace] == list(range(1, len(trace) + 1))
    assert all(e["ts"] and e["type"] for e in trace)
    types = [e["type"] for e in trace]
    assert types[0] == "run_start"
    assert types[-1] == "run_end"
    assert types.index("plan") < types.index("submit_findings")
    assert types.index("submit_findings") < types.index("coverage_gap")
    assert types.index("coverage_gap") < types.index("engine_adjustment")
    assert types.index("engine_adjustment") < types.index("run_end")
    assert types.count("submit_findings") == 2
    assert types.count("model_turn_start") == 3
    assert types.count("model_turn_end") == 3
    starts = sorted(
        (e["tool"], e["parallel_group"])
        for e in trace
        if e["type"] == "tool_call_start"
    )
    ends = sorted(
        (e["tool"], e["parallel_group"])
        for e in trace
        if e["type"] == "tool_call_end"
    )
    assert starts == ends
    assert len(starts) == 7  # dns + 5 coverage + chained posture
    plans = [e for e in trace if e["type"] == "plan"]
    assert [p["text"] for p in plans] == ["Plan: dns then submit."]
    run_start = trace[0]
    assert run_start["domain"] == DOMAIN
    assert run_start["aliases"] == ["Acme Corp"]
    run_end = trace[-1]
    assert run_end["usage"]["estimated_cost_usd"] > 0
    turn_end = next(e for e in trace if e["type"] == "model_turn_end")
    assert turn_end["tokens"] == {
        "prompt_tokens": 100,
        "completion_tokens": 20,
        "cached_tokens": 0,
    }
    run_dir = Path(result["trace_path"]).parent
    outputs = json.loads(
        (run_dir / "collector_outputs.json").read_text(encoding="utf-8")
    )
    assert set(outputs) == {
        "check_email_auth",
        "check_dnssec",
        "enumerate_ct_subdomains",
        "check_web_posture",
        "match_known_exploited",
        "search_public_incidents",
    }
    assert [f["finding_id"] for f in result["findings"]] == ["F-009"]
    adjustments = [
        e for e in trace if e["type"] == "engine_adjustment"
    ]
    assert len(adjustments) == 1
    assert adjustments[0]["reason"] == "unknown_rule"
