"""Tests for pe_risk_key.agent (mocked model + collectors). No network."""

import copy
import hashlib
import json
import re
import threading
import time
from datetime import date
from pathlib import Path
from types import SimpleNamespace

import dns.resolver
import pytest
import yaml

import pe_risk_key.agent.context as agent_context
import pe_risk_key.agent.orchestrator as orchestrator
import pe_risk_key.analyzers.interview as interview_module
import pe_risk_key.analyzers.soc2 as soc2_module
import pe_risk_key.engine.crosscheck as crosscheck_module
import pe_risk_key.engine.narrative as narrative_module
from pe_risk_key.agent import run_digest
from pe_risk_key.agent.prompts import system_prompt
from pe_risk_key.collectors import incidents, kev, net, web_posture
from pe_risk_key.validate import validate_digest

DOMAIN = "brightwaterfleet.example"
ROOT = Path(__file__).resolve().parents[1]
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


_CANNED_NARRATIVE = {
    "narrative": {
        "executive_summary": "Canned summary.",
        "key_questions_for_management": [
            f"Canned question {index}?" for index in range(5)
        ],
    },
    "deal_recommendations": [],
    "valid": True,
    "validation_errors": [],
    "regenerated": False,
    "first_attempt_errors": [],
    "usage": {"prompt_tokens": 10, "completion_tokens": 5, "cached_tokens": 0},
    "estimated_cost_usd": 0.00014,
}


@pytest.fixture
def agent_env(monkeypatch, tmp_path):
    _ScriptedAgentClient.turns = []
    _ScriptedAgentClient.chats = []
    monkeypatch.setattr(orchestrator, "ModelClient", _ScriptedAgentClient)
    monkeypatch.setattr(orchestrator, "RUNS_DIR", tmp_path / "runs")
    monkeypatch.setattr(
        orchestrator,
        "generate_narrative",
        lambda payload, mode="standard": copy.deepcopy(_CANNED_NARRATIVE),
    )
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


def _run_named_digest(agent_env, monkeypatch, domain, company):
    agent_env.turns = [
        {
            "content": "Plan: run every collector.",
            "tool_calls": [
                {"name": name, "arguments": {}}
                for name in [
                    "check_email_auth",
                    "check_dnssec",
                    "enumerate_ct_subdomains",
                    "check_web_posture",
                    "match_known_exploited",
                    "search_public_incidents",
                ]
            ],
        },
        {"content": "Submitting.", "tool_calls": [_submit()]},
    ]
    return run_digest(domain, company, "201-1000", "50M-250M")


def test_fixture_company_name_overrides_input(
    agent_env, monkeypatch, capsys
):
    result = _run_named_digest(
        agent_env, monkeypatch, DOMAIN, "Some Other Name"
    )
    assert (
        _read_digest(result)["target"]["name"]
        == "Brightwater Fleet Systems, Inc."
    )
    note = capsys.readouterr().out
    assert "Brightwater Fleet Systems, Inc." in note
    assert "Some Other Name" in note


def test_company_name_kept_without_fixture(agent_env, monkeypatch, capsys):
    result = _run_named_digest(
        agent_env, monkeypatch, "unfixtured.example", "Kept Name"
    )
    assert _read_digest(result)["target"]["name"] == "Kept Name"
    assert "fixture company name" not in capsys.readouterr().out


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


def test_concurrent_posture_and_kev_execute_posture_once(
    monkeypatch, tmp_path
):
    from concurrent.futures import ThreadPoolExecutor

    calls: list = []
    lock = threading.Lock()

    def fake_run(tool_name, domain, **kwargs):
        if tool_name == "check_web_posture":
            with lock:
                calls.append(tool_name)
            time.sleep(0.2)
            return {
                "status": "ok",
                "collection_method": "single_https_get",
                "hosts": [],
            }
        return {
            "status": "ok",
            "collection_method": "ct_log_query",
            "matches": [],
            "matches_count": 0,
        }

    monkeypatch.setattr(agent_context, "registry_run", fake_run)
    ctx = agent_context.RunContext(
        digest_id="dg_concurrent01",
        domain=DOMAIN,
        company_name="Acme",
        aliases=[],
        run_dir=tmp_path,
    )
    with ThreadPoolExecutor(max_workers=3) as pool:
        results = list(
            pool.map(
                lambda call: call(),
                [
                    lambda: ctx.run_tool("check_web_posture", {}, 1),
                    lambda: ctx.run_tool("check_web_posture", {}, 1),
                    lambda: ctx.run_tool("match_known_exploited", {}, 1),
                ],
            )
        )
    assert calls == ["check_web_posture"]
    assert all(result["status"] == "ok" for result in results)


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
        "catalog",
    }
    assert result["catalog"] is None


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
        "company_name": "Brightwater Fleet Systems, Inc.",
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
            "role": "narrative",
            "provider": "meta_model_api",
            "model": "muse-wonder-1.0",
        },
    ]
    assert digest["inputs"] == {
        "domain_scan": True,
        "documents": [],
        "interviews": [],
        "served_from_fixture": True,
    }
    assert [f["finding_id"] for f in digest["findings"]] == ["F-001", "F-002"]
    assert digest["contradictions"] == []
    assert digest["deal_recommendations"] == []
    assert digest["narrative"] == _CANNED_NARRATIVE["narrative"]
    assert digest["trace_ref"] == result["trace_path"]
    assert digest["overall"]["rating"] == "B"
    assert digest["overall"]["deal_signal"] == "proceed_with_conditions"
    assert digest["overall"]["rating_caps_applied"] == ["CAP-LOW-COVERAGE"]
    assert digest["overall"]["confidence"] == "low"
    by_function = {e["function"]: e for e in digest["function_scores"]}
    assert by_function["PR"]["score"] == 79.0
    assert by_function["PR"]["finding_count"] == 2
    assert [e["assessed"] for e in digest["function_scores"]] == [
        False,
        True,
        True,
        False,
        True,
        False,
    ]
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


# The nine expected outside-in findings: id, rule, severity, confidence,
# category, title.
_OUTSIDE_IN_FINDINGS = [
    ("F-001", "EMAIL-DMARC-NONE", "high", "high", "PR.DS", "DMARC none"),
    ("F-002", "EMAIL-SPF-SOFT", "medium", "high", "PR.DS", "SPF soft"),
    ("F-003", "DNS-NO-DNSSEC", "low", "high", "PR.PS", "No DNSSEC"),
    ("F-004", "SURFACE-RISKY-HOSTS", "medium", "medium", "ID.AM", "Risky hosts"),
    ("F-005", "SURFACE-SPRAWL", "low", "medium", "ID.AM", "Sprawl"),
    ("F-006", "WEB-LEGACY-TLS", "medium", "high", "PR.DS", "Legacy TLS"),
    ("F-007", "WEB-NO-HSTS", "low", "high", "PR.DS", "No HSTS"),
    ("F-008", "KEV-POTENTIAL", "critical", "medium", "ID.RA", "KEV hit"),
    ("F-009", "PUB-INCIDENT-RECENT", "high", "high", "RS.MA", "Incident"),
]


def _outside_in_finding(entry):
    finding_id, rule_id, severity, confidence, category, title = entry
    index = int(finding_id.split("-")[1])
    return {
        "finding_id": finding_id,
        "title": title,
        "severity": severity,
        "confidence": confidence,
        "csf_function": category.split(".")[0],
        "csf_category": category,
        "source": "outside_in",
        "evidence": [
            {
                "evidence_id": f"E-{index:03d}",
                "source_type": "outside_in",
                "collection_method": "dns_query",
                "locator": f"locator-{finding_id}",
                "excerpt": f"Evidence for {finding_id}.",
            }
        ],
        "deal_impact": f"Impact of {finding_id}.",
        "remediation": {
            "summary": f"Fix {finding_id}.",
            "cost_low_usd": 0,
            "cost_high_usd": 0,
            "effort_weeks": 0,
        },
        "rule_id": rule_id,
    }


def test_demo_run_matches_expected_outside_in_only(agent_env, monkeypatch):
    monkeypatch.setenv("DEMO_MODE", "1")
    expected = yaml.safe_load(
        (
            ROOT / "fixtures/expected/brightwaterfleet.example.yaml"
        ).read_text(encoding="utf-8")
    )
    block = expected["expected_outside_in_only"]
    findings = [_outside_in_finding(entry) for entry in _OUTSIDE_IN_FINDINGS]
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
        {"content": "Submitting.", "tool_calls": [_submit(*findings)]},
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
    assert digest["overall"]["rating_caps_applied"] == block["caps"]
    assert digest["overall"]["rating"] == block["rating"]
    assert digest["overall"]["confidence"] == block["confidence"]
    assert digest["overall"]["deal_signal"] == block["deal_signal"]
    unassessed = [
        entry["function"]
        for entry in digest["function_scores"]
        if not entry["assessed"]
    ]
    assert unassessed == block["unassessed"]


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


_SOC2_REPORT_TEXT = """Example Audit LLP examined Acme controls for the period.
Report period: January 1, 2026 to March 31, 2026.
Opinion: We found the controls suitably designed and operating effectively.
CC6.1-01 Logical access reviews. Result: 4 of 25 access reviews were late.
"""


class _ScriptedSoc2Client:
    extraction = {}
    calls: list = []

    def __init__(self, role, mode="standard", **kwargs):
        assert role == "document_analysis", role
        self.total_usage = {
            "prompt_tokens": 1000,
            "completion_tokens": 200,
            "cached_tokens": 0,
        }

    def chat_json(
        self, messages, *, schema, schema_name, reasoning_effort=None
    ):
        type(self).calls.append({"schema_name": schema_name})
        return copy.deepcopy(type(self).extraction)


def _soc2_extraction():
    return {
        "report_type": "type2",
        "period_start": "2026-01-01",
        "period_end": "2026-03-31",
        "auditor": "Example Audit LLP",
        "trust_services_categories": ["security"],
        "opinion": "unqualified",
        "opinion_quote": (
            "We found the controls suitably designed and "
            "operating effectively."
        ),
        "exceptions": [
            {
                "control_id": "CC6.1-01",
                "control_ref": "CC6.1-01",
                "description": "Quarterly access reviews were late.",
                "auditor_test": "Inspected access review records.",
                "deviations": 4,
                "sample_size": 25,
                "management_response": "Reviews are now automated.",
                "locator": "Section IV, CC6.1-01",
                "quote": "Result: 4 of 25 access reviews were late.",
                "deal_impact": "Access hygiene lagged during the period.",
            }
        ],
        "subservice_orgs": [],
        "cuecs": [],
        "notable_observations": [],
        "bridge_letter_provided": False,
    }


def _dmarc_finding():
    return _finding(
        rule_id="EMAIL-DMARC-NONE",
        finding_id="F-002",
        title="DMARC not enforced",
        severity="high",
        csf_category="PR.DS",
        csf_function="PR",
        evidence=[
            {
                "evidence_id": "E-002",
                "source_type": "outside_in",
                "collection_method": "dns_query",
                "locator": f"_dmarc.{DOMAIN} TXT",
                "excerpt": "No DMARC record published.",
            }
        ],
    )


def _run_soc2_digest(agent_env, monkeypatch, tmp_path, **kwargs):
    monkeypatch.setattr(
        agent_context,
        "registry_run",
        lambda *args, **kwargs: {
            "status": "ok",
            "collection_method": "dns_query",
        },
    )
    _ScriptedSoc2Client.extraction = _soc2_extraction()
    _ScriptedSoc2Client.calls = []
    monkeypatch.setattr(soc2_module, "ModelClient", _ScriptedSoc2Client)
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
            "tool_calls": [_submit(_finding(), _dmarc_finding())],
        },
    ]
    report = tmp_path / "acme_soc2.md"
    report.write_text(_SOC2_REPORT_TEXT, encoding="utf-8")
    params = {"soc2_path": report, "as_of": "2026-10-30"}
    params.update(kwargs)
    return run_digest(DOMAIN, "Acme", "201-1000", "50M-250M", **params)


def _read_digest(result):
    return json.loads(
        (Path(result["trace_path"]).parent / "digest.json").read_text(
            encoding="utf-8"
        )
    )


def test_soc2_findings_renumbered_without_collisions(
    agent_env, monkeypatch, tmp_path
):
    result = _run_soc2_digest(agent_env, monkeypatch, tmp_path)
    digest = _read_digest(result)
    findings = digest["findings"]
    assert [f["finding_id"] for f in findings] == [
        "F-001",
        "F-002",
        "F-003",
        "F-004",
    ]
    assert findings[2]["rule_id"] == "SOC2-EXCEPTION-ACCESS"
    assert findings[2]["title"].endswith("(CC6.1)")
    assert findings[3]["rule_id"] == "SOC2-BRIDGE-GAP"
    evidence_ids = [
        e["evidence_id"] for f in findings for e in f["evidence"]
    ]
    assert sorted(evidence_ids) == ["E-001", "E-002", "E-003", "E-004"]
    assert digest["soc2_analysis"]["exceptions"][0]["finding_id"] == "F-003"


def test_soc2_evidence_pool_merged(agent_env, monkeypatch, tmp_path):
    result = _run_soc2_digest(agent_env, monkeypatch, tmp_path)
    run_dir = Path(result["trace_path"]).parent
    pool = json.loads(
        (run_dir / "evidence_pool.json").read_text(encoding="utf-8")
    )
    by_id = {item["evidence_id"]: item for item in pool["evidence"]}
    assert sorted(by_id) == ["E-001", "E-002", "E-003", "E-004"]
    assert by_id["E-001"]["locator"] == f"{DOMAIN} DS"
    soc2_items = [
        item
        for item in pool["evidence"]
        if item.get("collector") == "soc2_analyzer"
    ]
    assert {item["evidence_id"] for item in soc2_items} == {"E-003", "E-004"}
    assert all(
        item["collection_method"] == "document_upload"
        for item in soc2_items
    )


def test_soc2_digest_validates_and_confidence_medium(
    agent_env, monkeypatch, tmp_path
):
    result = _run_soc2_digest(agent_env, monkeypatch, tmp_path)
    digest = _read_digest(result)
    assert validate_digest(digest) == []
    assert digest["soc2_analysis"]["opinion"] == "unqualified"
    assert digest["soc2_analysis"]["bridge_gap_days"] == 213
    assert digest["inputs"]["documents"] == [
        {
            "doc_id": "doc_" + result["digest_id"][3:],
            "type": "soc2_type2",
            "filename": "acme_soc2.md",
            "sha256": hashlib.sha256(
                _SOC2_REPORT_TEXT.encode("utf-8")
            ).hexdigest(),
        }
    ]
    roles = [p["role"] for p in digest["mode"]["providers"]]
    assert roles == [
        "orchestrator",
        "public_records",
        "document_analysis",
        "narrative",
    ]
    assert digest["overall"]["confidence"] == "medium"
    assert "No SOC 2 report provided" not in digest["limitations"]
    assert "No management interview provided" in digest["limitations"]


def test_soc2_trace_events(agent_env, monkeypatch, tmp_path):
    result = _run_soc2_digest(agent_env, monkeypatch, tmp_path)
    trace = _read_trace(result)
    starts = [e for e in trace if e["type"] == "document_analysis_start"]
    ends = [e for e in trace if e["type"] == "document_analysis_end"]
    assert len(starts) == 1
    assert len(ends) == 1
    assert trace.index(starts[0]) < trace.index(ends[0])
    end = ends[0]
    assert end["duration_ms"] >= 0
    assert end["tokens"] == {
        "prompt_tokens": 1000,
        "completion_tokens": 200,
        "cached_tokens": 0,
    }
    assert end["finding_count"] == 2


def test_soc2_as_of_defaults_to_today(agent_env, monkeypatch, tmp_path):
    result = _run_soc2_digest(
        agent_env, monkeypatch, tmp_path, as_of=None
    )
    digest = _read_digest(result)
    expected_gap = (date.today() - date(2026, 3, 31)).days
    assert digest["soc2_analysis"]["bridge_gap_days"] == expected_gap


def test_usage_breakdown_merges_orchestrator_and_soc2(
    agent_env, monkeypatch, tmp_path
):
    result = _run_soc2_digest(agent_env, monkeypatch, tmp_path)
    usage = result["usage"]
    assert set(usage["components"]) == {
        "orchestrator",
        "document_analysis",
        "narrative",
    }
    assert usage["prompt_tokens"] == 1210
    assert usage["completion_tokens"] == 245
    assert usage["cached_tokens"] == 0
    assert usage["estimated_cost_usd"] == pytest.approx(
        0.0016 + 0.008 + 0.00014
    )
    assert usage["components"]["orchestrator"][
        "estimated_cost_usd"
    ] == pytest.approx(0.0016)
    assert usage["components"]["document_analysis"][
        "estimated_cost_usd"
    ] == pytest.approx(0.008)
    run_end = _read_trace(result)[-1]
    assert run_end["type"] == "run_end"
    assert run_end["usage"] == usage


def test_usage_breakdown_orchestrator_only_without_soc2(
    agent_env, monkeypatch
):
    monkeypatch.setattr(
        agent_context,
        "registry_run",
        lambda *args, **kwargs: {
            "status": "ok",
            "collection_method": "dns_query",
        },
    )
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
        {"content": "Submitting.", "tool_calls": [_submit(_finding())]},
    ]
    result = run_digest(DOMAIN, "Acme", "201-1000", "50M-250M")
    assert set(result["usage"]["components"]) == {
        "orchestrator",
        "narrative",
    }
    assert result["usage"]["prompt_tokens"] == 210


def test_merge_usage_breakdown_with_transcription_entry():
    from pe_risk_key.agent.orchestrator import merge_usage_breakdown

    merged = merge_usage_breakdown(
        {
            "orchestrator": {
                "prompt_tokens": 100,
                "completion_tokens": 20,
                "cached_tokens": 0,
                "estimated_cost_usd": 0.0008,
            },
            "transcription": {
                "audio_hours": 0.0285,
                "estimated_cost_usd": 0.00513,
            },
        }
    )
    assert merged["prompt_tokens"] == 100
    assert merged["completion_tokens"] == 20
    assert merged["cached_tokens"] == 0
    assert merged["estimated_cost_usd"] == pytest.approx(0.00593)
    assert merged["components"]["transcription"]["audio_hours"] == 0.0285


CTO_NAME = "Dana Reyes (CTO)"

_INTERVIEW_TRANSCRIBE_RESPONSE = {
    "sessionId": "live",
    "transcript": "DMARC is enforced. We have immutable backups.",
    "audioDurationMs": 65000,
    "turns": [
        {
            "turnId": 1,
            "startMs": 0,
            "endMs": 65000,
            "transcript": "DMARC is enforced. We have immutable backups.",
            "speaker": "A",
        }
    ],
}


class _ScriptedInterviewClient:
    extraction = {}

    def __init__(self, role, mode="standard", **kwargs):
        assert role in ("transcription", "claim_extraction"), role
        self.total_usage = {
            "prompt_tokens": 500,
            "completion_tokens": 100,
            "cached_tokens": 0,
        }

    def transcribe(self, audio, **kwargs):
        return copy.deepcopy(_INTERVIEW_TRANSCRIBE_RESPONSE)

    def chat_json(
        self, messages, *, schema, schema_name, reasoning_effort=None
    ):
        return copy.deepcopy(type(self).extraction)


class _ScriptedCrosscheckClient:
    verdicts: list = []

    def __init__(self, role, mode="standard", **kwargs):
        assert role == "crosscheck", role
        self.total_usage = {
            "prompt_tokens": 50,
            "completion_tokens": 10,
            "cached_tokens": 0,
        }

    def chat_json(
        self, messages, *, schema, schema_name, reasoning_effort=None
    ):
        return {"verdicts": copy.deepcopy(type(self).verdicts)}


def _run_interview_digest(agent_env, monkeypatch, tmp_path):
    monkeypatch.setattr(
        agent_context,
        "registry_run",
        lambda *args, **kwargs: {
            "status": "ok",
            "collection_method": "dns_query",
        },
    )
    _ScriptedInterviewClient.extraction = {
        "claims": [
            {"text": "DMARC is enforced.", "claim_type": "control_exists"},
            {
                "text": "We have immutable backups.",
                "claim_type": "control_exists",
            },
        ]
    }
    monkeypatch.setattr(
        interview_module, "ModelClient", _ScriptedInterviewClient
    )
    monkeypatch.setattr(
        interview_module, "CACHE_DIR", tmp_path / "transcripts"
    )
    _ScriptedCrosscheckClient.verdicts = [
        {
            "claim_index": 0,
            "verdict": "contradicted",
            "evidence_refs": ["F-002"],
            "explanation": "DMARC finding contradicts the claim.",
        },
        {
            "claim_index": 1,
            "verdict": "supported",
            "evidence_refs": ["E-001"],
            "explanation": "Backup evidence corroborates the claim.",
        },
    ]
    monkeypatch.setattr(
        crosscheck_module, "ModelClient", _ScriptedCrosscheckClient
    )
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
            "tool_calls": [_submit(_finding(), _dmarc_finding())],
        },
    ]
    audio = tmp_path / "cto.wav"
    audio.write_bytes(b"RIFFfake-wav-bytes")
    return run_digest(
        DOMAIN,
        "Acme",
        "201-1000",
        "50M-250M",
        interview_path=audio,
        speaker_names=[CTO_NAME],
        target_speakers=[CTO_NAME],
    )


def _run_full_digest(agent_env, monkeypatch, tmp_path):
    monkeypatch.setattr(
        agent_context,
        "registry_run",
        lambda *args, **kwargs: {
            "status": "ok",
            "collection_method": "dns_query",
        },
    )
    _ScriptedSoc2Client.extraction = _soc2_extraction()
    _ScriptedSoc2Client.calls = []
    monkeypatch.setattr(soc2_module, "ModelClient", _ScriptedSoc2Client)
    _ScriptedInterviewClient.extraction = {
        "claims": [
            {"text": "DMARC is enforced.", "claim_type": "control_exists"},
            {
                "text": "We have immutable backups.",
                "claim_type": "control_exists",
            },
        ]
    }
    monkeypatch.setattr(
        interview_module, "ModelClient", _ScriptedInterviewClient
    )
    monkeypatch.setattr(
        interview_module, "CACHE_DIR", tmp_path / "transcripts"
    )
    _ScriptedCrosscheckClient.verdicts = [
        {
            "claim_index": 0,
            "verdict": "contradicted",
            "evidence_refs": ["F-002"],
            "explanation": "DMARC finding contradicts the claim.",
        },
        {
            "claim_index": 1,
            "verdict": "supported",
            "evidence_refs": ["E-001"],
            "explanation": "Backup evidence corroborates the claim.",
        },
    ]
    monkeypatch.setattr(
        crosscheck_module, "ModelClient", _ScriptedCrosscheckClient
    )
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
            "tool_calls": [_submit(_finding(), _dmarc_finding())],
        },
    ]
    report = tmp_path / "acme_soc2.md"
    report.write_text(_SOC2_REPORT_TEXT, encoding="utf-8")
    audio = tmp_path / "cto.wav"
    audio.write_bytes(b"RIFFfake-wav-bytes")
    return run_digest(
        DOMAIN,
        "Acme",
        "201-1000",
        "50M-250M",
        soc2_path=report,
        as_of="2026-10-30",
        interview_path=audio,
        speaker_names=[CTO_NAME],
        target_speakers=[CTO_NAME],
    )


def test_model_end_events_carry_cost_summing_to_run_end(
    agent_env, monkeypatch, tmp_path
):
    result = _run_full_digest(agent_env, monkeypatch, tmp_path)
    trace = _read_trace(result)
    costed = (
        "model_turn_end",
        "document_analysis_end",
        "transcription_end",
        "claims_extracted",
        "crosscheck_complete",
        "narrative_complete",
    )
    seen: dict[str, list[float]] = {type: [] for type in costed}
    for event in trace:
        if event["type"] in seen:
            assert isinstance(
                event["cost_usd"], (int, float)
            ), event["type"]
            seen[event["type"]].append(event["cost_usd"])
    for type, costs in seen.items():
        assert costs, f"no {type} in trace"
    total = next(
        event for event in trace if event["type"] == "run_end"
    )["usage"]["estimated_cost_usd"]
    assert sum(sum(costs) for costs in seen.values()) == pytest.approx(
        total
    )


def test_interview_digest_validates_with_contradictions(
    agent_env, monkeypatch, tmp_path
):
    result = _run_interview_digest(agent_env, monkeypatch, tmp_path)
    digest = _read_digest(result)
    assert validate_digest(digest) == []
    assert [c["contradiction_id"] for c in digest["contradictions"]] == [
        "C-001",
        "C-002",
    ]
    assert [c["verdict"] for c in digest["contradictions"]] == [
        "contradicted",
        "supported",
    ]
    assert [c["severity"] for c in digest["contradictions"]] == [
        "high",
        "info",
    ]
    assert digest["contradictions"][0]["evidence_refs"] == ["F-002"]
    assert digest["inputs"]["interviews"] == [
        {
            "interview_id": "int_" + result["digest_id"][3:],
            "filename": "cto.wav",
            "sha256": hashlib.sha256(b"RIFFfake-wav-bytes").hexdigest(),
            "duration_seconds": 65,
            "speakers": [CTO_NAME],
        }
    ]
    roles = [p["role"] for p in digest["mode"]["providers"]]
    assert roles == [
        "orchestrator",
        "public_records",
        "transcription",
        "claim_extraction",
        "crosscheck",
        "narrative",
    ]
    assert digest["overall"]["confidence"] == "medium"
    assert "No management interview provided" not in digest["limitations"]
    by_function = {e["function"]: e for e in digest["function_scores"]}
    assert by_function["GV"]["assessed"] is True
    claims_data = json.loads(
        (Path(result["trace_path"]).parent / "claims.json").read_text(
            encoding="utf-8"
        )
    )
    assert [c["text"] for c in claims_data["claims"]] == [
        "DMARC is enforced.",
        "We have immutable backups.",
    ]
    assert result["catalog"] == {
        "findings": 2,
        "outside_in_evidence": 2,
        "soc2_exceptions": 0,
        "soc2_no_exception": 0,
        "soc2_notables": 0,
    }


def test_interview_trace_events_per_claim(agent_env, monkeypatch, tmp_path):
    result = _run_interview_digest(agent_env, monkeypatch, tmp_path)
    trace = _read_trace(result)
    starts = [e for e in trace if e["type"] == "transcription_start"]
    ends = [e for e in trace if e["type"] == "transcription_end"]
    assert len(starts) == 1
    assert len(ends) == 1
    assert ends[0]["audio_seconds"] == 65.0
    assert ends[0]["cached"] is False
    extracted = [e for e in trace if e["type"] == "claims_extracted"]
    assert len(extracted) == 1
    assert extracted[0]["claim_count"] == 2
    merged_events = [e for e in trace if e["type"] == "claims_merged"]
    assert len(merged_events) == 1
    assert merged_events[0]["before"] == 2
    assert merged_events[0]["after"] == 2
    verdicts = [e for e in trace if e["type"] == "crosscheck_verdict"]
    assert [(v["claim_index"], v["verdict"]) for v in verdicts] == [
        (0, "contradicted"),
        (1, "supported"),
    ]
    assert verdicts[0]["text"] == "DMARC is enforced."
    assert verdicts[0]["refs"] == ["F-002"]
    assert verdicts[1]["contradiction_id"] == "C-002"


def test_interview_usage_components(agent_env, monkeypatch, tmp_path):
    result = _run_interview_digest(agent_env, monkeypatch, tmp_path)
    components = result["usage"]["components"]
    assert set(components) == {
        "orchestrator",
        "transcription",
        "claim_extraction",
        "crosscheck",
        "narrative",
    }
    assert components["transcription"]["audio_hours"] == round(
        65 / 3600, 6
    )
    assert components["claim_extraction"]["prompt_tokens"] == 500
    assert components["crosscheck"]["completion_tokens"] == 10


class _ScriptedNarrativeClient:
    outputs: list = []

    def __init__(self, role, mode="standard", **kwargs):
        assert role == "narrative", role
        self.total_usage = {
            "prompt_tokens": 200,
            "completion_tokens": 50,
            "cached_tokens": 0,
        }

    def chat_json(
        self, messages, *, schema, schema_name, reasoning_effort=None
    ):
        return copy.deepcopy(type(self).outputs.pop(0))


def _run_narrative_digest(agent_env, monkeypatch, outputs):
    monkeypatch.setattr(
        agent_context,
        "registry_run",
        lambda *args, **kwargs: {
            "status": "ok",
            "collection_method": "dns_query",
        },
    )
    monkeypatch.setattr(
        orchestrator, "generate_narrative", narrative_module.generate_narrative
    )
    _ScriptedNarrativeClient.outputs = outputs
    monkeypatch.setattr(
        narrative_module, "ModelClient", _ScriptedNarrativeClient
    )
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
        {"content": "Submitting.", "tool_calls": [_submit(_finding())]},
    ]
    return run_digest(DOMAIN, "Acme", "201-1000", "50M-250M")


def _narrative_output():
    return {
        "executive_summary": (
            "Bottom line: rating B with no material gap [F-001]. "
            "Key risks: one low finding. "
            "Management credibility: Not assessed: no management "
            "interview provided. "
            "Next steps: proceed; no SOC 2 report was provided."
        ),
        "key_questions_for_management": [
            f"Question {index} about controls [F-001]?"
            for index in range(4)
        ],
        "deal_recommendations": [
            {
                "type": "closing_condition",
                "text": "Require the fix in Days 31-60.",
                "basis_ids": ["F-001"],
            },
            {
                "type": "price_adjustment",
                "text": "No adjustment warranted.",
                "basis_ids": ["F-001"],
            },
        ],
    }


def test_narrative_fills_digest_and_memo(agent_env, monkeypatch):
    result = _run_narrative_digest(
        agent_env, monkeypatch, [_narrative_output()]
    )
    digest = _read_digest(result)
    assert validate_digest(digest) == []
    assert digest["narrative"]["executive_summary"].startswith("Bottom line:")
    assert len(digest["narrative"]["key_questions_for_management"]) == 4
    assert digest["deal_recommendations"][0]["type"] == "closing_condition"
    assert "narrative" in [p["role"] for p in digest["mode"]["providers"]]
    memo = (Path(result["trace_path"]).parent / "ic_memo.md").read_text(
        encoding="utf-8"
    )
    assert "# IC Memo: Brightwater Fleet Systems, Inc." in memo
    assert "(F-001," in memo
    assert "### Closing condition" in memo
    trace = _read_trace(result)
    complete = [e for e in trace if e["type"] == "narrative_complete"]
    assert len(complete) == 1
    assert complete[0]["valid"] is True
    assert not [e for e in trace if e["type"] == "narrative_validation_failed"]
    assert "narrative validation incomplete" not in digest["limitations"]
    assert result["usage"]["components"]["narrative"]["prompt_tokens"] == 200


def test_narrative_validation_failed_adds_limitation(agent_env, monkeypatch):
    bad = _narrative_output()
    bad["executive_summary"] = "There is a major exposure."
    bad["deal_recommendations"][0]["basis_ids"] = ["F-999"]
    result = _run_narrative_digest(agent_env, monkeypatch, [bad, bad])
    digest = _read_digest(result)
    assert validate_digest(digest) == []
    assert [r["type"] for r in digest["deal_recommendations"]] == [
        "price_adjustment"
    ]
    assert "narrative validation incomplete" in digest["limitations"]
    trace = _read_trace(result)
    complete = [e for e in trace if e["type"] == "narrative_complete"]
    assert complete[0]["valid"] is False
    failed = [e for e in trace if e["type"] == "narrative_validation_failed"]
    assert len(failed) == 1
    assert any("exposure" in e or "F-999" in e for e in failed[0]["errors"])


def test_preview_final_events_and_narrative_attempts(
    agent_env, monkeypatch
):
    result = _run_narrative_digest(
        agent_env, monkeypatch, [_narrative_output()]
    )
    trace = _read_trace(result)
    kinds = [event["type"] for event in trace]
    assert kinds.index("digest_preview") > kinds.index("scoring_complete")
    assert kinds.index("digest_final") > kinds.index("digest_validated")
    preview = next(
        event for event in trace if event["type"] == "digest_preview"
    )["digest"]
    assert preview["deal_recommendations"] == []
    assert "narrative" not in [
        provider["role"] for provider in preview["mode"]["providers"]
    ]
    final = next(
        event for event in trace if event["type"] == "digest_final"
    )["digest"]
    assert final == _read_digest(result)
    (complete,) = [
        event for event in trace if event["type"] == "narrative_complete"
    ]
    assert complete["attempts"] == 1
    assert complete["duration_ms"] >= 0
    assert "first_attempt_errors" not in complete


def test_narrative_repaired_traced_without_regeneration(
    agent_env, monkeypatch
):
    output = _narrative_output()
    output["deal_recommendations"][0]["text"] = (
        "Require the fix in Days 31-60 [F-001], consistent with Proceed "
        "with conditions."
    )
    result = _run_narrative_digest(agent_env, monkeypatch, [output])
    trace = _read_trace(result)
    (repaired,) = [
        event for event in trace if event["type"] == "narrative_repaired"
    ]
    assert any(
        "removed restated decision" in fix for fix in repaired["repairs"]
    )
    (complete,) = [
        event for event in trace if event["type"] == "narrative_complete"
    ]
    assert complete["attempts"] == 1
    assert complete["valid"] is True


def test_narrative_second_attempt_reports_first_errors(
    agent_env, monkeypatch
):
    bad = _narrative_output()
    bad["executive_summary"] = "There is a major exposure."
    result = _run_narrative_digest(
        agent_env, monkeypatch, [bad, _narrative_output()]
    )
    trace = _read_trace(result)
    (complete,) = [
        event for event in trace if event["type"] == "narrative_complete"
    ]
    assert complete["attempts"] == 2
    assert any(
        "exposure" in error
        for error in complete["first_attempt_errors"]
    )


def test_dedupe_evidence_pool_remaps_refs():
    from pe_risk_key.agent.orchestrator import dedupe_evidence_pool

    findings = [
        {
            "finding_id": "F-001",
            "evidence": [{"evidence_id": "E-001", "excerpt": "Same."}],
        },
        {
            "finding_id": "F-002",
            "evidence": [{"evidence_id": "E-002", "excerpt": "Same."}],
        },
    ]
    pool = [
        {"evidence_id": "E-001", "excerpt": "No DMARC record.", "locator": "L"},
        {
            "evidence_id": "E-002",
            "excerpt": "No  DMARC   record.",
            "locator": "L",
        },
        {"evidence_id": "E-003", "excerpt": "No DMARC record.", "locator": "N"},
    ]
    new_findings, new_pool = dedupe_evidence_pool(findings, pool)
    assert [item["evidence_id"] for item in new_pool] == ["E-001", "E-003"]
    assert new_findings[0]["evidence"][0]["evidence_id"] == "E-001"
    assert new_findings[1]["evidence"][0]["evidence_id"] == "E-001"
    assert pool[1]["evidence_id"] == "E-002"
    assert findings[1]["evidence"][0]["evidence_id"] == "E-002"


def test_cached_transcription_omits_provider(agent_env, monkeypatch, tmp_path):
    _run_interview_digest(agent_env, monkeypatch, tmp_path)
    result = _run_interview_digest(agent_env, monkeypatch, tmp_path)
    roles = [
        p["role"]
        for p in _read_digest(result)["mode"]["providers"]
    ]
    assert "transcription" not in roles
    assert "claim_extraction" in roles
    assert "crosscheck" in roles
    assert result["usage"]["components"]["transcription"]["cached"] is True
