"""Tests for pe_risk_key.collectors (SPEC §2, §4.1). No network access."""

import ast
import json
from pathlib import Path
from types import SimpleNamespace

import dns.resolver
import pe_risk_key.collectors
import pytest

from pe_risk_key.collectors import (
    ALLOWED_METHODS,
    SafetyBoundaryError,
    run,
    tool_definitions,
)
from pe_risk_key.collectors import ct, dnssec, email_auth, net
from pe_risk_key.collectors.registry import register

FIXTURES_DIR = Path(__file__).resolve().parents[1] / "fixtures" / "outside_in"
DOMAIN = "brightwaterfleet.example"

SPF_RECORD = "v=spf1 include:_spf.mailhost.example include:sendgrid.example ~all"
DMARC_RECORD = "v=DMARC1; p=none; rua=mailto:dmarc@brightwaterfleet.example"
DKIM_FOUND = {"selector1": "v=DKIM1; k=rsa; p=AAAAB3NzaC1"}


def _brightwater_fixture() -> dict:
    return json.loads((FIXTURES_DIR / f"{DOMAIN}.json").read_text(encoding="utf-8"))


class _Rdata(str):
    def to_text(self):  # dnspython renders TXT rdatas double-quoted
        return f'"{self}"'


def _fake_resolve_factory(calls: list):
    def _fake_resolve(name, rdtype):
        name = str(name)
        calls.append((name, rdtype))
        if (name, rdtype) == (DOMAIN, "TXT"):
            return [_Rdata(SPF_RECORD), _Rdata("unrelated-txt")]
        if (name, rdtype) == (f"_dmarc.{DOMAIN}", "TXT"):
            return [_Rdata(DMARC_RECORD)]
        if rdtype == "TXT" and name.endswith(f"._domainkey.{DOMAIN}"):
            selector = name.split(".")[0]
            if selector in DKIM_FOUND:
                return [_Rdata(DKIM_FOUND[selector])]
            raise dns.resolver.NoAnswer()
        if (name, rdtype) == (DOMAIN, "DS"):
            raise dns.resolver.NoAnswer()
        raise AssertionError(f"unexpected query {(name, rdtype)}")

    return _fake_resolve


class _FakeHttp:
    def __init__(self, payload):
        self.calls: list = []
        self.payload = payload

    def get(self, url, timeout=None):
        self.calls.append({"url": url, "timeout": timeout})
        return SimpleNamespace(
            json=lambda: self.payload, raise_for_status=lambda: None
        )


CRT_JSON = [
    {
        "name_value": "brightwaterfleet.example",
        "not_before": "2026-01-01T00:00:00",
        "not_after": "2026-12-31T00:00:00",
    },
    {
        "name_value": "vpn.brightwaterfleet.example",
        "not_before": "2023-02-11T00:00:00",
        "not_after": "2026-09-30T00:00:00",
    },
    {
        "name_value": "vpn.brightwaterfleet.example",
        "not_before": "2022-01-01T00:00:00",
        "not_after": "2023-01-01T00:00:00",
    },
    {
        "name_value": "*.staging-api.brightwaterfleet.example\nstaging-api.brightwaterfleet.example",
        "not_before": "2024-01-20T00:00:00",
        "not_after": "2026-10-01T00:00:00",
    },
    {
        "name_value": "jenkins-old.brightwaterfleet.example",
        "not_before": "2021-06-03T00:00:00",
        "not_after": "2026-08-14T00:00:00",
    },
    {
        "name_value": "mail.unrelated.example",
        "not_before": "2025-01-01T00:00:00",
        "not_after": "2026-01-01T00:00:00",
    },
]


def test_email_auth_matches_fixture_section(monkeypatch):
    calls: list = []
    monkeypatch.setattr("dns.resolver.resolve", _fake_resolve_factory(calls))
    out = email_auth.collect(DOMAIN)
    assert out == _brightwater_fixture()["check_email_auth"]
    assert out["spf"]["queried_name"] == DOMAIN
    assert out["spf"]["record_type"] == "TXT"
    assert out["spf"]["lookup_count"] == 2
    assert out["dmarc"]["queried_name"] == f"_dmarc.{DOMAIN}"
    # Only the six common DKIM selectors are ever queried.
    dkim_names = {n for n, t in calls if t == "TXT" and "._domainkey." in n}
    assert dkim_names == {
        f"{s}._domainkey.{DOMAIN}"
        for s in ["default", "selector1", "selector2", "google", "k1", "s1"]
    }


def test_email_auth_missing_records_yield_nones(monkeypatch):
    def _empty(name, rdtype):
        raise dns.resolver.NoAnswer()

    monkeypatch.setattr("dns.resolver.resolve", _empty)
    out = email_auth.collect(DOMAIN)
    assert out["spf"]["record"] is None
    assert out["spf"]["lookup_count"] == 0
    assert out["dmarc"]["policy"] is None
    assert out["dmarc"]["rua"] is False
    assert out["dkim"]["selectors_found"] == []


def test_dnssec_matches_fixture_section(monkeypatch):
    calls: list = []
    monkeypatch.setattr("dns.resolver.resolve", _fake_resolve_factory(calls))
    out = dnssec.collect(DOMAIN)
    assert out == _brightwater_fixture()["check_dnssec"]
    assert out["enabled"] is False
    assert (DOMAIN, "DS") in calls


def test_dnssec_enabled_when_ds_exists(monkeypatch):
    monkeypatch.setattr(
        "dns.resolver.resolve", lambda n, t: [_Rdata("12345 8 2 ABCDEF")]
    )
    out = dnssec.collect(DOMAIN)
    assert out["enabled"] is True


def test_ct_subdomains_dedupe_and_flag_risky(monkeypatch):
    fake = _FakeHttp(CRT_JSON)
    monkeypatch.setattr(net, "httpx", fake)
    net.begin_run(DOMAIN)
    out = ct.collect(DOMAIN)
    assert out["collection_method"] == "ct_log_query"
    assert out["query_url"] == f"https://crt.sh/?q=%25.{DOMAIN}&output=json"
    assert set(out) == set(_brightwater_fixture()["enumerate_ct_subdomains"])
    assert out["unique_hostnames"] == 4
    assert out["risky_hostnames_count"] == 3
    by_host = {r["hostname"]: r for r in out["risky_hostnames"]}
    assert by_host["vpn.brightwaterfleet.example"]["pattern"] == "vpn"
    assert by_host["vpn.brightwaterfleet.example"]["first_seen"] == "2022-01-01"
    assert by_host["vpn.brightwaterfleet.example"]["last_seen"] == "2026-09-30"
    assert by_host["staging-api.brightwaterfleet.example"]["pattern"] == "staging"
    assert by_host["jenkins-old.brightwaterfleet.example"]["pattern"] == "jenkins|old"
    assert not any(h.startswith("*.") for h in by_host)
    assert "mail.unrelated.example" not in by_host
    assert fake.calls[0]["url"] == out["query_url"]


def test_demo_mode_returns_fixture_sections(monkeypatch):
    monkeypatch.setenv("DEMO_MODE", "1")
    fixture = _brightwater_fixture()
    assert run("check_email_auth", DOMAIN) == fixture["check_email_auth"]
    assert run("check_dnssec", DOMAIN) == fixture["check_dnssec"]
    assert run("enumerate_ct_subdomains", DOMAIN) == fixture["enumerate_ct_subdomains"]
    copper = json.loads(
        (FIXTURES_DIR / "copperline.example.json").read_text(encoding="utf-8")
    )
    assert run("check_dnssec", "copperline.example") == copper["check_dnssec"]


def test_run_dispatches_live(monkeypatch):
    monkeypatch.delenv("DEMO_MODE", raising=False)
    calls: list = []
    monkeypatch.setattr("dns.resolver.resolve", _fake_resolve_factory(calls))
    out = run("check_email_auth", DOMAIN)
    assert out["spf"]["qualifier"] == "~all"
    assert out["dkim"]["selectors_found"] == ["selector1"]


def test_run_unknown_tool():
    with pytest.raises(KeyError, match="nope"):
        run("nope", DOMAIN)


def test_tool_definitions_shape():
    defs = tool_definitions()
    assert {d["function"]["name"] for d in defs} == {
        "check_email_auth",
        "check_dnssec",
        "enumerate_ct_subdomains",
    }
    for definition in defs:
        assert definition["type"] == "function"
        params = definition["function"]["parameters"]
        assert params["required"] == ["domain"]
        assert set(params["properties"]) == {"domain"}


def test_allowed_methods_match_schema():
    assert ALLOWED_METHODS == frozenset(
        {
            "dns_query",
            "ct_log_query",
            "single_https_get",
            "offline_lookup",
            "search_grounding",
            "document_upload",
            "interview_upload",
        }
    )


def test_registration_rejects_bad_method():
    with pytest.raises(ValueError, match="collection_method"):
        register(
            tool_name="x", description="x", collection_method="port_scan"
        )


def test_registration_rejects_duplicate():
    with pytest.raises(ValueError, match="uplicate"):
        register(
            tool_name="check_dnssec",
            description="x",
            collection_method="dns_query",
        )(lambda domain: {})


def test_safe_get_rejects_post():
    net.begin_run(DOMAIN)
    with pytest.raises(SafetyBoundaryError, match="GET"):
        net.safe_get("https://crt.sh/?q=x", method="POST")


def test_safe_get_rejects_disallowed_host():
    net.begin_run(DOMAIN)
    with pytest.raises(SafetyBoundaryError, match="outside the boundary"):
        net.safe_get("https://evil.example/")


def test_safe_get_rejects_plain_http():
    net.begin_run(DOMAIN)
    with pytest.raises(SafetyBoundaryError, match="HTTPS"):
        net.safe_get(f"http://{DOMAIN}/")


def test_safe_get_requires_run_context(monkeypatch):
    monkeypatch.setattr(net, "_run_domain", None)
    with pytest.raises(SafetyBoundaryError, match="run context"):
        net.safe_get("https://crt.sh/")


def test_safe_get_rejects_second_request_to_host(monkeypatch):
    fake = _FakeHttp([])
    monkeypatch.setattr(net, "httpx", fake)
    net.begin_run(DOMAIN)
    net.safe_get("https://crt.sh/?q=a")
    with pytest.raises(SafetyBoundaryError, match="Second request"):
        net.safe_get("https://crt.sh/?q=b")


def test_safe_get_allows_boundary_hosts(monkeypatch):
    fake = _FakeHttp([])
    monkeypatch.setattr(net, "httpx", fake)
    net.begin_run(DOMAIN)
    net.safe_get(f"https://{DOMAIN}/")
    net.safe_get(f"https://www.{DOMAIN}/")
    net.safe_get("https://crt.sh/?q=%25.x&output=json")
    assert [c["timeout"] for c in fake.calls] == [10.0, 10.0, 10.0]


def test_only_net_imports_http():
    root = Path(pe_risk_key.collectors.__file__).parent
    banned = {"socket", "requests", "httpx", "urllib"}
    offenders = []
    for path in sorted(root.glob("*.py")):
        if path.name == "net.py":
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                modules = [a.name.split(".")[0] for a in node.names]
            elif isinstance(node, ast.ImportFrom) and node.module:
                modules = [node.module.split(".")[0]]
            else:
                continue
            for module in modules:
                if module in banned:
                    offenders.append(f"{path.name} imports {module}")
    assert offenders == []
