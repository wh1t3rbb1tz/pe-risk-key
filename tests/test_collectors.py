"""Tests for pe_risk_key.collectors (SPEC §2, §4.1). No network access."""

import ast
import json
import ssl
from datetime import datetime, timezone
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
from pe_risk_key.collectors import ct, dnssec, email_auth, kev, net, web_posture
from pe_risk_key.collectors.registry import register

FIXTURES_DIR = Path(__file__).resolve().parents[1] / "fixtures" / "outside_in"
KEV_MINI = Path(__file__).resolve().parent / "data" / "kev_mini.json"
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
    assert run("check_web_posture", DOMAIN) == fixture["check_web_posture"]
    assert run("match_known_exploited", DOMAIN) == fixture["match_known_exploited"]
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
        "check_web_posture",
        "match_known_exploited",
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
    banned = {"socket", "ssl", "requests", "httpx", "urllib"}
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


class _RawSocket:
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class _TLSSocket(_RawSocket):
    def __init__(self, version="TLSv1.3", cert=None):
        self._version = version
        self._cert = cert

    def version(self):
        return self._version

    def getpeercert(self):
        return self._cert


class _FakeContext:
    def __init__(self, *args, sock=None, fail=None, record=None):
        self._sock = sock if sock is not None else _RawSocket()
        self._fail = fail
        self._record = record if record is not None else {}

    def wrap_socket(self, sock, server_hostname=None):
        self._record["server_hostname"] = server_hostname
        if self._fail is not None:
            raise self._fail
        return self._sock

    def set_ciphers(self, spec):
        self._record["ciphers"] = spec


TLS_CERT = {
    "issuer": (
        (("countryName", "US"),),
        (("organizationName", "Example Public CA"),),
    ),
    "notAfter": "Jan 02 00:00:00 2031 GMT",
}


def test_tls_info(monkeypatch):
    conns: list = []

    def fake_connect(addr, timeout=None):
        conns.append((addr, timeout))
        return _RawSocket()

    tls_sock = _TLSSocket(version="TLSv1.3", cert=TLS_CERT)
    monkeypatch.setattr("socket.create_connection", fake_connect)
    monkeypatch.setattr(
        "ssl.create_default_context",
        lambda: SimpleNamespace(
            wrap_socket=lambda sock, server_hostname=None: tls_sock
        ),
    )
    net.begin_run(DOMAIN)
    info = net.tls_info(DOMAIN)
    assert info["version"] == "TLSv1.3"
    assert info["issuer"] == "Example Public CA"
    assert info["not_after"] == "2031-01-02T00:00:00+00:00"
    expected_days = (
        datetime(2031, 1, 2, tzinfo=timezone.utc)
        - datetime.now(timezone.utc)
    ).days
    assert info["days_remaining"] == expected_days
    assert conns == [((DOMAIN, 443), 10.0)]


def test_tls_info_normalizes_legacy_version_and_issuer_fallback(monkeypatch):
    monkeypatch.setattr(
        "socket.create_connection", lambda addr, timeout=None: _RawSocket()
    )
    cases = [
        (
            {
                "issuer": ((("commonName", "example-ca"),),),
                "notAfter": "Jan 02 00:00:00 2031 GMT",
            },
            "TLSv1",
            "TLSv1.0",
            "example-ca",
        ),
        ({"issuer": (), "notAfter": "Jan 02 00:00:00 2031 GMT"}, "TLSv1.2", "TLSv1.2", ""),
    ]
    for cert, raw_version, version, issuer in cases:
        tls_sock = _TLSSocket(version=raw_version, cert=cert)
        monkeypatch.setattr(
            "ssl.create_default_context",
            lambda tls_sock=tls_sock: SimpleNamespace(
                wrap_socket=lambda sock, server_hostname=None: tls_sock
            ),
        )
        net.begin_run(DOMAIN)
        info = net.tls_info(DOMAIN)
        assert info["version"] == version
        assert info["issuer"] == issuer


def test_tls_info_rejects_non_apex_hosts():
    net.begin_run(DOMAIN)
    with pytest.raises(SafetyBoundaryError, match="apex or www"):
        net.tls_info("crt.sh")
    with pytest.raises(SafetyBoundaryError, match="apex or www"):
        net.tls_info("evil.example")


def test_tls_accepts_true_forces_version(monkeypatch):
    record: dict = {}
    conns: list = []

    def fake_connect(addr, timeout=None):
        conns.append(addr)
        return _RawSocket()

    def fake_context(*args):
        ctx = _FakeContext(record=record)
        record["ctx"] = ctx
        return ctx

    monkeypatch.setattr("socket.create_connection", fake_connect)
    monkeypatch.setattr("ssl.SSLContext", fake_context)
    net.begin_run(DOMAIN)
    assert net.tls_accepts(DOMAIN, "TLSv1.0") is True
    assert record["ctx"].minimum_version == ssl.TLSVersion.TLSv1
    assert record["ctx"].maximum_version == ssl.TLSVersion.TLSv1
    assert record["ciphers"] == "DEFAULT@SECLEVEL=0"
    assert conns == [(DOMAIN, 443)]


def test_tls_accepts_false_on_handshake_refusal(monkeypatch):
    def fake_context(*args):
        return _FakeContext(fail=ssl.SSLError("refused"))

    monkeypatch.setattr(
        "socket.create_connection", lambda addr, timeout=None: _RawSocket()
    )
    monkeypatch.setattr("ssl.SSLContext", fake_context)
    net.begin_run(DOMAIN)
    assert net.tls_accepts(DOMAIN, "TLSv1.1") is False


def test_tls_accepts_unknown_when_version_unconfigurable(monkeypatch):
    class _NoFloorContext(_FakeContext):
        def __setattr__(self, key, value):
            if key in ("minimum_version", "maximum_version"):
                raise AttributeError("TLS floors unsupported")
            super().__setattr__(key, value)

    monkeypatch.setattr("ssl.SSLContext", _NoFloorContext)
    net.begin_run(DOMAIN)
    assert net.tls_accepts(DOMAIN, "TLSv1.0") == "unknown"


def test_tls_accepts_unknown_when_unreachable(monkeypatch):
    def fail_connect(addr, timeout=None):
        raise OSError("down")

    monkeypatch.setattr("socket.create_connection", fail_connect)
    monkeypatch.setattr("ssl.SSLContext", _FakeContext)
    net.begin_run(DOMAIN)
    assert net.tls_accepts(DOMAIN, "TLSv1.0") == "unknown"


def test_tls_accepts_probe_limit_is_per_host(monkeypatch):
    monkeypatch.setattr(
        "socket.create_connection", lambda addr, timeout=None: _RawSocket()
    )
    monkeypatch.setattr("ssl.SSLContext", _FakeContext)
    net.begin_run(DOMAIN)
    assert net.tls_accepts(DOMAIN, "TLSv1.0") is True
    assert net.tls_accepts(DOMAIN, "TLSv1.1") is True
    with pytest.raises(SafetyBoundaryError, match="probe"):
        net.tls_accepts(DOMAIN, "TLSv1.0")
    assert net.tls_accepts(f"www.{DOMAIN}", "TLSv1.0") is True


def test_tls_accepts_rejects_bad_version():
    net.begin_run(DOMAIN)
    with pytest.raises(ValueError, match="TLSv1"):
        net.tls_accepts(DOMAIN, "TLSv1.2")


APEX_HTML = "<html><head><title>apex</title></head><body>hi</body></html>"
WWW_HTML = """<html><head>
<meta name="generator" content="WordPress 6.2">
</head><body>
<a href="/examplegate/login">VPN</a>
<a href="/about">About</a>
</body></html>"""


class _FakeWeb:
    def get(self, url, timeout=None):
        if url == f"https://{DOMAIN}/":
            headers = {"server": "nginx", "x-frame-options": "SAMEORIGIN"}
            text = APEX_HTML
        else:
            headers = {}
            text = WWW_HTML
        return SimpleNamespace(
            headers=headers, text=text, raise_for_status=lambda: None
        )


def test_web_posture_fingerprints_and_tls(monkeypatch):
    monkeypatch.setattr(net, "httpx", _FakeWeb())
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
        web_posture,
        "tls_accepts",
        lambda host, version: host == f"www.{DOMAIN}" and version == "TLSv1.0",
    )
    net.begin_run(DOMAIN)
    out = web_posture.collect(DOMAIN)
    assert out["collection_method"] == "single_https_get"
    assert set(out) == set(_brightwater_fixture()["check_web_posture"])
    assert [h["host"] for h in out["hosts"]] == [DOMAIN, f"www.{DOMAIN}"]
    apex, www = out["hosts"]
    assert apex["url"] == f"https://{DOMAIN}/"
    assert apex["headers"]["server"] == "nginx"
    assert apex["headers"]["x-powered-by"] is None
    assert apex["fingerprints"] == [
        {
            "product": "nginx",
            "version": None,
            "source": "server header",
            "locator": f"https://{DOMAIN}/ (server header)",
        }
    ]
    assert apex["tls_versions"] == ["TLSv1.3"]
    assert www["tls_versions"] == ["TLSv1.0", "TLSv1.3"]
    assert www["fingerprints"] == [
        {
            "product": "WordPress",
            "version": "6.2",
            "source": "meta generator tag",
            "locator": f"https://www.{DOMAIN}/ (meta generator tag)",
        },
        {
            "product": "ExampleGate SSL-VPN",
            "version": None,
            "source": "link /examplegate/login",
            "locator": f"https://www.{DOMAIN}/ (link /examplegate/login)",
        },
    ]
    assert www["cert"]["issuer"] == "Example Public CA"
    fixture_host = _brightwater_fixture()["check_web_posture"]["hosts"][0]
    assert set(apex) == set(fixture_host)
    assert set(apex["cert"]) == set(fixture_host["cert"])
    assert set(apex["fingerprints"][0]) == set(fixture_host["fingerprints"][0])


def test_kev_product_match_and_note(monkeypatch):
    monkeypatch.setattr(kev, "KEV_SNAPSHOT_PATH", KEV_MINI)
    matched_fp = {
        "host": f"www.{DOMAIN}",
        "product": "examplegate ssl-vpn",
        "version": "7.0.11",
        "source": "link /examplegate/login",
        "locator": f"https://www.{DOMAIN}/ (link /examplegate/login)",
    }
    fps = [
        matched_fp,
        {
            "host": DOMAIN,
            "product": "nginx",
            "version": None,
            "source": "server header",
            "locator": f"https://{DOMAIN}/ (server header)",
        },
    ]
    out = kev.collect(DOMAIN, fingerprints=fps)
    assert out["collection_method"] == "offline_lookup"
    assert out["matches_count"] == 1
    (match,) = out["matches"]
    assert match["cve_id"] == "CVE-PLACEHOLDER-0001"
    assert match["vendor"] == "ExampleGate"
    assert match["product"] == "SSL-VPN"
    assert match["matched_fingerprint"] == matched_fp
    assert match["kev_snapshot_date"] == "2026-10-20"
    assert match["match_level"] == "product"
    assert (
        match["note"]
        == "KEV lists products, not affected versions; version not verified."
    )
    assert "version" not in match


def test_kev_self_collects_posture(monkeypatch):
    monkeypatch.setattr(kev, "KEV_SNAPSHOT_PATH", KEV_MINI)
    posture = {
        "hosts": [
            {
                "host": f"www.{DOMAIN}",
                "fingerprints": [
                    {
                        "product": "ExampleGate SSL-VPN",
                        "version": None,
                        "source": "link /x",
                        "locator": "u",
                    }
                ],
            }
        ]
    }
    monkeypatch.setattr(
        kev, "web_posture", SimpleNamespace(collect=lambda domain: posture)
    )
    out = kev.collect(DOMAIN)
    assert out["matches_count"] == 1
    assert out["matches"][0]["matched_fingerprint"]["host"] == f"www.{DOMAIN}"


def test_kev_missing_snapshot_errors(monkeypatch, tmp_path):
    monkeypatch.setattr(kev, "KEV_SNAPSHOT_PATH", tmp_path / "nope.json")
    with pytest.raises(FileNotFoundError, match="update_kev"):
        kev.collect(DOMAIN, fingerprints=[])


def test_run_chains_fingerprints_into_kev(monkeypatch):
    monkeypatch.delenv("DEMO_MODE", raising=False)
    monkeypatch.setattr(kev, "KEV_SNAPSHOT_PATH", KEV_MINI)
    out = run(
        "match_known_exploited",
        DOMAIN,
        fingerprints=[{"product": "ExampleGate SSL-VPN", "locator": "u"}],
    )
    assert out["matches_count"] == 1
