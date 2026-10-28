"""Tests for pe_risk_key.collectors (SPEC §2, §4.1). No network access."""

import ast
import json
import ssl
from datetime import date, datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import dns.resolver
import httpx
import pe_risk_key.collectors
import pytest

from pe_risk_key.collectors import (
    ALLOWED_METHODS,
    SafetyBoundaryError,
    run,
    tool_definitions,
)
from pe_risk_key.collectors import (
    ct,
    dnssec,
    email_auth,
    incidents,
    kev,
    net,
    web_posture,
)
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

    def get(self, url, timeout=None, **kwargs):
        self.calls.append({"url": url, "timeout": timeout, **kwargs})
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
    assert (
        run("search_public_incidents", DOMAIN)
        == fixture["search_public_incidents"]
    )
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
        "search_public_incidents",
    }
    for definition in defs:
        assert definition["type"] == "function"
        params = definition["function"]["parameters"]
        assert params["required"] == ["domain"]
        if definition["function"]["name"] == "search_public_incidents":
            assert set(params["properties"]) == {"domain", "company_name"}
        else:
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
    assert all(c["follow_redirects"] is False for c in fake.calls)


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
    def __init__(self):
        self.calls: list = []

    def get(self, url, timeout=None, **kwargs):
        self.calls.append({"url": url, "timeout": timeout, **kwargs})
        if url == f"https://{DOMAIN}/":
            headers = {"server": "nginx", "x-frame-options": "SAMEORIGIN"}
            text = APEX_HTML
        else:
            headers = {}
            text = WWW_HTML
        return SimpleNamespace(status_code=200, headers=headers, text=text)


class _FakeWebPages:
    """Canned per-URL (status, headers, text) responses or exceptions."""

    def __init__(self, pages):
        self.calls: list = []
        self.pages = pages

    def get(self, url, timeout=None, **kwargs):
        self.calls.append({"url": url, "timeout": timeout, **kwargs})
        page = self.pages[url]
        if isinstance(page, Exception):
            raise page
        status_code, headers, text = page
        return SimpleNamespace(status_code=status_code, headers=headers, text=text)


def _mock_tls(monkeypatch, accepts=None):
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
        web_posture, "tls_accepts", accepts or (lambda host, version: False)
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
    probes = {
        (f"www.{DOMAIN}", "TLSv1.0"): True,
        (DOMAIN, "TLSv1.1"): "unknown",
    }
    monkeypatch.setattr(
        web_posture,
        "tls_accepts",
        lambda host, version: probes.get((host, version), False),
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
            "kind": "web_server",
            "source": "server_header",
            "locators": [f"https://{DOMAIN}/ (server header)"],
            "locator_count": 1,
        }
    ]
    assert apex["tls_support"] == {
        "TLSv1.0": False,
        "TLSv1.1": "not_tested",
        "TLSv1.2": "not_tested",
        "TLSv1.3": True,
    }
    assert apex["tls_versions"] == ["TLSv1.3"]
    assert www["tls_support"] == {
        "TLSv1.0": True,
        "TLSv1.1": False,
        "TLSv1.2": "not_tested",
        "TLSv1.3": True,
    }
    assert www["tls_versions"] == ["TLSv1.0", "TLSv1.3"]
    assert www["fingerprints"] == [
        {
            "product": "WordPress",
            "version": "6.2",
            "kind": "cms",
            "source": "meta_generator",
            "locators": [f"https://www.{DOMAIN}/ (meta generator tag)"],
            "locator_count": 1,
        },
        {
            "product": "ExampleGate SSL-VPN",
            "version": None,
            "kind": "appliance",
            "source": "asset_path",
            "locators": [f"https://www.{DOMAIN}/ (link /examplegate/login)"],
            "locator_count": 1,
        },
    ]
    assert www["cert"]["issuer"] == "Example Public CA"
    fixture_host = _brightwater_fixture()["check_web_posture"]["hosts"][0]
    assert set(apex) == set(fixture_host)
    assert set(apex["cert"]) == set(fixture_host["cert"])
    assert set(apex["fingerprints"][0]) == set(fixture_host["fingerprints"][0])


WP_PLUGIN_HTML = """<html><head>
<meta name="generator" content="WordPress 6.2">
</head><body>
<a href="/wp-login.php">login</a>
<script src="/wp-content/plugins/duplicator/admin.js?ver=1.5.2"></script>
<link href="/wp-content/plugins/duplicator/style.css" rel="stylesheet">
<a href="/wp-content/plugins/social-warfare/x.js">x</a>
</body></html>"""


def test_web_posture_merges_products_and_detects_plugins(monkeypatch):
    pages = {
        f"https://{DOMAIN}/": (200, {}, WP_PLUGIN_HTML),
        f"https://www.{DOMAIN}/": (200, {}, APEX_HTML),
    }
    monkeypatch.setattr(net, "httpx", _FakeWebPages(pages))
    _mock_tls(monkeypatch)
    net.begin_run(DOMAIN)
    (apex, _) = web_posture.collect(DOMAIN)["hosts"]
    base = f"https://{DOMAIN}"
    assert apex["fingerprints"] == [
        {
            "product": "WordPress",
            "version": "6.2",
            "kind": "cms",
            "source": "meta_generator",
            "locators": [
                f"{base}/ (meta generator tag)",
                f"{base}/ (link /wp-login.php)",
            ],
            "locator_count": 2,
        },
        {
            "product": "duplicator",
            "version": "1.5.2",
            "kind": "plugin",
            "source": "asset_path",
            "locators": [
                f"{base}/ (link /wp-content/plugins/duplicator/admin.js?ver=1.5.2)",
                f"{base}/ (link /wp-content/plugins/duplicator/style.css)",
            ],
            "locator_count": 2,
        },
        {
            "product": "social-warfare",
            "version": None,
            "kind": "plugin",
            "source": "asset_path",
            "locators": [
                f"{base}/ (link /wp-content/plugins/social-warfare/x.js)"
            ],
            "locator_count": 1,
        },
    ]


def test_kev_product_match_and_note(monkeypatch):
    monkeypatch.setattr(kev, "KEV_SNAPSHOT_PATH", KEV_MINI)
    matched_fp = {
        "host": f"www.{DOMAIN}",
        "product": "examplegate ssl-vpn",
        "version": "7.0.11",
        "kind": "appliance",
        "source": "asset_path",
        "locators": [f"https://www.{DOMAIN}/ (link /examplegate/login)"],
    }
    fps = [
        matched_fp,
        {
            "host": DOMAIN,
            "product": "nginx",
            "version": None,
            "kind": "web_server",
            "source": "server_header",
            "locators": [f"https://{DOMAIN}/ (server header)"],
        },
    ]
    out = kev.collect(DOMAIN, fingerprints=fps)
    assert out["collection_method"] == "offline_lookup"
    assert out["matches_count"] == 1
    (match,) = out["matches"]
    assert match["cve_id"] == "CVE-PLACEHOLDER-0001"
    assert match["vendor"] == "ExampleGate"
    assert match["product"] == "ExampleGate SSL-VPN"
    assert match["matched_fingerprint"] == {
        "product": "examplegate ssl-vpn",
        "kind": "appliance",
        "version": "7.0.11",
        "host": f"www.{DOMAIN}",
        "locator": f"https://www.{DOMAIN}/ (link /examplegate/login)",
    }
    assert match["kev_snapshot_date"] == "2026-10-20"
    assert match["match_level"] == "product"
    assert match["match_tier"] == "appliance_exposed"
    assert (
        match["note"]
        == "KEV lists products, not affected versions; version not verified."
    )
    assert "version" not in match


def test_kev_cdn_fingerprints_match_nothing(monkeypatch):
    monkeypatch.setattr(kev, "KEV_SNAPSHOT_PATH", KEV_MINI)
    out = kev.collect(
        DOMAIN,
        fingerprints=[
            {
                "host": DOMAIN,
                "product": "Cloudflare",
                "version": None,
                "kind": "cdn_or_proxy",
                "source": "server_header",
                "locators": [f"https://{DOMAIN}/ (server header)"],
            }
        ],
    )
    assert out["matches"] == []
    assert out["matches_count"] == 0


def test_kev_cms_matches_only_core(monkeypatch):
    monkeypatch.setattr(kev, "KEV_SNAPSHOT_PATH", KEV_MINI)
    out = kev.collect(
        DOMAIN,
        fingerprints=[
            {
                "host": f"www.{DOMAIN}",
                "product": "WordPress",
                "version": "6.2",
                "kind": "cms",
                "source": "meta_generator",
                "locators": ["u"],
            }
        ],
    )
    assert [m["cve_id"] for m in out["matches"]] == ["CVE-2024-11111"]
    assert out["matches"][0]["match_tier"] == "product_listed"


def test_kev_plugin_slug_matches_its_entry(monkeypatch):
    monkeypatch.setattr(kev, "KEV_SNAPSHOT_PATH", KEV_MINI)
    out = kev.collect(
        DOMAIN,
        fingerprints=[
            {
                "host": f"www.{DOMAIN}",
                "product": "duplicator",
                "version": "1.5.2",
                "kind": "plugin",
                "source": "asset_path",
                "locators": ["u"],
            }
        ],
    )
    (match,) = out["matches"]
    assert match["cve_id"] == "CVE-2024-33333"
    assert match["product"] == "Snap Creek Duplicator Plugin"
    assert match["match_tier"] == "product_listed"


def test_kev_dedupes_by_cve_and_host(monkeypatch):
    monkeypatch.setattr(kev, "KEV_SNAPSHOT_PATH", KEV_MINI)
    out = kev.collect(
        DOMAIN,
        fingerprints=[
            {
                "host": f"www.{DOMAIN}",
                "product": "duplicator",
                "kind": "plugin",
                "locators": ["u1"],
            },
            {
                "host": f"www.{DOMAIN}",
                "product": "Duplicator",
                "kind": "plugin",
                "locators": ["u2"],
            },
            {
                "host": DOMAIN,
                "product": "duplicator",
                "kind": "plugin",
                "locators": ["u3"],
            },
        ],
    )
    assert out["matches_count"] == 2
    assert {(m["cve_id"], m["matched_fingerprint"]["host"]) for m in out["matches"]} == {
        ("CVE-2024-33333", f"www.{DOMAIN}"),
        ("CVE-2024-33333", DOMAIN),
    }


def test_plugin_generator_tag_merges_with_asset_fingerprint(monkeypatch):
    html = """<html><head>
<meta name="generator" content="WordPress 6.4.2">
<meta name="generator" content="WooCommerce 9.1.0">
</head><body>
<link href="/wp-content/plugins/woocommerce/assets/style.css?ver=9.0.0">
</body></html>"""
    pages = {
        f"https://{DOMAIN}/": (200, {}, html),
        f"https://www.{DOMAIN}/": (200, {}, APEX_HTML),
    }
    monkeypatch.setattr(net, "httpx", _FakeWebPages(pages))
    _mock_tls(monkeypatch)
    net.begin_run(DOMAIN)
    (apex, _) = web_posture.collect(DOMAIN)["hosts"]
    by_product = {fp["product"]: fp for fp in apex["fingerprints"]}
    assert set(by_product) == {"WordPress", "woocommerce"}
    assert by_product["WordPress"]["kind"] == "cms"
    woo = by_product["woocommerce"]
    assert woo["kind"] == "plugin"
    assert woo["version"] == "9.1.0"  # generator tag wins over asset ver
    assert woo["locator_count"] == 2
    assert any("meta generator tag" in loc for loc in woo["locators"])
    assert any("plugins/woocommerce" in loc for loc in woo["locators"])


def test_wordpress_page_fixture(monkeypatch):
    html = (Path(__file__).resolve().parent / "data" / "wordpress_page.html").read_text(
        encoding="utf-8"
    )
    pages = {
        f"https://{DOMAIN}/": (200, {}, html),
        f"https://www.{DOMAIN}/": (200, {}, APEX_HTML),
    }
    monkeypatch.setattr(net, "httpx", _FakeWebPages(pages))
    _mock_tls(monkeypatch)
    net.begin_run(DOMAIN)
    (apex, _) = web_posture.collect(DOMAIN)["hosts"]
    base = f"https://{DOMAIN}"
    by_product = {fp["product"]: fp for fp in apex["fingerprints"]}
    assert set(by_product) == {
        "WordPress",
        "storefront",
        "woocommerce",
        "duplicator",
        "social-warfare",
        "w3-total-cache",
    }
    cms = by_product["WordPress"]
    assert cms["version"] == "6.4.2" and cms["kind"] == "cms"
    assert cms["locators"] == [f"{base}/ (meta generator tag)"]
    assert cms["locator_count"] == 1
    theme = by_product["storefront"]
    assert (theme["version"], theme["kind"]) == ("4.5.0", "theme")
    woo = by_product["woocommerce"]
    assert woo["version"] == "11.2.1"  # part after wc.
    assert woo["locator_count"] == 2
    dup = by_product["duplicator"]
    assert dup["version"] == "1.5.2"  # highest of 1.5.2 x3, 1.4.0
    assert len(dup["locators"]) == 3 and dup["locator_count"] == 4
    assert by_product["social-warfare"]["version"] is None  # 40-hex hash
    assert by_product["w3-total-cache"]["version"] is None  # digit hash
    assert all("uploads" not in loc for fp in apex["fingerprints"] for loc in fp["locators"])


def test_kev_slim_references_from_detected_fingerprints(monkeypatch):
    html = (Path(__file__).resolve().parent / "data" / "wordpress_page.html").read_text(
        encoding="utf-8"
    )
    pages = {
        f"https://{DOMAIN}/": (200, {}, html),
        f"https://www.{DOMAIN}/": (200, {}, APEX_HTML),
    }
    monkeypatch.setattr(net, "httpx", _FakeWebPages(pages))
    monkeypatch.setattr(kev, "KEV_SNAPSHOT_PATH", KEV_MINI)
    _mock_tls(monkeypatch)
    net.begin_run(DOMAIN)
    (apex, _) = web_posture.collect(DOMAIN)["hosts"]
    fingerprints = [{**fp, "host": DOMAIN} for fp in apex["fingerprints"]]
    out = kev.collect(DOMAIN, fingerprints=fingerprints)
    assert {m["cve_id"] for m in out["matches"]} == {
        "CVE-2024-11111",
        "CVE-2024-33333",
        "CVE-2024-44444",
    }
    for match in out["matches"]:
        assert set(match["matched_fingerprint"]) == {
            "product",
            "kind",
            "version",
            "host",
            "locator",
        }
    dup = next(m for m in out["matches"] if m["cve_id"] == "CVE-2024-33333")
    assert dup["matched_fingerprint"]["locator"].startswith(f"https://{DOMAIN}/")


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
                        "kind": "appliance",
                        "source": "asset_path",
                        "locators": ["u"],
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
        fingerprints=[
            {"product": "ExampleGate SSL-VPN", "kind": "appliance", "locators": ["u"]}
        ],
    )
    assert out["matches_count"] == 1


REDIRECT_HTML = "<html><head><title>moved</title></head><body>moved</body></html>"


def test_web_posture_records_redirect_without_following(monkeypatch):
    pages = {
        f"https://{DOMAIN}/": (200, {"server": "nginx"}, APEX_HTML),
        f"https://www.{DOMAIN}/": (
            301,
            {
                "location": f"https://{DOMAIN}/",
                "strict-transport-security": "max-age=31536000",
            },
            REDIRECT_HTML,
        ),
    }
    fake = _FakeWebPages(pages)
    monkeypatch.setattr(net, "httpx", fake)
    _mock_tls(monkeypatch)
    net.begin_run(DOMAIN)
    out = web_posture.collect(DOMAIN)
    assert out["status"] == "ok"  # a redirect is a valid result
    apex, www = out["hosts"]
    assert apex["status"] == "ok"
    assert www["status"] == "redirect"
    assert www["status_code"] == 301
    assert www["redirect_location"] == f"https://{DOMAIN}/"
    assert www["headers"]["strict-transport-security"] == "max-age=31536000"
    assert www["fingerprints"] == []
    assert [c["url"] for c in fake.calls] == [
        f"https://{DOMAIN}/",
        f"https://www.{DOMAIN}/",
    ]


def test_web_posture_partial_on_www_timeout(monkeypatch):
    pages = {
        f"https://{DOMAIN}/": (200, {"server": "nginx"}, APEX_HTML),
        f"https://www.{DOMAIN}/": httpx.ReadTimeout("timed out"),
    }
    monkeypatch.setattr(net, "httpx", _FakeWebPages(pages))
    _mock_tls(monkeypatch)
    net.begin_run(DOMAIN)
    out = web_posture.collect(DOMAIN)
    assert out["status"] == "partial"
    apex, www = out["hosts"]
    assert apex["status"] == "ok"
    assert www["status"] == "error"
    assert www["error"] == "timeout"


def test_web_posture_error_on_www_dns_failure(monkeypatch):
    pages = {
        f"https://{DOMAIN}/": (200, {"server": "nginx"}, APEX_HTML),
        f"https://www.{DOMAIN}/": httpx.ConnectError(
            "[Errno -2] Name or service not known"
        ),
    }
    monkeypatch.setattr(net, "httpx", _FakeWebPages(pages))
    _mock_tls(monkeypatch)
    net.begin_run(DOMAIN)
    out = web_posture.collect(DOMAIN)
    assert out["status"] == "partial"
    www = out["hosts"][1]
    assert www["status"] == "error"
    assert www["error"] == "connection failed"


def test_ct_503_returns_error_status(monkeypatch):
    def get(url, timeout=None, **kwargs):
        request = httpx.Request("GET", url)
        response = httpx.Response(503, request=request)

        def fail():
            raise httpx.HTTPStatusError(
                "unavailable", request=request, response=response
            )

        return SimpleNamespace(json=lambda: [], raise_for_status=fail)

    monkeypatch.setattr(net, "httpx", SimpleNamespace(get=get))
    net.begin_run(DOMAIN)
    out = ct.collect(DOMAIN)
    assert out["status"] == "error"
    assert out["error"] == "HTTP 503"
    assert out["collection_method"] == "ct_log_query"
    assert out["query_url"] == f"https://crt.sh/?q=%25.{DOMAIN}&output=json"


def test_ct_timeout_returns_error_status(monkeypatch):
    def get(url, timeout=None, **kwargs):
        raise httpx.ReadTimeout("timed out")

    monkeypatch.setattr(net, "httpx", SimpleNamespace(get=get))
    net.begin_run(DOMAIN)
    out = ct.collect(DOMAIN)
    assert out["status"] == "error"
    assert out["error"] == "timeout"


def test_run_catches_collector_exceptions(monkeypatch):
    from pe_risk_key.collectors.registry import _REGISTRY

    monkeypatch.delenv("DEMO_MODE", raising=False)

    def boom(domain):
        raise RuntimeError("kaput")

    register(
        tool_name="boom_probe", description="x", collection_method="dns_query"
    )(boom)
    try:
        out = run("boom_probe", DOMAIN)
    finally:
        _REGISTRY.pop("boom_probe", None)
    assert out == {
        "status": "error",
        "error": "RuntimeError: kaput",
        "collection_method": "dns_query",
    }


def test_fixture_sections_have_status():
    sections = [
        "check_email_auth",
        "check_dnssec",
        "enumerate_ct_subdomains",
        "check_web_posture",
        "match_known_exploited",
        "search_public_incidents",
    ]
    for name in ("brightwaterfleet.example.json", "copperline.example.json"):
        data = json.loads((FIXTURES_DIR / name).read_text(encoding="utf-8"))
        for section in sections:
            assert data[section]["status"] == "ok", (name, section)
            assert data[section]["collection_method"], (name, section)
        for host in data["check_web_posture"]["hosts"]:
            assert host["status"] == "ok"
            assert host["status_code"] == 200
            assert "redirect_location" in host


# --- search_public_incidents (mocked search + extraction) --------------------


def _grounded_response(texts, citations):
    """Fake Responses API response: one message item per text in ``texts``.

    ``citations`` is a list of (url, title) attached to the LAST message,
    mirroring a narrated search followed by a cited final answer.
    """
    items = [SimpleNamespace(type="web_search_call", status="completed")]
    for index, text in enumerate(texts):
        if index == len(texts) - 1:
            annotations = [
                SimpleNamespace(
                    type="url_citation",
                    url=url,
                    title=title,
                    start_index=0,
                    end_index=1,
                )
                for url, title in citations
            ]
        else:
            annotations = []
        items.append(
            SimpleNamespace(
                type="message",
                status="completed",
                role="assistant",
                content=[
                    SimpleNamespace(
                        type="output_text",
                        text=text,
                        annotations=annotations,
                    )
                ],
            )
        )
    return SimpleNamespace(output=items)


class _ScriptedSearchClient:
    """Fake ModelClient for the two-phase flow.

    ``script`` maps each query to queued (texts, citations) pages or an
    exception; ``extraction`` holds queued phase-2 outputs or an
    exception. Token bumps make per-phase usage assertions possible.
    """

    script: dict = {}
    extraction: Any = None
    calls: list = []
    extract_calls: list = []

    def __init__(self, role, **kwargs):
        assert role == "public_records", role
        self.total_usage = {
            "prompt_tokens": 0,
            "completion_tokens": 0,
            "cached_tokens": 0,
        }

    def responses_search(self, query, *, instructions=None, **kwargs):
        type(self).calls.append(query)
        self.total_usage["prompt_tokens"] += 10
        self.total_usage["completion_tokens"] += 5
        pages = type(self).script[query]
        if isinstance(pages, Exception):
            raise pages
        texts, citations = pages.pop(0)
        return _grounded_response(texts, citations)

    def chat_json(self, messages, *, schema=None, schema_name="r", **kwargs):
        type(self).extract_calls.append(messages)
        self.total_usage["prompt_tokens"] += 100
        self.total_usage["completion_tokens"] += 20
        out = type(self).extraction
        if isinstance(out, Exception):
            raise out
        return out.pop(0)


@pytest.fixture
def search_script(monkeypatch):
    _ScriptedSearchClient.script = {}
    _ScriptedSearchClient.extraction = []
    _ScriptedSearchClient.calls = []
    _ScriptedSearchClient.extract_calls = []
    monkeypatch.setattr(incidents, "ModelClient", _ScriptedSearchClient)
    monkeypatch.delenv("DEMO_MODE", raising=False)
    return _ScriptedSearchClient


COMPANY = "Acme Corporation"
QUERIES = [
    "Acme Corporation data breach",
    "Acme Corporation security incident notification",
    "Acme Corporation 8-K Item 1.05 cybersecurity incident",
    f"{DOMAIN} breach notice attorney general",
]


def _incident_result(url, **overrides):
    result = {
        "type": "state_ag_breach_notice",
        "date": "2025-08-14",
        "summary": "Notice filed.",
        "url": url,
        "entity_match": "exact",
        "match_basis": "Names the company.",
    }
    result.update(overrides)
    return result


def _quiet_script(queries=QUERIES):
    return {
        query: [(["No incidents found for this query."], [])]
        for query in queries
    }


def _extraction_input(search_script):
    (messages,) = search_script.extract_calls
    return messages


def test_incidents_uses_final_message_and_citations(search_script):
    url = "https://ag.state.example/notices/acme-2025"
    narration = "I'll search for Acme Corporation breach notices now."
    final = "Summary: an AG breach notice was filed in August 2025."
    script = _quiet_script()
    script[QUERIES[0]] = [([narration, final], [(url, "AG notice")])]
    search_script.script = script
    search_script.extraction = [{"results": [_incident_result(url)]}]
    out = incidents.collect(DOMAIN, company_name=COMPANY)
    assert out["collection_method"] == "search_grounding"
    assert out["status"] == "ok"
    assert out["queries_run"] == QUERIES
    assert search_script.calls == QUERIES  # 4-search cap, one call each
    # Phase 2 saw the final text and the citation, not the narration.
    user_text = _extraction_input(search_script)[1]["content"]
    assert final in user_text
    assert narration not in user_text
    assert url in user_text
    assert out["dropped_uncited"] == 0
    assert out["dropped_prohibited_source"] == 0
    (kept,) = out["results"]
    assert kept["url"] == url
    assert kept["locator"] == url
    assert kept["entity_match"] == "exact"
    assert kept["counts_toward_findings"] is True
    # Months computed in code from the result date, not from the model.
    today = date.today()
    assert out["disclosed_within_months"] == (
        (today.year - 2025) * 12 + today.month - 8
    )


def test_incidents_extraction_uses_only_provided_citations(search_script):
    cited = "https://ag.state.example/notices/acme-cited"
    invented = "https://news.example/acme-invented"
    script = _quiet_script()
    script[QUERIES[0]] = [
        (["Summary: one notice found."], [(cited, "AG notice")])
    ]
    search_script.script = script
    search_script.extraction = [
        {
            "results": [
                _incident_result(cited),
                _incident_result(invented),
            ]
        }
    ]
    out = incidents.collect(DOMAIN, company_name=COMPANY)
    assert [r["url"] for r in out["results"]] == [cited]
    assert out["dropped_uncited"] == 1
    assert out["status"] == "ok"


def test_incidents_drops_prohibited_sources(search_script):
    paste = "https://pastebin.com/raw/acme53"
    forum = "https://breachforums.example/thread/9"
    script = _quiet_script()
    script[QUERIES[0]] = [
        (["Summary: two dumps found."], [(paste, "p"), (forum, "f")])
    ]
    search_script.script = script
    search_script.extraction = [
        {
            "results": [
                _incident_result(paste),
                _incident_result(forum),
            ]
        }
    ]
    out = incidents.collect(DOMAIN, company_name=COMPANY)
    assert out["results"] == []
    assert out["dropped_prohibited_source"] == 2
    assert out["dropped_uncited"] == 0


def test_incidents_uncertain_match_not_counted(search_script):
    old = _incident_result(
        "https://ag.state.example/notices/acme-old", date="2024-01-10"
    )
    new = _incident_result(
        "https://news.example/acme-maybe",
        date="2026-10-01",
        type="press_report",
        entity_match="uncertain",
        match_basis="Same name, different state; could be another Acme.",
    )
    script = _quiet_script()
    script[QUERIES[0]] = [
        (
            ["Summary: two possible incidents."],
            [(old["url"], "AG"), (new["url"], "press")],
        )
    ]
    search_script.script = script
    search_script.extraction = [{"results": [old, new]}]
    out = incidents.collect(DOMAIN, company_name=COMPANY)
    assert len(out["results"]) == 2
    uncertain = next(
        r for r in out["results"] if r["entity_match"] == "uncertain"
    )
    assert uncertain["counts_toward_findings"] is False
    # Most recent *counted* date is the older exact match.
    today = date.today()
    assert out["disclosed_within_months"] == (
        (today.year - 2024) * 12 + today.month - 1
    )


def test_incidents_domain_fallback_and_query_cap(search_script):
    expected = [
        f"{DOMAIN} data breach",
        f"{DOMAIN} security incident notification",
        f"{DOMAIN} 8-K Item 1.05 cybersecurity incident",
        f"{DOMAIN} breach notice attorney general",
    ]
    search_script.script = _quiet_script(expected)
    search_script.extraction = [{"results": []}]
    out = incidents.collect(DOMAIN)
    assert out["queries_run"] == expected
    assert len(search_script.calls) == 4
    assert len(search_script.extract_calls) == 1  # one extraction call


def test_incidents_empty_results_is_ok(search_script):
    search_script.script = _quiet_script()
    search_script.extraction = [{"results": []}]
    out = incidents.collect(DOMAIN, company_name=COMPANY)
    assert out["status"] == "ok"
    assert out["results"] == []
    assert out["disclosed_within_months"] is None


def test_incidents_partial_when_one_search_fails(search_script):
    script = _quiet_script()
    script[QUERIES[0]] = RuntimeError("boom")
    search_script.script = script
    search_script.extraction = [{"results": []}]
    out = incidents.collect(DOMAIN, company_name=COMPANY)
    assert out["status"] == "partial"
    assert out["queries_run"] == QUERIES
    # Extraction still ran over the three surviving summaries.
    assert len(search_script.extract_calls) == 1


def test_incidents_error_when_all_searches_fail(search_script):
    search_script.script = {query: RuntimeError("down") for query in QUERIES}
    search_script.extraction = [{"results": []}]
    out = incidents.collect(DOMAIN, company_name=COMPANY)
    assert out["status"] == "error"
    assert out["results"] == []
    assert out["disclosed_within_months"] is None
    assert search_script.extract_calls == []  # nothing to extract from
    assert out["usage"]["phase2_extract"] == {
        "prompt_tokens": 0,
        "completion_tokens": 0,
        "cached_tokens": 0,
    }


def test_incidents_error_when_extraction_fails(search_script):
    search_script.script = _quiet_script()
    search_script.extraction = ValueError("bad output twice")
    out = incidents.collect(DOMAIN, company_name=COMPANY)
    assert out["status"] == "error"
    assert out["results"] == []
    assert out["disclosed_within_months"] is None


def test_incidents_reports_per_phase_usage(search_script):
    search_script.script = _quiet_script()
    search_script.extraction = [{"results": []}]
    out = incidents.collect(DOMAIN, company_name=COMPANY)
    assert out["status"] == "ok"
    assert out["usage"] == {
        "searches": 4,
        "phase1_search": {
            "prompt_tokens": 40,
            "completion_tokens": 20,
            "cached_tokens": 0,
        },
        "phase2_extract": {
            "prompt_tokens": 100,
            "completion_tokens": 20,
            "cached_tokens": 0,
        },
    }


def test_incidents_drops_invalid_date(search_script):
    url = "https://ag.state.example/notices/acme-date"
    script = _quiet_script()
    script[QUERIES[0]] = [(["Summary: one notice."], [(url, "AG")])]
    search_script.script = script
    search_script.extraction = [
        {"results": [_incident_result(url, date="2025-13-99")]}
    ]
    out = incidents.collect(DOMAIN, company_name=COMPANY)
    assert out["results"] == []
    assert out["disclosed_within_months"] is None
    assert out["status"] == "ok"


def test_run_passes_company_name_to_incidents(search_script):
    search_script.script = _quiet_script()
    search_script.extraction = [{"results": []}]
    out = run("search_public_incidents", DOMAIN, company_name=COMPANY)
    assert out["queries_run"] == QUERIES


def test_incidents_demo_mode_returns_fixture(monkeypatch):
    monkeypatch.setenv("DEMO_MODE", "1")
    out = run("search_public_incidents", DOMAIN, company_name="Acme")
    assert out == _brightwater_fixture()["search_public_incidents"]
    assert out["results"][0]["entity_match"] == "exact"
    assert out["results"][0]["counts_toward_findings"] is True
    copper = json.loads(
        (FIXTURES_DIR / "copperline.example.json").read_text(encoding="utf-8")
    )
    out = run("search_public_incidents", "copperline.example")
    assert out == copper["search_public_incidents"]
    assert out["results"] == []
    assert out["disclosed_within_months"] is None
