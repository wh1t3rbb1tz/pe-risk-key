"""check_web_posture collector: one HTTPS GET per host + TLS inspection."""

from __future__ import annotations

import re
from html.parser import HTMLParser

from pe_risk_key.collectors.net import (
    SafetyBoundaryError,
    safe_get,
    short_reason,
    tls_accepts,
    tls_info,
)
from pe_risk_key.collectors.registry import register

COLLECTION_METHOD = "single_https_get"

HEADER_NAMES = [
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "server",
    "x-powered-by",
]

LEGACY_TLS_VERSIONS = ["TLSv1.0", "TLSv1.1"]
TLS_ORDER = ["TLSv1.0", "TLSv1.1", "TLSv1.2", "TLSv1.3"]

# Known product login/asset path fragments matched (case-insensitive)
# against link targets found in the fetched page only. Never fetched.
KNOWN_PATH_PATTERNS = [
    ("/wp-login.php", "WordPress"),
    ("/wp-includes/", "WordPress"),
    ("/examplegate/login", "ExampleGate SSL-VPN"),
]

PLUGIN_PATH_RE = re.compile(r"/wp-content/plugins/([^/?#]+)", re.IGNORECASE)
THEME_PATH_RE = re.compile(r"/wp-content/themes/([^/?#]+)", re.IGNORECASE)
UPLOADS_PATH_RE = re.compile(r"/wp-content/uploads/", re.IGNORECASE)
VERSION_PARAM_RE = re.compile(r"[?&]ver=([^&#]+)", re.IGNORECASE)
VERSION_RE = re.compile(r"^\d+(\.\d+){0,3}([-.+][\w.]+)?$")
HEX_BLOB_RE = re.compile(r"^[0-9a-fA-F]{7,}$")

CDN_TOKENS = ("cloudflare", "akamai", "fastly", "cloudfront")
APPLIANCE_TOKENS = ("vpn", "firewall", "gateway")
CMS_PRODUCTS = ("wordpress", "joomla", "drupal")


class _PageLinks(HTMLParser):
    """Collects generator meta content plus link/script href targets."""

    def __init__(self) -> None:
        super().__init__()
        self.generators: list[str] = []
        self.hrefs: list[str] = []

    def handle_starttag(self, tag: str, attrs: list) -> None:
        attrs = {k.lower(): (v or "") for k, v in attrs}
        if tag == "meta" and attrs.get("name", "").lower() == "generator":
            if attrs.get("content"):
                self.generators.append(attrs["content"])
        if tag in ("a", "link") and attrs.get("href"):
            self.hrefs.append(attrs["href"])
        if tag == "script" and attrs.get("src"):
            self.hrefs.append(attrs["src"])


def _split_product_version(text: str) -> tuple[str, str | None]:
    chunks = text.strip().split(None, 1)
    if len(chunks) == 2:
        return chunks[0], chunks[1]
    return text.strip(), None


def _split_header_product(text: str) -> tuple[str, str | None]:
    token = text.strip().split(None, 1)[0]
    if "/" in token:
        product, version = token.split("/", 1)
        return product, version or None
    return token, None


def _parse_version(raw: str | None) -> str | None:
    """Validate a ``?ver=`` value: version-like, not a hash, WC-aware."""
    if not raw:
        return None
    parts = re.split(r"(?i)wc\.", raw, maxsplit=1)
    candidate = parts[1] if len(parts) == 2 else raw
    if not VERSION_RE.match(candidate):
        return None
    if HEX_BLOB_RE.match(candidate):
        return None
    return candidate


def _asset_version(href: str) -> str | None:
    match = VERSION_PARAM_RE.search(href)
    return _parse_version(match.group(1)) if match else None


def _classify_kind(product: str, source: str) -> str:
    name = product.strip().lower()
    if any(token in name for token in CDN_TOKENS):
        return "cdn_or_proxy"
    if any(token in name for token in APPLIANCE_TOKENS):
        return "appliance"
    if source == "meta_generator" or name in CMS_PRODUCTS:
        return "cms"
    return "web_server"


def _raw_fingerprints(url: str, headers: dict, body: str) -> list[dict]:
    found: list[dict] = []

    def add(
        product: str,
        version: str | None,
        source: str,
        where: str,
        kind: str | None = None,
    ) -> None:
        found.append(
            {
                "product": product,
                "version": version,
                "kind": kind or _classify_kind(product, source),
                "source": source,
                "locators": [f"{url} ({where})"],
            }
        )

    if headers.get("server"):
        product, version = _split_header_product(headers["server"])
        add(product, version, "server_header", "server header")
    if headers.get("x-powered-by"):
        product, version = _split_header_product(headers["x-powered-by"])
        add(product, version, "server_header", "x-powered-by header")
    page = _PageLinks()
    page.feed(body)
    for content in page.generators:
        product, version = _split_product_version(content)
        add(product, version, "meta_generator", "meta generator tag")
    for href in page.hrefs:
        lowered = href.lower()
        plugin = PLUGIN_PATH_RE.search(href)
        if plugin:
            add(
                plugin.group(1),
                _asset_version(href),
                "asset_path",
                f"link {href}",
                kind="plugin",
            )
            continue
        theme = THEME_PATH_RE.search(href)
        if theme:
            add(
                theme.group(1),
                _asset_version(href),
                "asset_path",
                f"link {href}",
                kind="theme",
            )
            continue
        if UPLOADS_PATH_RE.search(href):
            continue
        for fragment, product in KNOWN_PATH_PATTERNS:
            if fragment in lowered:
                add(product, None, "asset_path", f"link {href}")
    return found


def _version_key(version: str) -> tuple:
    match = re.match(r"^(\d+(?:\.\d+)*)(.*)$", version)
    if not match:
        return ((), version)
    numeric = tuple(int(part) for part in match.group(1).split("."))
    return (numeric, match.group(2))


def _best_version(first: str | None, second: str | None) -> str | None:
    """Highest real version; ties and non-version strings keep the first."""
    if first is None:
        return second
    if second is None:
        return first
    return second if _version_key(second) > _version_key(first) else first


def _merge_fingerprints(found: list[dict]) -> list[dict]:
    """Merge by normalized product: highest version, capped locators."""
    merged: dict[str, dict] = {}
    for fingerprint in found:
        key = fingerprint["product"].strip().lower()
        if key not in merged:
            merged[key] = {
                **fingerprint,
                "locators": list(fingerprint["locators"]),
            }
            continue
        current = merged[key]
        current["version"] = _best_version(
            current["version"], fingerprint["version"]
        )
        for locator in fingerprint["locators"]:
            if locator not in current["locators"]:
                current["locators"].append(locator)
    for fingerprint in merged.values():
        fingerprint["locator_count"] = len(fingerprint["locators"])
        fingerprint["locators"] = fingerprint["locators"][:3]
    return list(merged.values())


def _fingerprints(url: str, headers: dict, body: str) -> list[dict]:
    return _merge_fingerprints(_raw_fingerprints(url, headers, body))


def _collect_host(host: str) -> dict:
    url = f"https://{host}/"
    entry: dict = {
        "host": host,
        "url": url,
        "status": "ok",
        "status_code": None,
        "redirect_location": None,
        "tls_support": {version: "not_tested" for version in TLS_ORDER},
        "tls_versions": [],
        "cert": None,
        "headers": {name: None for name in HEADER_NAMES},
        "fingerprints": [],
    }
    try:
        response = safe_get(url)
        entry["status_code"] = response.status_code
        entry["headers"] = {
            name: response.headers.get(name) for name in HEADER_NAMES
        }
        if 300 <= response.status_code < 400:
            # Valid result: record the redirect, never follow it.
            entry["status"] = "redirect"
            entry["redirect_location"] = response.headers.get("location")
        elif 200 <= response.status_code < 300:
            entry["fingerprints"] = _fingerprints(
                url, entry["headers"], response.text
            )
        else:
            entry["status"] = "error"
            entry["error"] = f"HTTP {response.status_code}"
            return entry
        info = tls_info(host)
        support: dict[str, bool | str] = {}
        for version in TLS_ORDER:
            if version == info["version"]:
                support[version] = True
            elif version in LEGACY_TLS_VERSIONS:
                probe = tls_accepts(host, version)
                if probe is True:
                    support[version] = True
                elif probe is False:
                    support[version] = False
                else:
                    support[version] = "not_tested"
            else:
                support[version] = "not_tested"
        entry["tls_support"] = support
        entry["tls_versions"] = [
            version for version in TLS_ORDER if support[version] is True
        ]
        if info["version"] not in entry["tls_versions"]:
            entry["tls_versions"].append(info["version"])
        entry["cert"] = {
            "issuer": info["issuer"],
            "days_remaining": info["days_remaining"],
            "not_after": info["not_after"],
        }
    except SafetyBoundaryError:
        raise
    except Exception as exc:  # per-host failure: keep what was collected
        entry["status"] = "error"
        entry["error"] = short_reason(exc)
    return entry


@register(
    tool_name="check_web_posture",
    description=(
        "Fetch the apex and www home pages once each (the only HTTP in "
        "this tool), reading security headers, TLS posture, and technology "
        "fingerprints. Same as loading each page in a browser."
    ),
    collection_method=COLLECTION_METHOD,
)
def collect(domain: str) -> dict:
    """Collect web posture for the apex and www hosts.

    Never raises for a single-host failure: failed hosts come back as
    ``status: "error"`` entries and the section reports ``partial`` (or
    ``error`` when every host failed).
    """
    hosts = [_collect_host(domain), _collect_host(f"www.{domain}")]
    errors = sum(1 for host in hosts if host["status"] == "error")
    if errors == len(hosts):
        status = "error"
    elif errors:
        status = "partial"
    else:
        status = "ok"
    return {
        "collection_method": COLLECTION_METHOD,
        "status": status,
        "hosts": hosts,
    }
