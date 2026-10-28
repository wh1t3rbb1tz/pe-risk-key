"""check_web_posture collector: one HTTPS GET per host + TLS inspection."""

from __future__ import annotations

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
    ("/wp-content/", "WordPress"),
    ("/examplegate/login", "ExampleGate SSL-VPN"),
]


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


def _fingerprints(url: str, headers: dict, body: str) -> list[dict]:
    found: list[dict] = []
    seen: set[tuple[str, str | None, str]] = set()

    def add(product: str, version: str | None, where: str) -> None:
        key = (product, version, where.split(" ", 1)[0])
        if key in seen:
            return
        seen.add(key)
        found.append(
            {
                "product": product,
                "version": version,
                "source": where,
                "locator": f"{url} ({where})",
            }
        )

    if headers.get("server"):
        product, version = _split_header_product(headers["server"])
        add(product, version, "server header")
    if headers.get("x-powered-by"):
        product, version = _split_header_product(headers["x-powered-by"])
        add(product, version, "x-powered-by header")
    page = _PageLinks()
    page.feed(body)
    for content in page.generators:
        product, version = _split_product_version(content)
        add(product, version, "meta generator tag")
    for href in page.hrefs:
        lowered = href.lower()
        for fragment, product in KNOWN_PATH_PATTERNS:
            if fragment in lowered:
                add(product, None, f"link {href}")
    return found


def _collect_host(host: str) -> dict:
    url = f"https://{host}/"
    entry: dict = {
        "host": host,
        "url": url,
        "status": "ok",
        "status_code": None,
        "redirect_location": None,
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
        versions = {info["version"]}
        for legacy in LEGACY_TLS_VERSIONS:
            if tls_accepts(host, legacy) is True:
                versions.add(legacy)
        entry["tls_versions"] = sorted(
            versions, key=lambda v: TLS_ORDER.index(v) if v in TLS_ORDER else 99
        )
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
