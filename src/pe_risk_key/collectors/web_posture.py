"""check_web_posture collector: one HTTPS GET per host + TLS inspection."""

from __future__ import annotations

from html.parser import HTMLParser

from pe_risk_key.collectors.net import safe_get, tls_accepts, tls_info
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
    response = safe_get(url)
    response.raise_for_status()
    headers = {name: response.headers.get(name) for name in HEADER_NAMES}
    info = tls_info(host)
    versions = {info["version"]}
    for legacy in LEGACY_TLS_VERSIONS:
        if tls_accepts(host, legacy) is True:
            versions.add(legacy)
    tls_versions = sorted(versions, key=lambda v: TLS_ORDER.index(v) if v in TLS_ORDER else 99)
    return {
        "host": host,
        "url": url,
        "tls_versions": tls_versions,
        "cert": {
            "issuer": info["issuer"],
            "days_remaining": info["days_remaining"],
            "not_after": info["not_after"],
        },
        "headers": headers,
        "fingerprints": _fingerprints(url, headers, response.text),
    }


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
    """Collect web posture for the apex and www hosts."""
    return {
        "collection_method": COLLECTION_METHOD,
        "hosts": [_collect_host(domain), _collect_host(f"www.{domain}")],
    }
