# PE Risk Key

PE-native IT and cybersecurity risk digest, built on Meta Muse models for the
**Meta Global AI Developer Hackathon** (Indie track, theme: Build for Your World).

> **Provenance:** This repository was created and built during the hackathon
> building period, **Oct 27 – Nov 4, 2026**. No code predates the event.
> Planning specs in this first commit were drafted with AI assistance; all
> application code is written during the event with Muse Code.

## Repo layout (initial)

| Path | Purpose |
|---|---|
| `SPEC.md` | Build specification: scope, safety boundary, architecture, interfaces, day plan |
| `digest.schema.json` | JSON Schema for the digest — the product contract for API, MCP, and UI |
| `scoring.yaml` | Deterministic scoring rules, weights, caps, and cost bands |
| `fixtures/outside_in/` | Synthetic passive-collector output for fictional `.example` targets |
| `fixtures/documents/` | Synthetic SOC 2 Type II report |
| `fixtures/interviews/` | Script for the synthetic management interview recording |
| `fixtures/expected/` | Expected findings and contradictions for the eval harness |

## Safety

PE Risk Key is passive by design: DNS, certificate transparency, a single
standard HTTPS GET, public records, and documents the user provides. No
scanning, probing, or authentication attempts. Up to two handshake-only TLS
probes per host (TLSv1.0, TLSv1.1) detect deprecated protocol support; no
application data is sent. All demo targets are fictional companies on the
reserved `.example` TLD. See `SPEC.md` §2.

### How safety is enforced

- `src/pe_risk_key/collectors/net.py` is the only module that may make
  target HTTP/TLS requests; a static test fails if any other collector
  file imports socket, requests, httpx, or urllib.
- `safe_get` enforces GET-only requests to allowlisted hosts, never
  follows redirects, and caps requests per host per run.
- `search_public_incidents` keeps only cited results and drops
  denylisted sources (`PROHIBITED_SOURCE_PATTERNS` in
  `collectors/incidents.py`): no paste-site, breach-dump, or
  credential-lookup content ever enters a digest.

## Status

Working today (Oct 28): Meta Model API provider with role routing and
retries; six passive collectors (email auth, DNSSEC, CT, web posture,
KEV, public incidents); Wonder orchestrator agent with parallel tool
calls, coverage check, and JSONL trace; deterministic rule engine,
scoring, and schema-validated digest assembly. Next: SOC 2 analyzer,
interview pipeline, cross-check, narrative, dashboard, API.

Demo (collectors from fixtures, model calls live; needs `MODEL_API_KEY`
in `.env`):

```sh
.venv/bin/python scripts/run_digest.py --demo \
  --domain brightwaterfleet.example \
  --company "Brightwater Fleet Systems, Inc." \
  --employee-band 201-1000 --revenue-band 50M-250M
```

## Known limitations

- KEV matches are product-level (no version-range check);
- public-incident search results vary run to run, and the parent/brand
  entity must be supplied via aliases;
- TLS 1.2 support isn’t probed;
- CT log presence doesn’t confirm live hosts;
- cost bands are triage estimates;
- DMARC/SPF/DNSSEC reflect the moment of collection.
