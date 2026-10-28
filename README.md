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

## Status

Day 1 — specs and fixtures. Code to follow.
