# PE Risk Key — Build Specification

> PE-native IT & cybersecurity risk digest, built on Meta Muse models.
> Meta Global AI Developer Hackathon · Indie track · Theme: **Build for Your World**
> Building period: Oct 27 – Nov 4, 2026. Everything in this repo was built during that window.

Product name: **PE Risk Key**. Repo: https://github.com/wh1t3rbb1tz/pe-risk-key

---

## 1. Problem and outcome

PE deal teams quantify financial risk precisely, but IT/cyber risk arrives late, vague, and expensive (third-party diligence engagements, weeks of elapsed time). PE Risk Key produces a **triage-grade, evidence-cited cyber risk digest in minutes**, framed in deal language: rating, top risks, 100-day remediation cost, and deal-term recommendations.

**Positioning:** triage *before* you commission full diligence, not a replacement for it.

**Primary user:** PE deal associate / operating partner. **Secondary:** portfolio-company CISO preparing for diligence.

## 2. Safety boundary (the "safe" in point-and-shoot)

This boundary is a product feature and a hard engineering constraint. Collectors must be reviewable against it.

**Allowed (passive / provided):**
- Public DNS queries (MX, TXT, CAA, DNSKEY/DS, NS)
- Certificate Transparency log queries (crt.sh)
- One standard HTTPS GET to the apex and `www` (what any browser does), reading headers, TLS handshake metadata, and page markup for technology fingerprints
- Up to two handshake-only TLS probes per host (TLSv1.0, TLSv1.1) to detect deprecated protocol support; no application data is sent.
- Public records and news via Muse search grounding (SEC filings, breach notices, press)
- Documents the user uploads (SOC 2, pen-test summary, questionnaire, insurance application)
- Interview recordings the user uploads and has the right to process

**Prohibited (never implement):**
- Port scanning, service enumeration, banner grabbing beyond the single GET above
- Directory brute forcing, crawling beyond apex/www, subdomain brute forcing
- Any authentication attempt, credential testing, or vulnerability probing/exploitation
- Accepting NDAs or click-through terms on a target's trust center
- Querying breach/credential-dump data sources

Every finding records `collection_method` so a reviewer can verify it stayed inside the boundary.

**Demo targets:** fictional companies on the reserved `.example` TLD, served from fixtures. No real third party's weaknesses appear in the demo or repo.

## 3. Architecture

```
            ┌───────────── Inputs ─────────────┐
            │ domain │ documents │ interview audio│
            └────┬────────┬───────────┬─────────┘
                 │        │           │
                 ▼        ▼           ▼
         ┌──────────────────────────────────────┐
         │  Orchestrator agent (Muse Wonder)    │
         │  plans → parallel tool calls →       │
         │  structured findings (schema-valid)  │
         └──┬─────────┬──────────┬──────────┬───┘
            │         │          │          │
   ┌────────▼──┐ ┌────▼─────┐ ┌──▼───────┐ ┌▼──────────────┐
   │ Passive   │ │ Document │ │Interview │ │ Search         │
   │ collectors│ │ analyzer │ │ pipeline │ │ grounding      │
   │ (Python)  │ │ (Wonder /│ │(Voice    │ │ (web_search)   │
   │           │ │ open-wt) │ │Transcribe│ │                │
   └────────┬──┘ └────┬─────┘ │+ Wonder) │ └┬──────────────┘
            │         │       └──┬───────┘  │
            ▼         ▼          ▼          ▼
         ┌──────────────────────────────────────┐
         │ Cross-check engine (claims vs evidence)│
         └──────────────────┬───────────────────┘
                            ▼
         ┌──────────────────────────────────────┐
         │ Deterministic scoring (scoring.yaml) │  ← no LLM
         └──────────────────┬───────────────────┘
                            ▼
         ┌──────────────────────────────────────┐
         │ Narrative + deal recs (Muse Wonder)  │  ← cites finding IDs only
         └──────────────────┬───────────────────┘
                            ▼
                 digest.json (digest.schema.json)
                 ┌──────────┼───────────┐
              REST API    MCP server   Dashboard
```

### LLM vs deterministic boundary

| Step | Owner | Why |
|---|---|---|
| Collecting raw signals | Python collectors | Reproducible, auditable, inside safety boundary |
| Interpreting signals into findings | Muse Wonder (structured output) | Judgment, framework mapping |
| Extracting SOC 2 exceptions/CUECs/carve-outs | Muse Wonder or open-weight (confidential mode) | Long-context reading |
| Transcription + diarization | Muse Voice Transcribe | Native capability |
| Claim extraction from transcript | Muse Wonder | Judgment |
| Claim-vs-evidence verdicts | Muse Wonder, constrained to cited evidence IDs | Judgment, but grounded |
| Scores, ratings, deal signal, cost totals | **Python + scoring.yaml** | Reproducible; same inputs → same score |
| Narrative, deal recommendations | Muse Wonder | Must reference finding IDs; validator rejects uncited claims |

### Model routing and providers

One provider interface, OpenAI-compatible, selected by config:

| Mode | Provider | Base URL | Model |
|---|---|---|---|
| Standard | Meta Model API | `https://api.meta.ai/v1` | `muse-wonder-1.0` (agent, analysis), `muse-spark-1.3` (cheap sub-tasks) |
| Transcription | Meta Model API | `POST /v1/asr/transcribe` | `muse-voice-transcribe-1.0` |
| Confidential | Baseten (or Modal / Fireworks) | per partner | `meta-models/muse-spark-open-1026` |

In confidential mode, uploaded documents and transcripts are processed only by the open-weight deployment. The UI shows which provider handled each artifact. Never use `-contributor` model variants on target documents.

## 4. Components

### 4.1 Passive collectors (`collectors/`)

Each collector is a pure function `collect(domain) -> dict` returning exactly its section of `fixtures/outside_in/<domain>.json`, including `collection_method`. Every signal carries an exact locator (`queried_name` + `record_type`, query URL, hostname) so downstream evidence can cite it verbatim. Each collector has a fixture-backed test. Agent-facing tool definitions are generated from these.

| Tool name | Signals | Collection method |
|---|---|---|
| `check_email_auth` | SPF record and qualifier, DMARC policy/pct/rua, DKIM selectors found (common selectors only) | `dns_query` |
| `check_dnssec` | DS/DNSKEY presence | `dns_query` |
| `enumerate_ct_subdomains` | Unique hostnames from CT logs, flagged by risky name patterns (vpn, jenkins, staging, dev, admin, legacy, old) | `ct_log_query` |
| `check_web_posture` | TLS versions offered by apex/www, cert expiry/issuer, HSTS, CSP, X-Frame-Options, server/tech fingerprints | `single_https_get` |
| `match_known_exploited` | Fingerprinted product/version → CISA KEV matches (local KEV JSON snapshot) | `offline_lookup` |
| `search_public_incidents` | 8-K Item 1.05 filings, state AG breach notices, press reports | `search_grounding` |

Fingerprint-based KEV matches are always `confidence: medium` at most and phrased as "potential exposure."

### 4.2 Document analyzer (`analyzers/soc2.py`)

Input: SOC 2 Type II report (PDF or text). Output: `soc2_analysis` block plus findings.

Extract:
- Report type, period, auditor, opinion (unqualified / qualified / adverse / disclaimer)
- Every testing exception: control ID, description, auditor test, sample size, deviations, management response
- Subservice organizations and method (carve-out vs inclusive)
- CUECs (complementary user entity controls)
- Bridge-letter gap: days between period end and today

Prompting rule: the model must quote the locator (section/page/control ID) for every extracted item. A validator rejects items without a locator.

### 4.3 Interview pipeline (`analyzers/interview.py`)

1. Transcribe with `muse-voice-transcribe-1.0`, speaker diarization on.
2. Muse Wonder extracts **security claims**: speaker, timestamp, verbatim claim, claim type (control exists / control coverage / incident history / third-party assurance).
3. Each claim is passed with the candidate evidence set (findings + SOC 2 items + raw signals) to the cross-check step.

### 4.4 Cross-check engine (`engine/crosscheck.py`)

For each claim, Muse Wonder returns exactly one verdict:
- `contradicted` — evidence conflicts with the claim
- `unsupported` — no evidence either way, and the claim matters
- `supported` — evidence corroborates

Constraints: the verdict must cite `evidence_refs` that exist in the digest. A validator drops verdicts that cite unknown IDs. Supported verdicts are kept and shown; showing balance is part of credibility.

### 4.5 Scoring (`engine/scoring.py`)

Pure Python driven entirely by `scoring.yaml`. No model calls. Unit tested with fixed inputs → fixed outputs. See `scoring.yaml` for rules.

### 4.6 Narrative and deal recommendations

Muse Wonder writes the executive summary and deal recommendations from the scored digest. Every sentence that asserts a risk must reference at least one `finding_id` or `contradiction_id`. A validator flags unreferenced risk claims and triggers one regeneration.

## 5. Interfaces

### REST API (FastAPI)

| Method | Path | Purpose |
|---|---|---|
| POST | `/v1/digests` | Start a digest: `{domain, mode, document_ids[], interview_ids[]}` → `{digest_id}` |
| GET | `/v1/digests/{id}` | Full digest JSON |
| GET | `/v1/digests/{id}/trace` | Agent trace events (for the live trace panel) |
| POST | `/v1/uploads` | Upload document or audio → `{upload_id, sha256}` |
| GET | `/v1/compare?ids=a,b` | Side-by-side summary of two digests |

### MCP server

| Tool | Input | Output |
|---|---|---|
| `get_risk_digest` | `domain` or `digest_id` | Overall rating, top risks, deal signal, cost range |
| `explain_finding` | `digest_id`, `finding_id` | Finding with evidence and remediation |
| `compare_targets` | `digest_ids[]` (2–3) | Comparison table, recommendation on relative risk |

### Dashboard

Single page:
1. Header: target, rating badge, deal signal, confidence, provider/mode badge
2. **Live agent trace panel** (tool calls streaming in, in parallel)
3. Top risks with severity and cost range
4. **Contradictions panel** (claim → verdict → evidence)
5. SOC 2 panel (opinion, exceptions, carve-outs, bridge gap)
6. 100-day plan and deal recommendations
7. "Export IC memo" (Markdown/PDF)

## 6. Demo mode

`DEMO_MODE=1` makes collectors read from `fixtures/outside_in/*.json` instead of the network. Model calls stay live; only raw signal collection is fixture-backed. This keeps the demo deterministic and keeps real companies out of it, while the Muse reasoning is genuinely running.

## 7. Evaluation harness (`eval/`)

- `fixtures/expected/*.yaml` lists findings and contradictions that must appear for each fixture target.
- `make eval` runs the full pipeline against fixtures and reports recall on expected findings, precision on contradictions, schema-validation pass rate, and scoring determinism (same run twice → identical score).
- Include the eval output table in the README. Judges score craft; this is the evidence.

## 8. Day plan

| Day | Deliverable | Done when |
|---|---|---|
| Oct 27 | Repo, these specs, provider interface, Muse Wonder structured-output smoke test, schema validator | A Wonder call returns schema-valid JSON |
| Oct 28 | Collectors + fixtures + tests; attend Agents 102 | `pytest collectors/` green |
| Oct 29 | Orchestrator agent with parallel tool calls; scoring engine | Fixture domain → scored findings |
| Oct 30 | SOC 2 analyzer | Expected exceptions extracted from fixture |
| Oct 31 | Interview pipeline + cross-check | Expected contradictions produced |
| Nov 1 | Dashboard + trace panel; REST API | End-to-end in browser |
| Nov 2 | MCP server; confidential mode on partner inference | Mode toggle works end to end |
| Nov 3 | Eval harness, README, architecture diagram, demo video | Video recorded |
| Nov 4 | Buffer; submit by noon PT; X post | Submitted |

Cut order if behind: confidential mode → compare_targets → PDF export.

## 9. Acceptance criteria

- [ ] Every digest validates against `digest.schema.json`
- [ ] Scoring is deterministic (two runs, identical scores)
- [ ] Every finding has ≥1 evidence item with a locator and `collection_method`
- [ ] No collector performs an action outside §2
- [ ] Eval recall ≥ 90% on expected findings for fixture targets
- [ ] Demo runs end to end in under 2 minutes on the fixture target
- [ ] README states clearly what was built during Oct 27 – Nov 4
