# Third-party licenses

Direct dependencies of PE Risk Key (from `pyproject.toml`), with
licenses taken from installed package metadata on 2026-11-03.
Versions are the installed ones; constraints live in `pyproject.toml`.

| Package | Version | License |
|---|---|---|
| dnspython | 2.9.0 | ISC |
| fastapi | 0.162.0 | MIT |
| httpx | 0.28.1 | BSD-3-Clause |
| jsonschema | 4.26.0 | MIT |
| mcp | 2.3.0 | MIT |
| openai | 3.40.0 | Apache-2.0 |
| pydantic | 2.14.1 | MIT |
| pypdf | 6.21.4 | BSD-3-Clause |
| pytest | 9.2.0 | MIT |
| python-dotenv | 1.2.4 | BSD-3-Clause |
| python-multipart | 0.0.33 | Apache-2.0 |
| pyyaml | 6.0.3 | MIT |
| uvicorn | 0.54.0 | BSD-3-Clause |

## AGPL-3.0 compatibility

No incompatible licenses found. MIT, ISC, BSD-3-Clause, and Apache-2.0
are all permissive licenses compatible with AGPL-3.0-or-later.

## Data notes

- The CISA KEV snapshot (`data/kev_snapshot.json`, fetched by
  `scripts/update_kev.py`) is US government public data, not subject to
  copyright.
- All fixtures under `fixtures/` (collector output, documents,
  interviews, expected results) are synthetic data created for this
  project; no third-party content is redistributed.
