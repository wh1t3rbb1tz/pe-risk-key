# PE Risk Key
.PHONY: setup test demo serve eval fresh-demo mcp readme

setup:
	uv sync

test:
	.venv/bin/python -m pytest -q

# Full Brightwater demo run: demo collectors, live models, SOC 2 + interview.
demo:
	.venv/bin/python scripts/run_digest.py \
		--domain brightwaterfleet.example \
		--company "Brightwater Fleet Systems, Inc." \
		--employee-band 201-1000 \
		--revenue-band 50M-250M \
		--demo \
		--soc2 fixtures/documents/brightwater_soc2_type2.md \
		--as-of 2026-10-30 \
		--interview fixtures/interviews/brightwater_cto_interview.wav \
		--speakers "Diligence Lead,Dana Reyes (CTO)" \
		--target "Dana Reyes (CTO)"

serve:
	.venv/bin/python scripts/serve.py

# Usage:
#   make eval            -> cost estimate only (refuses to run)
#   make eval ARGS=--yes -> run the full harness (live model calls)
eval:
	.venv/bin/python scripts/eval.py $(ARGS)

# Clear model-backed caches, then serve (collectors stay fixture-free).
fresh-demo:
	rm -rf .cache/transcripts .cache/public_incidents
	.venv/bin/python scripts/serve.py

mcp:
	.venv/bin/python -m pe_risk_key.mcp_server

readme:
	.venv/bin/python scripts/update_readme_results.py
