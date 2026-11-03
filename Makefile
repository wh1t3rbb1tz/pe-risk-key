# PE Risk Key
.PHONY: eval test

# Usage:
#   make eval            -> cost estimate only (refuses to run)
#   make eval ARGS=--yes -> run the full harness (live model calls)
eval:
	.venv/bin/python scripts/eval.py $(ARGS)

test:
	.venv/bin/python -m pytest -q
