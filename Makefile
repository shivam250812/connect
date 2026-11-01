# Common tasks. `make help` lists them.
PY ?= .venv/bin/python

.PHONY: help install run run-lab test lint format stress fuzz check clean

help:            ## list targets
	@grep -E '^[a-z-]+:.*##' $(MAKEFILE_LIST) | awk -F':.*## ' '{printf "  %-10s %s\n", $$1, $$2}'

install:         ## create .venv and install ConnectForge with dev tools
	@test -x $(PY) || (command -v uv >/dev/null && uv venv --python 3.12 .venv || python3 -m venv .venv)
	@command -v uv >/dev/null && uv pip install --python $(PY) -e ".[dev]" || $(PY) -m pip install -e ".[dev]"

run:             ## start the web UI + API on :8100
	./run.sh

run-lab:         ## start with the mock lab sources (failure drills)
	CF_LAB=1 ./run.sh

test:            ## run the test suite (no network)
	$(PY) -m pytest -q

lint:            ## static checks (style, bugs, security)
	$(PY) -m ruff check src tests scripts

format:          ## auto-fix what the linter can fix
	$(PY) -m ruff check src tests scripts --fix

stress:          ## AI-written config corpus (85 cases)
	$(PY) scripts/stress_ai_configs.py -q

fuzz:            ## 20,000 randomly damaged config files
	$(PY) scripts/fuzz_intake.py 20000

check: lint test stress   ## everything CI runs

clean:           ## remove caches (keeps data/ and .venv/)
	find . -name __pycache__ -not -path "./.venv/*" -prune -exec rm -rf {} +
	rm -rf .pytest_cache .ruff_cache build dist *.egg-info src/*.egg-info
