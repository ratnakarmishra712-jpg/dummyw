# ReconToReport — one-command workflows.
# Everything runs inside a local .venv; no manual `source activate` needed.
#
# Quick start:
#   make setup      # create venv + install the package
#   make config     # create config.yaml from the example (edit it after)
#   make db         # create/upgrade the database schema
#   make scan       # run Phase 1 WITH authorization (active scan)
#   make report     # render HTML/XML report from the store
#
# Common:
#   make run        # dry run (no authorization — active phases are SKIPPED)
#   make test       # run the unit tests
#   make check-tools# report which external CLI tools are installed
#   make query Q="SELECT title,severity FROM findings"
#   make clean      # remove venv, db, reports, caches

PY        ?= python3
VENV      ?= .venv
BIN        = $(VENV)/bin
CONFIG    ?= config.yaml
PHASES    ?= 1

.DEFAULT_GOAL := help
.PHONY: help setup dev config db initdb run scan report test check-tools query clean

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
	 | awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'

setup: $(VENV)/.installed ## Create venv and install the package
$(VENV)/.installed: pyproject.toml
	$(PY) -m venv $(VENV)
	$(BIN)/pip install -q --upgrade pip
	$(BIN)/pip install -q -e ".[dev]"
	@touch $@
	@echo "✓ installed into $(VENV)"

dev: setup ## Install optional phase extras (mitmproxy, playwright, jwt)
	$(BIN)/pip install -q -e ".[proxy,browser,scan]"
	@echo "✓ phase extras installed"

config: ## Create config.yaml from the example (won't overwrite)
	@if [ -f $(CONFIG) ]; then \
	  echo "✓ $(CONFIG) already exists (not overwriting)"; \
	else \
	  cp config.example.yaml $(CONFIG); \
	  echo "✓ created $(CONFIG) — now edit target.url, scope, and wordlists.content_discovery"; \
	fi

db: setup ## Create/upgrade the DB schema via Alembic
	RECONTOREPORT_CONFIG=$(CONFIG) $(BIN)/alembic upgrade head
	@echo "✓ schema up to date"

initdb: setup ## Create tables directly (quick start, no Alembic history)
	$(BIN)/r2r initdb --config $(CONFIG)

run: setup ## Dry run — active phases SKIPPED (no authorization)
	$(BIN)/r2r run --config $(CONFIG) --phases $(PHASES)

scan: setup ## Authorized run — active phases EXECUTE (needs permission!)
	$(BIN)/r2r run --config $(CONFIG) --phases $(PHASES) --i-have-authorization

report: setup ## Render a report from the existing store (no scanning)
	$(BIN)/r2r report --config $(CONFIG)

test: setup ## Run the unit test suite
	$(BIN)/python -m pytest -q

check-tools: ## Report which external CLI tools are installed
	@for t in subfinder amass ffuf katana nuclei mitmdump sqlmap; do \
	  if command -v $$t >/dev/null 2>&1; then \
	    printf "  \033[32m✓\033[0m %-10s %s\n" $$t "$$(command -v $$t)"; \
	  else \
	    printf "  \033[31m✗\033[0m %-10s (not installed)\n" $$t; \
	  fi; \
	done

query: setup ## Run a SQL query against the store:  make query Q="SELECT ..."
	@if [ -z "$(Q)" ]; then echo 'Usage: make query Q="SELECT title,severity FROM findings"'; exit 2; fi
	@$(BIN)/python scripts/query.py --config $(CONFIG) "$(Q)"

clean: ## Remove venv, database, reports, and caches
	rm -rf $(VENV) reports .pytest_cache .alembic_tmp.db
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
	@echo "✓ cleaned (config.yaml and *.db left in place — delete manually if desired)"
