# AegisAI developer tasks.
#
# Requires GNU make. On Windows use `make` from Git for Windows / MSYS2, or run the
# equivalent commands listed in docs/architecture.md (section "Developer workflow").
# PYTHON can be overridden, e.g. `make test PYTHON=.venv/bin/python`.

PYTHON ?= python
PIP    ?= $(PYTHON) -m pip
SCANNER_DIR = packages/scanner
EXT_DIR     = apps/vscode-extension

.PHONY: help install install-ext test test-ext lint typecheck format scan package clean rules-doc

help:
	@echo "install    - install the scanner (editable) with dev dependencies"
	@echo "install-ext- install VS Code extension dependencies"
	@echo "test       - run the Python test suite"
	@echo "test-ext   - compile and test the VS Code extension"
	@echo "lint       - ruff lint + format check"
	@echo "typecheck  - mypy (strict)"
	@echo "format     - apply ruff formatting"
	@echo "scan       - self-scan this repository with built-in rules"
	@echo "package    - build the wheel/sdist and the VSIX"
	@echo "rules-doc  - regenerate docs/supported-rules.md and docs/schema"

install:
	$(PIP) install -e "$(SCANNER_DIR)[dev]"

install-ext:
	cd $(EXT_DIR) && npm ci

test:
	cd $(SCANNER_DIR) && $(PYTHON) -m pytest -q

test-ext:
	cd $(EXT_DIR) && npm run compile && npm test

lint:
	cd $(SCANNER_DIR) && $(PYTHON) -m ruff check src tests && $(PYTHON) -m ruff format --check src tests

typecheck:
	cd $(SCANNER_DIR) && $(PYTHON) -m mypy

format:
	cd $(SCANNER_DIR) && $(PYTHON) -m ruff check src tests --fix && $(PYTHON) -m ruff format src tests

scan:
	$(PYTHON) -m aegisai.cli scan . --profile all --format terminal --format json --output .aegisai-reports/report.json --fail-on none

package:
	cd $(SCANNER_DIR) && $(PYTHON) -m build
	cd $(EXT_DIR) && npm run package

rules-doc:
	$(PYTHON) scripts/generate_rule_docs.py
	$(PYTHON) -m aegisai.cli schema --output-dir docs/schema

clean:
	rm -rf $(SCANNER_DIR)/dist $(SCANNER_DIR)/build $(SCANNER_DIR)/.mypy_cache $(SCANNER_DIR)/.pytest_cache $(SCANNER_DIR)/.ruff_cache $(EXT_DIR)/out .aegisai-reports
