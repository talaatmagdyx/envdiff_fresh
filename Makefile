.PHONY: venv install install-dev test lint fmt check clean help pre-commit-install
PY?=python3
VENV?=.venv

help: ## Show this help message
	@echo "Available targets:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}'

venv: ## Create virtual environment
	$(PY) -m venv $(VENV)
	. $(VENV)/bin/activate; pip install -U pip setuptools wheel

install: venv ## Install runtime dependencies
	. $(VENV)/bin/activate; pip install -e .

install-dev: venv ## Install development dependencies
	. $(VENV)/bin/activate; pip install -e ".[dev]"

test: ## Run tests with coverage
	pytest

test-verbose: ## Run tests with verbose output
	pytest -v

lint: ## Run ruff linter
	ruff check .

fmt: ## Format code with ruff
	ruff format .

fmt-check: ## Check code formatting without making changes
	ruff format --check .

check: lint fmt-check test ## Run all checks (lint, format check, tests)

clean: ## Clean up generated files
	rm -rf .venv
	rm -rf __pycache__ */__pycache__ */*/__pycache__
	rm -rf *.egg-info
	rm -rf .pytest_cache
	rm -rf .coverage htmlcov
	find . -type d -name __pycache__ -exec rm -r {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete
	find . -type f -name "*.pyo" -delete

pre-commit-install: ## Install pre-commit hooks
	pip install pre-commit
	pre-commit install
