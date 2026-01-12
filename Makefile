.PHONY: help install install-dev sync clean test lint format typecheck check build

help: ## Show this help message
	@echo "Available targets:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}'

install: ## Install the package in production mode
	uv pip install -e .

install-dev: ## Install the package with dev dependencies
	uv pip install -e ".[dev]"
	uv pip install pre-commit
	pre-commit install
	$(MAKE) download-spacy-model

sync: ## Sync dependencies from pyproject.toml
	uv sync --all-extras

clean: ## Remove build artifacts and cache files
	rm -rf build/
	rm -rf dist/
	rm -rf *.egg-info
	find . -type d -name __pycache__ -exec rm -r {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete
	find . -type d -name "*.egg-info" -exec rm -r {} + 2>/dev/null || true
	find . -type d -name ".pytest_cache" -exec rm -r {} + 2>/dev/null || true
	find . -type d -name ".mypy_cache" -exec rm -r {} + 2>/dev/null || true
	find . -type d -name ".ruff_cache" -exec rm -r {} + 2>/dev/null || true

test: ## Run tests
	uv run pytest

test-verbose: ## Run tests with verbose output
	uv run pytest -v

test-coverage: ## Run tests with coverage report
	uv run pytest --cov=ceil_dlp --cov-report=term-missing

lint: ## Run linters (ruff and mypy)
	uv run ruff check .
	uv run mypy .

format: ## Format code with ruff and black
	uv run ruff format .
	uv run black .

format-check: ## Check if code is formatted correctly
	uv run ruff format --check .
	uv run black --check .

typecheck: ## Run type checker
	uv run mypy .

check: ## Run all checks (lint, typecheck, format-check, test)
	$(MAKE) format-check
	$(MAKE) lint
	$(MAKE) test

build: ## Build the package
	uv build

pre-commit: ## Run pre-commit hooks on all files
	uv run pre-commit run --all-files

download-spacy-model: ## Download spaCy model required by Presidio
	@echo "Installing spaCy model en_core_web_sm..."
	uv pip install https://github.com/explosion/spacy-models/releases/download/en_core_web_sm-3.8.0/en_core_web_sm-3.8.0-py3-none-any.whl || \
	echo "Failed to install model. Please check available versions at https://github.com/explosion/spacy-models/releases"