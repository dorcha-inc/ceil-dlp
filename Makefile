.PHONY: help install install-dev sync clean test lint format typecheck check build

help: ## Show this help message
	@echo "Available targets:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}'

install: sync ## Install the package in production mode
	uv pip install -e .
	
install-dev: sync ## Install the package with dev dependencies
	uv pip install -e .[dev]
	pre-commit install || true

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

format: ## Format code with ruff
	uv run ruff format .

format-check: ## Check if code is formatted correctly
	uv run ruff format --check .

typecheck: ## Run type checker
	uv run mypy .

check: ## Run all code quality checks (lint, typecheck, format-check)
	$(MAKE) format-check
	$(MAKE) lint

build: ## Build the package
	uv build

pre-commit: ## Run pre-commit hooks on all files
	uv run pre-commit run --all-files

examples: install ## Run examples and generate redacted files
	./examples/images/run.sh
	./examples/pdf/run.sh

example-gifs: ## Generate gifs from example images
	@for image in aws_console dl_real_id research_paper; do \
		echo "Creating fade GIF for $$image..."; \
		uv run python scripts/create_fade_gif.py \
			examples/images/$$image.png \
			examples/images/$$image.redacted.png \
			-o share/$${image}_fade.gif; \
	done