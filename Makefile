.PHONY: help install install-dev sync clean test lint format typecheck check build bump bump-patch bump-minor bump-major

help: ## Show this help message
	@echo "Available targets:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}'

install: ## Install the package in production mode
	uv sync

install-dev: ## Install the package with dev dependencies
	uv sync --all-extras
	uv pip install pre-commit
	pre-commit install || true
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

bump: ## Bump version and create git tag (use: make bump VERSION=1.0.2 or make bump-patch/minor/major)
	@if [ -z "$(VERSION)" ]; then \
		echo "Error: VERSION not set. Use 'make bump VERSION=x.y.z' or 'make bump-patch/minor/major'"; \
		exit 1; \
	fi
	@echo "Bumping version to $(VERSION)..."
	@sed -i.bak "s/^version = \".*\"/version = \"$(VERSION)\"/" pyproject.toml && rm pyproject.toml.bak
	@echo "Updated pyproject.toml to version $(VERSION)"
	@git add pyproject.toml
	@git commit -m "Bump version to $(VERSION)" || true
	@git tag -a "v$(VERSION)" -m "Release v$(VERSION)"
	@echo "Created git tag v$(VERSION)"
	@echo "Run 'git push && git push --tags' to publish"

bump-patch: ## Bump patch version (1.0.1 -> 1.0.2)
	@current=$$(grep '^version = ' pyproject.toml | sed 's/version = "\(.*\)"/\1/'); \
	major=$$(echo $$current | cut -d. -f1); \
	minor=$$(echo $$current | cut -d. -f2); \
	patch=$$(echo $$current | cut -d. -f3); \
	new_patch=$$((patch + 1)); \
	new_version="$$major.$$minor.$$new_patch"; \
	$(MAKE) bump VERSION=$$new_version

bump-minor: ## Bump minor version (1.0.1 -> 1.1.0)
	@current=$$(grep '^version = ' pyproject.toml | sed 's/version = "\(.*\)"/\1/'); \
	major=$$(echo $$current | cut -d. -f1); \
	minor=$$(echo $$current | cut -d. -f2); \
	new_minor=$$((minor + 1)); \
	new_version="$$major.$$new_minor.0"; \
	$(MAKE) bump VERSION=$$new_version

bump-major: ## Bump major version (1.0.1 -> 2.0.0)
	@current=$$(grep '^version = ' pyproject.toml | sed 's/version = "\(.*\)"/\1/'); \
	major=$$(echo $$current | cut -d. -f1); \
	new_major=$$((major + 1)); \
	new_version="$$new_major.0.0"; \
	$(MAKE) bump VERSION=$$new_version

pre-commit: ## Run pre-commit hooks on all files
	uv run pre-commit run --all-files

download-spacy-model: ## Download spaCy model required by Presidio
	@echo "Installing spaCy model en_core_web_sm..."
	uv pip install https://github.com/explosion/spacy-models/releases/download/en_core_web_sm-3.8.0/en_core_web_sm-3.8.0-py3-none-any.whl || \
	echo "Failed to install model. Please check available versions at https://github.com/explosion/spacy-models/releases"