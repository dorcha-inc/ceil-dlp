# Contributing to ceil-dlp

Thank you so much for considering contributing to ceil-dlp! ceil-dlp is designed to be a community-focused project and runs on individual contributions from amazing people around the world. This document provides guidelines and instructions for contributing to the project.

## Code of Conduct

This project adheres to a Code of Conduct that all contributors are expected to follow. Please read [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) before contributing.

## Getting Started

1. Fork the repository on GitHub
2. Clone your fork locally:

   ```bash
   git clone https://github.com/YOUR_USERNAME/ceil-dlp.git
   cd ceil-dlp
   ```

3. Add the upstream remote:

   ```bash
   git remote add upstream https://github.com/dorcha-inc/ceil-dlp.git
   ```

## Development Setup

### Prerequisites

ceil-dlp requires Python 3.11+. We recommend using [uv](https://docs.astral.sh/uv/) for dependency management, but regular `pip` also works.

Check your Python version:

```bash
python3 --version
```

### Setup Steps

First install dependencies by running:

```bash
make install-dev
```

This will:
- Install all dependencies including dev dependencies
- Set up pre-commit hooks
- Download the required spaCy model for Presidio

Then you can verify the setup using:

```bash
make lint
```

and

```bash
make test
```

Try building the package using:

```bash
make build
```

### Git Hooks (Optional but Recommended)

ceil-dlp includes pre-commit hooks that run formatting, linting, and type checking before each commit. These are automatically installed when you run

```bash
make install-dev
```

The pre-commit hooks will:
- Format code with `ruff` and `black`
- Run linting (`ruff check`)
- Run type checking (`mypy`)
- Run tests (`make test`)

To skip hooks for a commit, use `git commit --no-verify`.

## Making Changes

### Workflow

1. Create a branch from `main`:

```bash
git checkout -b <your_github_username>/<descriptive_name>
```

2. Write or update tests for your changes

3. Run tests and linter:

   ```bash
   make test
   make lint
   ```

4. Commit your changes with clear, descriptive commit messages:

   ```bash
   git commit -m "<message>"
   ```

### Commit Message Guidelines

We follow [Conventional Commit](https://www.conventionalcommits.org/en/v1.0.0/) message style:

- `feat: add image redaction support`
- `fix: resolve email detection edge case`
- `docs: update README with installation instructions`
- `test: add tests for image PII detection`
- `refactor: simplify config loading logic`

## Submitting Changes

### Pull Request Process

1. Push your branch to your fork:
   ```bash
   git push origin feature/your-feature-name
   ```

2. Create a pull request on GitHub.

3. Please ensure CI checks pass before asking for a review.

4. Please address reviewer feedback

### Pull Request Checklist

Before submitting, make sure:

- [ ] You've added tests for new functionality
- [ ] All tests pass (`make test`)
- [ ] Linting passes (`make lint`)
- [ ] Code is formatted (`make format`)
- [ ] Type checking passes (`make typecheck`)
- [ ] Documentation is updated if needed
- [ ] Commit messages are clear and descriptive

## Testing

Run all tests using:

```bash
make test
```

Run tests with verbose output using:

```bash
make test-verbose
```

Run tests with coverage report:

```bash
make test-coverage
```

## Areas for Contribution

We welcome contributions in many areas including bug fixes, features, documentation,
tests, tooling, code quality, security patches, and performance optimizations.

## Recognition

Contributors will be recognized in:

1. GitHub contributors list
2. [CONTRIBUTORS.md](CONTRIBUTORS.md)
3. Release notes

Thank you for contributing to ceil-dlp!
