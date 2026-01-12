<div align="center">
  <h1>ceil-dlp</h1>
  <p>DLP plugin for LiteLLM for seamlessly managing PII in LLM interactions.</p>
</div>

<p align="center">
  <a href="https://www.python.org/"><img src="https://img.shields.io/badge/Python-3.11+-3776AB?style=flat&logo=python&logoColor=white" alt="Python Version"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-green.svg" alt="License"></a>
  <a href="https://pypi.org/project/ceil-dlp/"><img src="https://img.shields.io/pypi/v/ceil-dlp?color=blue" alt="PyPI Version"></a>
  <a href="https://github.com/dorcha-inc/ceil-dlp/actions/workflows/build.yml"><img src="https://github.com/dorcha-inc/ceil-dlp/actions/workflows/build.yml/badge.svg" alt="Build"></a>
  <a href="https://codecov.io/gh/dorcha-inc/ceil-dlp"><img src="https://codecov.io/gh/dorcha-inc/ceil-dlp/branch/main/graph/badge.svg" alt="Coverage"></a>
</p>

`ceil-dlp` is a Data Loss Prevention (DLP) plugin for [LiteLLM](https://github.com/BerriAI/litellm) that automatically detects and protects Personally Identifiable Information (PII) in LLM requests. This includes PII in both text and images (pdf support is on the way). It blocks, masks, or logs sensitive data before it reaches your LLM provider. This helps prevent you from leaking your secrets, API keys, and other sensitive information. It also helps you ensure compliance with data privacy regulations like HIPAA, PCI-DSS, GDPR, and CCPA.

## Usage

See [QUICKSTART.md](QUICKSTART.md) for detailed installation and usage instructions.

The setup is as simple as installing:

```bash
uv pip install ceil-dlp
```

and enabling in LiteLLM:

```python
from litellm import proxy
from ceil_dlp import setup_litellm

litellm_config = setup_litellm()
proxy(host="0.0.0.0", port=4000, **litellm_config)
```

And you're done!

## Documentation

- See the [Quick Start Guide](QUICKSTART.md) for installation and basic usage
- Take a look at the [example configuration file](config.example.yaml)

## Developing

Contributions are always welcome!

### Releasing a New Version

To release a new version of `ceil-dlp`:

1. Update the version in `pyproject.toml`:
   ```toml
   version = "1.2.0"
   ```

2. Commit the version change:
   ```bash
   git add pyproject.toml
   git commit -m "Bump version to 1.2.0"
   ```

3. Create and push a git tag:
   ```bash
   git tag -a v1.2.0 -m "Release v1.2.0"
   git push && git push --tags
   ```

4. The GitHub Actions workflow will automatically build the package and publish to PyPI when the tag is pushed

The publish workflow triggers on tags matching `v*` (e.g., `v1.2.0`). Make sure your changes are committed and pushed before creating the tag.