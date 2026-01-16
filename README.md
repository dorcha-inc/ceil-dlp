<!-- Logo attribution: Based on "Express Train" by Charles Parsons (Currier and Ives), 1859. 
     Original source: https://commons.wikimedia.org/wiki/File:Express_Train_MET_DT5428.jpg
     Public domain (CC0) - available for use without restrictions. -->

<div align="center">
  <img src="share/ceil-dlp-logo-no-bg.png" alt="ceil-dlp logo" width="400">
  
  <h1>ceil-dlp</h1>
  <p>DLP plugin for LiteLLM that seamlessly manages PII in LLM interactions.</p>
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

The setup is as simple as installing:

```bash
uv pip install ceil-dlp
```

and enabling in LiteLLM by adding to your `config.yaml`:

```yaml
litellm_settings:
  callbacks: ceil_dlp.ceil_dlp_callback.proxy_handler_instance
```

Then run: `litellm --config config.yaml --port 4000`

To customize behavior, create a `ceil-dlp.yaml` file and set the `CEIL_DLP_CONFIG_PATH` environment variable.

And you're done!

## Documentation

- See the [Quick Start Guide](docs/ollama_guide.md) for a comprehensive, step-by-step tutorial with Ollama
- Take a look at the [example configuration file](config.example.yaml) for all available options

## Contributing

Contributions are always welcome! We'd love to have you contribute to ceil-dlp.

- See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup and guidelines
- Read our [Code of Conduct](CODE_OF_CONDUCT.md) to understand our community standards
- Check out [SECURITY.md](SECURITY.md) for security reporting guidelines

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