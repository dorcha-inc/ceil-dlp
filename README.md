<!-- Logo attribution: Based on "Express Train" by Charles Parsons (Currier and Ives), 1859. 
     Original source: https://commons.wikimedia.org/wiki/File:Express_Train_MET_DT5428.jpg
     Public domain (CC0) - available for use without restrictions. -->

<div align="center">
  <img src="https://raw.githubusercontent.com/dorcha-inc/ceil-dlp/main/share/ceil-dlp-logo-no-bg-logo.png" alt="ceil-dlp logo" width="400">
  
  <p>Open-Source DLP for LLMs and Agentic Workflows</p>
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

Install ceil-dlp:

```bash
uv pip install ceil-dlp
```

Then use the CLI to automatically configure LiteLLM:

```bash
ceil-dlp install path/to/config.yaml
```

This command will:
1. Create a local `ceil_dlp_callback.py` wrapper in the same directory as your LiteLLM config
2. Create a starter `ceil-dlp.yaml` configuration file
3. Automatically update your LiteLLM `config.yaml` to include the callback

Then run: `litellm --config config.yaml --port 4000`

To customize behavior, edit the generated `ceil-dlp.yaml` file in the same directory as your config.

To remove ceil-dlp from your configuration:

```bash
ceil-dlp remove path/to/config.yaml
```

This will remove the callback from your LiteLLM config. You can also use `--remove-callback-file` and `--remove-config-file` flags to remove the generated files.

## Documentation

- See the [Quick Start Guide](docs/ollama_guide.md) for a comprehensive, step-by-step tutorial with Ollama
- Take a look at the [example configuration file](config.example.yaml) for all available options

## About

`ceil-dlp` is an open-source solution that handles both PII + PHI (via Presidio) and secrets (API keys, tokens, credentials, etc.) in one integrated solution, eliminating the need to configure and maintain separate guardrails. `ceil-dlp` supports model-specific policies using pattern-based rules within a single policy definition, allowing you to configure different rules for different models directly in your configuration file. For example, you can block API keys or PII for an external model provider such as Anthropic or OpenAI while allowing them for locally hosted models. This can be done using simple regex patterns in your config, all without requiring separate guardrail definitions or per-request configuration.

`ceil-dlp` also provides comprehensive image support, detecting both PII and secrets in images through OCR, not just in text content. It applies automatically to all requests via LiteLLM's callback system, so you don't need to specify a `guardrails` parameter on every request. Finally, it supports both blocking and masking actions for all detection types, giving you full control over how sensitive data is handled.

### Existing LiteLLM Guardrails

LiteLLM offers built-in [guardrails](https://docs.litellm.ai/docs/proxy/guardrails/quick_start) for many tasks involving LLM interaction security. However, we unable to find a solution that helps with all the features a person or team working with sensitive data in a real-world LLM interaction would require.

To be more specific, LiteLLM provides two separate guardrails for data protection, each with significant limitations. LiteLLM's [Presidio guardrail](https://docs.litellm.ai/docs/proxy/guardrails/pii_masking_v2) handles PII and PHI masking using Microsoft Presidio, but it does not handle secrets (API keys, tokens, credentials, etc.). Additionally, it only supports LiteLLM-wide configuration and cannot apply different policies to different models. It also seems to lack support for detecting PII in images, only working with text content. LiteLLM's [Secret Detection guardrail](https://docs.litellm.ai/docs/proxy/guardrails/secret_detection) is an Enterprise-only feature that requires a paid license. While it can detect secrets and can be configured per model (by defining separate guardrail configurations), it only performs redaction and cannot block requests containing secrets. It also only works on text content and does not detect or redact secrets in images.


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