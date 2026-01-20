<!-- Logo attribution: Based on "Express Train" by Charles Parsons (Currier and Ives), 1859. 
     Original source: https://commons.wikimedia.org/wiki/File:Express_Train_MET_DT5428.jpg
     Public domain (CC0) - available for use without restrictions. -->

<div align="center">
  <img src="https://raw.githubusercontent.com/dorcha-inc/ceil-dlp/main/share/ceil-dlp-logo-no-bg-logo.png" alt="ceil-dlp logo" width="400">
  
  <p>Open-Source DLP for LLMs and Agentic Workflows with Conversational Coherence</p>
</div>

<p align="center">
  <a href="https://www.python.org/"><img src="https://img.shields.io/badge/Python-3.11+-3776AB?style=flat&logo=python&logoColor=white" alt="Python Version"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-green.svg" alt="License"></a>
  <a href="https://pypi.org/project/ceil-dlp/"><img src="https://img.shields.io/pypi/v/ceil-dlp?color=blue" alt="PyPI Version"></a>
  <a href="https://github.com/dorcha-inc/ceil-dlp/actions/workflows/build.yml"><img src="https://github.com/dorcha-inc/ceil-dlp/actions/workflows/build.yml/badge.svg" alt="Build"></a>
  <a href="https://codecov.io/gh/dorcha-inc/ceil-dlp"><img src="https://codecov.io/gh/dorcha-inc/ceil-dlp/branch/main/graph/badge.svg" alt="Coverage"></a>
</p>

`ceil-dlp` is a Data Loss Prevention (DLP) plugin for [LiteLLM](https://github.com/BerriAI/litellm) that automatically detects and protects Personally Identifiable Information (PII) in LLM requests. This includes PII in text, images, and PDFs. It blocks, masks, or uses reversible tokens to protect sensitive data before it reaches your LLM provider. This helps prevent you from leaking your secrets, API keys, and other sensitive information. If used with reversible tokens, `ceil-dlp` allows you to preserve conversational coherence so users can have natural conversations despite the DLP protections. Finally, `ceil-dlp` also helps you ensure compliance with data privacy regulations like HIPAA, PCI-DSS, GDPR, and CCPA.

<div align="center">
  <img src="https://raw.githubusercontent.com/dorcha-inc/ceil-dlp/main/share/dl_real_id_fade.gif" alt="real id redacted" width="260">
  <img src="https://raw.githubusercontent.com/dorcha-inc/ceil-dlp/main/share/aws_console_fade.gif" alt="aws console redacted" width="260">
  <img src="https://raw.githubusercontent.com/dorcha-inc/ceil-dlp/main/share/research_paper_fade.gif" alt="research paper redacted" width="260">
</div>

## Usage

Install ceil-dlp:

```bash
pip install ceil-dlp
```

Download required spaCy models:

```bash
python -m spacy download en_core_web_lg
python -m spacy download en_core_web_sm
```

Note: If using `uv`, use `uv run python` instead of `python` to ensure models are installed in the correct environment.

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

`ceil-dlp` provides image and PDF support, detecting both PII and secrets in images + pdfs through OCR,. It applies automatically to all requests via LiteLLM's callback system, so you don't need to specify a `guardrails` parameter on every request It also supports both blocking and masking actions for all detection types, giving you full control over how sensitive data is handled.

An important feature in `ceil-dlp` is that it can do DLP while preserving *conversarional coherence*. In addition to masking, blocking, 
and observinb, `ceil-dlp` includes a separate DLP mode called `whistledown`. whistledown (based on our [preprint](https://arxiv.org/pdf/2511.13319)), is designed to preserve conversational context by using consistent, reversible tokens instead of generic redaction markers.

## Preserving Conversational Coherence

<div align="center">
  <img src="https://raw.githubusercontent.com/dorcha-inc/ceil-dlp/main/share/whistledown_mode.png" alt="Whistledown mode diagram" width="800">
</div>

Traditional masking works something like this:

```
User: "My name is John Doe and my email is john@example.com"
-> LLM sees: "My name is [REDACTED_PERSON] and my email is [REDACTED_EMAIL]"
-> User sees: "Hello [REDACTED_PERSON]! I'll send details to [REDACTED_EMAIL]"
```

In whistledown mode, `ceil-dlp` does the following instead:

```
User: "My name is John Doe and my email is john@example.com"
-> LLM sees: "My name is PERSON_1 and my email is EMAIL_1"
-> LLM responds: "Hello PERSON_1! I'll send details to EMAIL_1"
-> User sees: "Hello John Doe! I'll send details to john@example.com"
```

In other words, `ceil-dlp` masks in a way that maintains a one-to-one correspondence between the original entities and the masked entities. `ceil-dlp` then automatically reverses the transformations in LLM responses, restoring the original values for the user. This maintains conversational flow while protecting sensitive data from being sent to external LLM providers.

To enable Whistledown mode, set the action to `whistledown` in your `ceil-dlp.yaml` configuration:

```yaml
policies:
  person:
    action: whistledown  # Use consistent tokens instead of [REDACTED_PERSON]
    enabled: true
  
  email:
    action: whistledown
    enabled: true
```

Note that you can mix actions within the same configuration. For example, using `whistledown` for person names and emails while using `block` for credit cards and API keys.

### Ensemble Model Architecture

`ceil-dlp` uses a unique ensemble approach that combines multiple models to maximize PII detection accuracy while minimizing false negatives. The ensemble architecture operates at two levels:

#### NER Ensemble

You can choose between three configurable detection strength levels. Level 1 uses spaCy's `en_core_web_lg` model, level 2
additionally uses a transformer-based model (`dslim/bert-base-NER`), and level 3 
uses GLiNER (`urchade/gliner_multi_pii-v1`) in addition to the models in the previous levels. All models detect PII + PHI + 
Secrets on the original text independently. The detected results are then merged. This "detect everything first, merge later" approach ensures maximum coverage since each model sees the complete, unredacted text.

#### OCR Ensemble

For images and PDFs, `ceil-dlp` uses a sequential multi-pass OCR ensemble. This also has three configurable 
ocr strength levels. Level 1 uses a lightweight docTR model. Level 2 uses Tesseract as a second model. Finally,
level 3 uses a more heavy-weight docTR model. Each OCR engine runs on the previously-redacted image in sequence. This sequential approach is helpful for images because OCR engines can still read surrounding context after redaction (unlike text where redaction destroys information). The intuition behind this is that different OCR engines have different strengths e.g some are better at handwriting, others at printed text etc. and that running multiple passes will catch PII that any single OCR engine might miss.

### Existing LiteLLM Guardrails

LiteLLM offers built-in [guardrails](https://docs.litellm.ai/docs/proxy/guardrails/quick_start) for many tasks involving LLM interaction security. However, we were unable to find a solution that helps with all the features a person or team working with sensitive data in a real-world LLM interaction would require.

To be more specific, LiteLLM provides two separate guardrails for data protection, each with significant limitations. LiteLLM's [Presidio guardrail](https://docs.litellm.ai/docs/proxy/guardrails/pii_masking_v2) handles PII and PHI masking using Microsoft Presidio, but it does not handle secrets (API keys, tokens, credentials, etc.). Additionally, it only supports LiteLLM-wide configuration and cannot apply different policies to different models. It also seems to lack support for detecting PII in images and PDFs, only working with text content. LiteLLM's [Secret Detection guardrail](https://docs.litellm.ai/docs/proxy/guardrails/secret_detection) is an Enterprise-only feature that requires a paid license. While it can detect secrets and can be configured per model (by defining separate guardrail configurations), it only performs redaction and cannot block requests containing secrets. It also only works on text content and does not detect or redact secrets in images or PDFs.

The masking approach of these existing guardrails use generic `[REDACTED]` tags that break conversational coherence. When the LLM responds with `[REDACTED]`, the user sees the same generic placeholder instead of their original values, making conversations difficult to follow.  In contrast, `ceil-dlp` preserves conversational coherence by using consistent, reversible tokens (like `PERSON_1`, `EMAIL_1`) that are automatically converted back to original values in LLM responses, allowing natural conversations while protecting sensitive data.

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