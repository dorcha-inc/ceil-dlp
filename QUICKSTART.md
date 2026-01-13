# Quick Start Guide

### Install

We recommend using [uv](https://docs.astral.sh/uv/) but regular `pip` also works.

```bash
uv pip install ceil-dlp
```

### Enable in LiteLLM

Add to your LiteLLM `config.yaml`:

```yaml
model_list:
  - model_name: gpt-3.5-turbo
    litellm_params:
      model: gpt-3.5-turbo

litellm_settings:
  callbacks: ceil_dlp.ceil_dlp_callback.proxy_handler_instance
```

This uses the default configuration (enforce mode). Then run LiteLLM:

```bash
litellm --config config.yaml --port 4000
```

That's it! ceil-dlp is now protecting all LLM requests.

### Configuration Files

To customize behavior, create a separate `ceil-dlp.yaml` configuration file:

```yaml
# Operational mode: observe | warn | enforce
mode: observe  # Start in observe mode to see what gets detected

policies:
  credit_card:
    action: block
    enabled: true
  email:
    action: mask
    enabled: true
  # Add more policies as needed

audit_log_path: /var/log/ceil-dlp/audit.log
```

Then set the `CEIL_DLP_CONFIG_PATH` environment variable to point to your config file:

```bash
export CEIL_DLP_CONFIG_PATH=/path/to/ceil-dlp.yaml
litellm --config config.yaml --port 4000
```

Or set it inline:

```bash
CEIL_DLP_CONFIG_PATH=/path/to/ceil-dlp.yaml litellm --config config.yaml --port 4000
```

### Testing

Send a request with PII:

```bash
curl http://localhost:4000/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{
    "model": "ollama/qwen3:0.6b",
    "messages": [
      {"role": "user", "content": "Please echo back the following: my email is john@example.com and my phone is 555-123-4567"}
    ]
  }'
```

### Checking Audit Logs

Audit logs show what was detected:

```json
{
  "timestamp": "2026-01-12T12:00:00.000000",
  "user_id": "user_123",
  "action": "blocked",
  "pii_types": ["credit_card"],
  "mode": "enforce"
}
```

### Operational Modes

As mentioned earlier, you can choose how strict to be:

1. `observe`: Log all detections but never block or mask (great for dev/staging)
2. `warn`: Apply masking and log, but never block (adds warning headers)
3. `enforce`: Block and mask according to policies (default, secure-by-default)

This can be set via:
- YAML config: `mode: observe` in a separate `ceil-dlp.yaml` file (set via `CEIL_DLP_CONFIG_PATH` environment variable)

### What Gets Detected?

#### Blocked by Default (High-Risk)
- Credit cards (with Luhn validation)
- SSNs
- API keys (OpenAI, Anthropic, GitHub, Stripe, Slack, Google, AWS, Bearer tokens)
- PEM/SSH private keys
- JWT tokens
- High-entropy tokens (secrets without known patterns)

### Redacted by Default (Medium-Risk)
- Email addresses
- Phone numbers (US and international)

### Image PII Detection

ceil-dlp automatically detects PII in images sent via multimodal messages:

```python
# Image with credit card will be detected and blocked
response = completion(
    model="ollama/ministral-3:3b",
    messages=[
        {
            "role": "user",
            "content": [
                {"type": "text", "text": "What's on this card?"},
                {"type": "image_url", "image_url": {"url": "data:image/png;base64,..."}}
            ]
        }
    ]
)
```

Note: Image detection requires Tesseract OCR installed system-wide:

On macOS: 

```bash
brew install tesseract
```

On Linux: 

```bash
apt-get install tesseract-ocr
```

On Windows: Download from [GitHub](https://github.com/UB-Mannheim/tesseract/wiki)

### Model-Aware Policies

You can apply policies conditionally based on the target LLM model:

```yaml
policies:
  email:
    action: mask
    enabled: true
    models:
      allow:  # Only allow emails to self-hosted models
        - "ollama/qwen3:0.6b"
        - "local/.*"  # regex: any local model
        - "self-hosted/.*"  # regex: any self-hosted model
      block:  # Explicitly block from external models
        - "openai/.*"
        - "anthropic/.*"
```