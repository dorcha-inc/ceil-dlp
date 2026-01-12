# Quick Start Guide

### Install

We recommend using [uv](https://docs.astral.sh/uv/) but regular `pip` also works.

```bash
uv pip install ceil-dlp
```

### Enable in LiteLLM

#### Option A: Using Python

```python
from litellm import proxy
from ceil_dlp import setup_litellm

# Just enable with defaults (enforce mode)
litellm_config = setup_litellm()

# Start proxy with ceil-dlp enabled
proxy(
    host="0.0.0.0",
    port=4000,
    **litellm_config
)
```

You can also change the mode. Supported modes are `observe`, `warn`, and `enforce`. `observe` logs all 
detections but never blocks or masks. This is great for dev and staging environments. `warn` applies 
masking and logs, but never blocks. It also adds a warning header. Finally, `enforce` blocks and masks
according to policies.

```python
litellm_config = setup_litellm(mode="observe")
```

#### Option B: Using YAML Config

Add to your LiteLLM `config.yaml`:

```yaml
general_settings:
  custom_callback: ceil_dlp.CeilDLPHandler
```

#### Setting mode via environment variable

Note that the mode can also be set using an environment variable if left unset in Python.

```bash
export CEIL_DLP_MODE=observe
```

That's it! ceil-dlp is now protecting all LLM requests.

### Configuration Files

To customize behavior, create a configuration file.

Create `ceil-dlp.yaml`:

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

Then use it in LiteLLM:

Python:

```python
from litellm import proxy
from ceil_dlp import setup_litellm

litellm_config = setup_litellm(config_path="/path/to/ceil-dlp.yaml")
proxy(host="0.0.0.0", port=4000, **litellm_config)
```

Or YAML:

```yaml
general_settings:
  custom_callback: ceil_dlp.CeilDLPHandler
  custom_callback_params:
    config_path: /path/to/ceil-dlp.yaml
```

### Testing

Send a request with PII:

```python
from litellm import completion

# This will be blocked if mode is "enforce"
try:
    response = completion(
        model="ollama/qwen3:0.6b",
        messages=[
            {"role": "user", "content": "My credit card is 4111111111111111"}
        ]
    )
except Exception as e:
    print(f"Blocked: {e}")
    # Output: Request blocked: Detected sensitive data (credit_card)
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
- Parameter: `setup_litellm(mode="observe")`
- Environment: `export CEIL_DLP_MODE=observe`
- Config file: `mode: observe` in `ceil-dlp.yaml`

### What Gets Detected?

#### Blocked by Default (High-Risk)
- Credit cards (with Luhn validation)
- SSNs
- API keys (OpenAI, Anthropic, GitHub, Stripe, Slack, Google, AWS, Bearer tokens)
- PEM/SSH private keys
- JWT tokens
- High-entropy tokens (secrets without known patterns)

### Masked by Default (Medium-Risk)
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
- macOS: `brew install tesseract`
- Linux: `apt-get install tesseract-ocr` or `yum install tesseract`
- Windows: Download from [GitHub](https://github.com/UB-Mannheim/tesseract/wiki)

### Model-Aware Policies

You can apply policies conditionally based on the target LLM model:

```yaml
policies:
  email:
    action: mask
    enabled: true
    models:
      allow:  # Only allow emails to self-hosted models
        - "ollama/llama2"
        - "local/.*"  # regex: any local model
        - "self-hosted/.*"  # regex: any self-hosted model
      block:  # Explicitly block from external models
        - "openai/.*"
        - "anthropic/.*"
```