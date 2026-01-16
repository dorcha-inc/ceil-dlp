# Quick Start Guide: Running ceil-dlp with LiteLLM

This is a comprehensive quickstart tutorial that uses [Ollama](https://ollama.ai/) as an example, but the same principles apply to any LLM provider supported by LiteLLM (OpenAI, Anthropic, Google, etc.). Simply replace the Ollama model names with your preferred provider's model names in the configuration. Ollama allows you to run LLMs locally, and `ceil-dlp` adds an extra layer of security by detecting and protecting PII before it reaches your models.

## Prerequisites

- Python 3.11 or higher
- [Ollama](https://ollama.ai/) installed and running
- At least one Ollama model pulled (e.g., `ollama pull qwen3:0.6b`)

## Installation

### Install Ollama

If you haven't already, install Ollama.

On macOS, you can use brew:

```bash
brew install ollama
```

On Linux, you can use

```bash
curl -fsSL https://ollama.ai/install.sh | sh
```

For Windows, take a look at [https://ollama.ai/download](https://ollama.ai/download).

### Pull an Ollama Model

In this example, we will use `qwen3:0.6b`. 

```bash
ollama pull qwen3:0.6b
```

Verify that the model is installed:

```bash
ollama list
```

### Install LiteLLM and ceil-dlp

We recommend using [uv](https://docs.astral.sh/uv/) but regular `pip` also works:

```bash
uv pip install 'litellm[proxy]' ceil-dlp
```

## Setup

First, create a basic LiteLLM `config.yaml` file with your model configuration:

```yaml
model_list:
  - model_name: ollama/qwen3:0.6b
    litellm_params:
      model: ollama/qwen3:0.6b
```

Then use the `ceil-dlp` CLI to automatically configure ceil-dlp:

```bash
ceil-dlp install config.yaml
```

This will automatically:
1. Create a `ceil_dlp_callback.py` wrapper file in the same directory as your config
2. Create a starter `ceil-dlp.yaml` configuration file
3. Update your `config.yaml` to include the ceil-dlp callback

The generated `ceil-dlp.yaml` uses the default configuration (enforce mode). You can customize it by editing the file directly.

## Running LiteLLM

Then run LiteLLM:

```bash
uv run litellm --config config.yaml --port 4000
```

## Testing

First, verify Ollama works:

```bash
ollama run qwen3:0.6b "Hello, how are you?"
```

Next, test that LiteLLM can reach Ollama:

```bash
curl http://localhost:4000/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{
    "model": "ollama/qwen3:0.6b",
    "messages": [
      {"role": "user", "content": "Hello!"}
    ]
  }'
```

Finally, check if `ceil-dlp` is working:

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

The response should be something like:

```json
{
  "id": "chatcmpl-691dafb6-9548-4c77-9e67-473b04202348",
  "created": 1768297462,
  "model": "ollama/qwen3:0.6b",
  "object": "chat.completion",
  "choices": [
    {
      "finish_reason": "stop",
      "index": 0,
      "message": {
        "content": "Please echo back the following: my email is [REDACTED_EMAIL] and my phone is [REDACTED_PHONE].",
        "role": "assistant"
      }
    }
  ],
  "usage": {
    "completion_tokens": 270,
    "prompt_tokens": 40,
    "total_tokens": 310
  }
}
```

### Testing Image PII Detection

`ceil-dlp` can also detect PII in images sent via multimodal messages. Test with the included example image. Note that 
we are testing with a model that supports vision here (`ministral-3:3b`) and not the smaller `qwen3:0.6b` model. You 
will need to change this in `config.yaml`.

```bash
curl http://localhost:4000/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d "{
    \"model\": \"ollama/ministral-3:3b\",
    \"messages\": [
      {
        \"role\": \"user\",
        \"content\": [
          {\"type\": \"text\", \"text\": \"What PII is in this image?\"},
          {\"type\": \"image_url\", \"image_url\": {\"url\": \"data:image/png;base64,$(base64 -i docs/pii_image.png | tr -d '\n')\"}}
        ]
      }
    ]
  }"
```

The response should have the PII redacted in the image content:

```json
{
  "id": "chatcmpl-ac03bcaf-85ae-4040-84bb-2dad95f5fcbc",
  "created": 1768300162,
  "model": "ollama/ministral-3:3b",
  "object": "chat.completion",
  "choices": [
    {
      "finish_reason": "stop",
      "index": 0,
      "message": {
        "content": "The provided image does not contain any personally identifiable information (PII) that can be read or extracted from the blurred text.\n\nIf you are referring to the redacted fields in the image:\n- **[REDACTED_EMAIL]** represents a placeholder for an email address that is intentionally obscured.\n- **[REDACTED_PHONE]** represents a placeholder for a phone number that is also intentionally obscured.\n\nNo actual PII is visible in the image. If you need assistance with verifying or handling actual PII, ensure compliance with privacy regulations (e.g., GDPR, CCPA) and avoid sharing real data here.",
        "role": "assistant"
      }
    }
  ],
  "usage": {
    "completion_tokens": 125,
    "prompt_tokens": 642,
    "total_tokens": 767
  }
}
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

## Custom Configuration Example

By default, `ceil-dlp` masks email addresses. This example will go over customizing the configuration
to block emails instead.

### Edit the Config File

The `ceil-dlp install` command creates a `ceil-dlp.yaml` file in the same directory as your LiteLLM config.
Simply edit this file to customize the behavior:

```yaml
mode: enforce

policies:
  email:
    action: block  # Block instead of mask
    enabled: true
  phone:
    action: mask  # Keep phone masking as default
    enabled: true
```

The callback wrapper automatically detects and uses the `ceil-dlp.yaml` file in the same directory. Just restart LiteLLM after making changes:

```bash
uv run litellm --config config.yaml --port 4000
```

### Test the Blocking Behavior

Now test with a request containing an API key:

```bash
curl http://localhost:4000/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{
    "model": "ollama/qwen3:0.6b",
    "messages": [
      {"role": "user", "content": "My API key is AIza12345678901234567890123456789012345"}
    ]
  }'
```

The request should be blocked with a response like:

```json
{
  "error": {
    "message": "{'error': '[ceil-dlp] Request blocked: Detected sensitive data (api_key)'}",
    "type": "None",
    "param": "None",
    "code": "400"
  }
}
```

You should also see a log entry indicating the block in the LiteLLM console output.

## Model-Specific Policies

`ceil-dlp` supports model-aware policies, allowing you to apply different rules to different models. This is useful when you want stricter security for some models while allowing more flexibility for trusted local models.

### Example: Block API Keys for One Model, Allow for Another

Suppose you want to block API keys when using `ollama/ministral3:3b` (a larger, potentially less trusted model) but allow them for `ollama/qwen3:0.6b` (a smaller, trusted local model).

Create a `ceil-dlp.yaml` configuration:

```yaml
mode: enforce

policies:
  api_key:
    action: block
    enabled: true
    models:
      allow:
        - "ollama/qwen3:0.6b"  # Allow API keys for this specific model
  # Other policies apply to all models by default
  email:
    action: mask
    enabled: true
  phone:
    action: mask
    enabled: true
```

### Model Matching

If there is no `models` field, then the policy applies to all models. This is the default behavior. 

If there is a `models.allow` list, then models matching patterns in this list will skip the policy i.e the policy is not applied
for these models. The policy is enforced for all models not in the allow list.

If there is a `models.block` list, then models matching patterns in this list will apply the policy, however 
models not in the blocklist will skip the policy.

Patterns support regex matching. For example:

- `"ollama/qwen3:0.6b"` - exact match
- `"ollama/qwen.*"` - matches any qwen model
- `"ollama/.*"` - matches all ollama models

### Testing Model-Specific Policies

With the configuration above, test blocking behavior:

```bash
curl http://localhost:4000/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{
    "model": "ollama/ministral3:3b",
    "messages": [
      {"role": "user", "content": "My API key is AIza00000000000000000000000000000000000"}
    ]
  }'
```

Expected response:
```json
{
  "error": {
    "message": "{'error': '[ceil-dlp] Request blocked: Detected sensitive data (api_key)'}",
    "type": "None",
    "param": "None",
    "code": "400"
  }
}
```

Now test the allowed model:

```bash
curl http://localhost:4000/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{
    "model": "ollama/qwen3:0.6b",
    "messages": [
      {"role": "user", "content": "My API key is AIza00000000000000000000000000000000000"}
    ]
  }'
```

This request should succeed and the API key will be passed through to the model (since the policy is skipped for this model)"

```json
{
  "id": "chatcmpl-8780e909-a243-4c79-a99b-3b0eb7ea80a7",
  "created": 1768526891,
  "model": "ollama/qwen3:0.6b",
  "object": "chat.completion",
  "choices": [
    {
      "finish_reason": "stop",
      "index": 0,
      "message": {
        "content": "Great to know! Your API key is AIza0000000000000000000000000000000",
        "role": "assistant"
      }
    }
  ],
  "usage": {
    "completion_tokens": 0,
    "prompt_tokens": 22,
    "total_tokens": 22
  }
}
```

## Removing ceil-dlp

To remove ceil-dlp from your LiteLLM configuration, use the `remove` command:

```bash
ceil-dlp remove config.yaml
```

This will:
- Remove the callback from your LiteLLM `config.yaml`
- Remove the `ceil_dlp_callback.py` wrapper file (by default)

You can also control what gets removed using flags:
- `--keep-callback-file` - Keep the callback wrapper file
- `--remove-config-file` - Also remove the `ceil-dlp.yaml` config file
- `--no-update-config` - Don't update the LiteLLM config file

For example, to remove the callback from the config but keep all files:

```bash
ceil-dlp remove config.yaml --keep-callback-file --no-update-config
```

