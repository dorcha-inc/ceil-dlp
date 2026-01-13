# Running ceil-dlp with local Ollama models

This guide shows you how to set up `ceil-dlp` with [Ollama](https://ollama.ai/) models through LiteLLM. Ollama allows you to run LLMs locally, and `ceil-dlp` adds an extra layer of security by detecting and protecting PII before it reaches your models.

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

Create a `config.yaml` file:

```yaml
model_list:
  - model_name: ollama/qwen3:0.6b
    litellm_params:
      model: ollama/qwen3:0.6b

litellm_settings:
  callbacks: ceil_dlp.ceil_dlp_callback.proxy_handler_instance
```

This uses the default configuration (enforce mode). To customize, create a separate `ceil-dlp.yaml` file and set the `CEIL_DLP_CONFIG_PATH` environment variable.

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

By default, `ceil-dlp` masks email addresses. This example will go over creating a custom configuration
to block emails instead.

### Create a Custom Config

Create a file called `ceil-dlp.yaml`:

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

### Use the Custom Config

Set the `CEIL_DLP_CONFIG_PATH` environment variable and restart LiteLLM:

```bash
export CEIL_DLP_CONFIG_PATH=./ceil-dlp.yaml
uv run litellm --config config.yaml --port 4000
```

Or set it inline:

```bash
CEIL_DLP_CONFIG_PATH=./ceil-dlp.yaml uv run litellm --config config.yaml --port 4000
```

### Test the Blocking Behavior

Now test with a request containing an email:

```bash
curl http://localhost:4000/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{
    "model": "ollama/qwen3:0.6b",
    "messages": [
      {"role": "user", "content": "My email is john@example.com"}
    ]
  }'
```

The request should be blocked with a response like:

```json
{
  "error": {
    "message": "{'error': '[ceil-dlp] Request blocked: Detected sensitive data (email)'}",
    "type": "None",
    "param": "None",
    "code": "400"
  }
}
```

You should also see a log entry indicating the block in the LiteLLM console output.