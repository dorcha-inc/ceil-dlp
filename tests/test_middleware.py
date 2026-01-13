"""Tests for middleware/LiteLLM integration."""

from unittest.mock import patch

import pytest
import yaml

from ceil_dlp.config import Config
from ceil_dlp.middleware import CeilDLPHandler


def test_middleware_init_default_config():
    """Test middleware initialization with default config."""
    handler = CeilDLPHandler()
    assert handler.config is not None
    assert handler.detector is not None
    assert handler.audit_logger is not None


def test_middleware_init_with_config():
    """Test middleware initialization with custom config."""
    config = Config()
    handler = CeilDLPHandler(config=config)
    assert handler.config == config


def test_middleware_init_with_config_path(tmp_path):
    """Test middleware initialization with config path."""

    config_file = tmp_path / "config.yaml"
    config_data = {
        "policies": {
            "email": {"action": "block", "enabled": True},
        }
    }
    config_file.write_text(yaml.dump(config_data))

    handler = CeilDLPHandler(config_path=config_file)
    assert handler.config is not None
    assert handler.config.policies["email"].action == "block"


def test_middleware_extract_text_from_messages():
    """Test text extraction from LiteLLM messages."""
    handler = CeilDLPHandler()
    messages = [
        {"role": "user", "content": "Hello"},
        {"role": "assistant", "content": "Hi there"},
        {"role": "user", "content": "What is my email? john@example.com"},
    ]
    text = handler._extract_text_from_messages(messages)
    assert "Hello" in text
    assert "Hi there" in text
    assert "john@example.com" in text


def test_middleware_extract_text_from_string_messages():
    """Test text extraction when content is a string."""
    handler = CeilDLPHandler()
    messages = [
        {"role": "user", "content": "Hello world"},
    ]
    text = handler._extract_text_from_messages(messages)
    assert text == "Hello world"


def test_middleware_extract_text_empty():
    """Test text extraction with empty messages."""
    handler = CeilDLPHandler()
    text = handler._extract_text_from_messages([])
    assert text == ""


@pytest.mark.asyncio
async def test_middleware_pre_call_hook_no_pii():
    """Test pre-call hook with no PII detected."""
    handler = CeilDLPHandler()
    messages = [{"role": "user", "content": "Hello world"}]
    data = {
        "model": "gpt-4",
        "messages": messages,
        "litellm_call_id": "test123",
    }

    result = await handler.async_pre_call_hook(
        user_api_key_dict=None,
        cache=None,
        data=data,
        call_type="completion",
    )
    assert result == data


@pytest.mark.asyncio
async def test_middleware_pre_call_hook_blocked_pii():
    """Test pre-call hook blocking high-risk PII."""
    handler = CeilDLPHandler()
    messages = [{"role": "user", "content": "My credit card is 4111111111111111"}]
    data = {
        "model": "gpt-4",
        "messages": messages,
        "litellm_call_id": "test123",
    }

    result = await handler.async_pre_call_hook(
        user_api_key_dict=None,
        cache=None,
        data=data,
        call_type="completion",
    )
    assert isinstance(result, str)
    assert "blocked" in result.lower()


@pytest.mark.asyncio
async def test_middleware_pre_call_hook_masked_pii():
    """Test pre-call hook masking medium-risk PII."""
    handler = CeilDLPHandler()
    messages = [{"role": "user", "content": "My email is john@example.com"}]
    data = {
        "model": "gpt-4",
        "messages": messages,
        "litellm_call_id": "test123",
    }

    result = await handler.async_pre_call_hook(
        user_api_key_dict=None,
        cache=None,
        data=data,
        call_type="completion",
    )
    assert isinstance(result, dict)
    # Check that messages were modified
    assert "[REDACTED_EMAIL]" in str(result.get("messages", []))


@pytest.mark.asyncio
async def test_middleware_async_pre_call_hook():
    """Test async pre-call hook."""
    handler = CeilDLPHandler()
    messages = [{"role": "user", "content": "Hello"}]
    data = {"model": "gpt-4", "messages": messages}

    result = await handler.async_pre_call_hook(
        user_api_key_dict=None,
        cache=None,
        data=data,
        call_type="completion",
    )
    # Should return data for normal text
    assert isinstance(result, dict)
    assert result == data


@pytest.mark.asyncio
async def test_middleware_pre_call_hook_empty_text():
    """Test pre-call hook with empty text content."""
    handler = CeilDLPHandler()
    messages = [{"role": "user", "content": None}]
    data = {"model": "gpt-4", "messages": messages, "litellm_call_id": "test123"}

    result = await handler.async_pre_call_hook(
        user_api_key_dict=None,
        cache=None,
        data=data,
        call_type="completion",
    )
    assert result == data


@pytest.mark.asyncio
async def test_middleware_pre_call_hook_disabled_policy():
    """Test pre-call hook with disabled policy."""
    config = Config()
    config.policies["email"].enabled = False
    handler = CeilDLPHandler(config=config)
    messages = [{"role": "user", "content": "My email is john@example.com"}]
    data = {"model": "gpt-4", "messages": messages, "litellm_call_id": "test123"}

    result = await handler.async_pre_call_hook(
        user_api_key_dict=None,
        cache=None,
        data=data,
        call_type="completion",
    )
    # Should not block or mask since policy is disabled
    assert result == data


@pytest.mark.asyncio
async def test_middleware_pre_call_hook_no_policy():
    """Test pre-call hook with PII type that has no policy."""
    handler = CeilDLPHandler()
    # Use a detector that finds something not in default policies
    messages = [{"role": "user", "content": "test"}]
    data = {"model": "gpt-4", "messages": messages, "litellm_call_id": "test123"}

    result = await handler.async_pre_call_hook(
        user_api_key_dict=None,
        cache=None,
        data=data,
        call_type="completion",
    )
    assert result == data


@pytest.mark.asyncio
async def test_middleware_async_pre_call_hook_exception():
    """Test async pre-call hook exception handling."""
    handler = CeilDLPHandler()
    messages = [{"role": "user", "content": "Hello"}]
    data = {"model": "gpt-4", "messages": messages}

    # Mock _process_pii_detection to raise an exception
    with patch.object(handler, "_process_pii_detection", side_effect=Exception("Test error")):
        result = await handler.async_pre_call_hook(
            user_api_key_dict=None,
            cache=None,
            data=data,
            call_type="completion",
        )
        # Should return original data on exception (fail-safe)
        assert result == data


@pytest.mark.asyncio
async def test_middleware_async_post_call_success_hook():
    """Test async post-call success hook."""
    handler = CeilDLPHandler()
    data = {"model": "gpt-4", "messages": [{"role": "user", "content": "Hello"}]}
    response = {"content": "Hi"}
    result = await handler.async_post_call_success_hook(
        data=data,
        user_api_key_dict=None,
        response=response,
    )
    # Should return None (no-op)
    assert result is None


def test_middleware_extract_text_none_content():
    """Test text extraction with None content."""
    handler = CeilDLPHandler()
    messages = [{"role": "user", "content": None}]
    text = handler._extract_text_from_messages(messages)
    assert text == ""


def test_middleware_extract_text_multimodal():
    """Test text extraction from multimodal content."""
    handler = CeilDLPHandler()
    messages = [
        {
            "role": "user",
            "content": [
                {"type": "text", "text": "Hello"},
                {"type": "image", "image_url": "https://example.com/image.jpg"},
                {"type": "text", "text": "world"},
            ],
        }
    ]
    text = handler._extract_text_from_messages(messages)
    assert "Hello" in text
    assert "world" in text
    assert "image" not in text


def test_middleware_extract_text_empty_strings():
    """Test text extraction filtering empty strings."""
    handler = CeilDLPHandler()
    messages = [
        {"role": "user", "content": ""},
        {"role": "user", "content": "Hello"},
        {"role": "user", "content": "   "},
    ]
    text = handler._extract_text_from_messages(messages)
    assert "Hello" in text
    assert text.strip() == "Hello"


def test_middleware_replace_text_in_messages_multimodal():
    """Test text replacement in multimodal messages."""
    handler = CeilDLPHandler()
    messages = [
        {
            "role": "user",
            "content": [
                {"type": "text", "text": "My email is john@example.com"},
                {"type": "image", "image_url": "https://example.com/image.jpg"},
            ],
        }
    ]
    modified = handler._replace_text_in_messages(messages, "john@example.com", "[REDACTED_EMAIL]")
    assert "[REDACTED_EMAIL]" in str(modified)
    # Image should be preserved
    assert "image" in str(modified)


def test_middleware_replace_text_in_string_messages():
    """Test text replacement when message is a string."""
    handler = CeilDLPHandler()
    messages = ["My email is john@example.com"]
    modified = handler._replace_text_in_messages(messages, "john@example.com", "[REDACTED_EMAIL]")
    assert len(modified) == 1
    assert modified[0]["content"] == "My email is [REDACTED_EMAIL]"


def test_middleware_create_handler():
    """Test create_handler factory function."""
    from ceil_dlp.middleware import create_handler

    handler = create_handler()
    assert isinstance(handler, CeilDLPHandler)


def test_middleware_create_handler_with_config_path(tmp_path):
    """Test create_handler with config path."""
    from ceil_dlp.middleware import create_handler

    config_file = tmp_path / "config.yaml"
    config_data = {"policies": {"email": {"action": "block", "enabled": True}}}
    config_file.write_text(yaml.dump(config_data))

    handler = create_handler(config_path=str(config_file))
    assert handler.config.policies["email"].action == "block"


def test_middleware_create_handler_with_kwargs():
    """Test create_handler with kwargs (config dict passed as keyword args)."""
    from ceil_dlp.middleware import create_handler

    handler = create_handler(policies={"custom_type": {"action": "block", "enabled": True}})
    # Custom policy should be present
    assert handler.config.policies["custom_type"].action == "block"
    # Defaults should still be present
    assert "credit_card" in handler.config.policies
    assert "email" in handler.config.policies


def test_middleware_extract_text_string_message():
    """Test text extraction when message is a string (not dict)."""
    handler = CeilDLPHandler()
    messages = ["Hello world", "Another string"]
    text = handler._extract_text_from_messages(messages)
    assert "Hello world" in text
    assert "Another string" in text


def test_middleware_extract_text_string_message_empty():
    """Test text extraction with empty string message."""
    handler = CeilDLPHandler()
    messages = [""]
    text = handler._extract_text_from_messages(messages)
    assert text == ""


@pytest.mark.asyncio
async def test_middleware_mode_observe():
    """Test observe mode: log but never block or mask."""
    config = Config(mode="observe")
    handler = CeilDLPHandler(config=config)
    messages = [{"role": "user", "content": "My credit card is 4111111111111111"}]
    data = {"model": "gpt-4", "messages": messages, "litellm_call_id": "test123"}

    result = await handler.async_pre_call_hook(
        user_api_key_dict=None,
        cache=None,
        data=data,
        call_type="completion",
    )
    # Should not block in observe mode
    assert result == data


@pytest.mark.asyncio
async def test_middleware_mode_warn():
    """Test warn mode: mask but never block, add warning header."""
    config = Config(mode="warn")
    handler = CeilDLPHandler(config=config)
    messages = [{"role": "user", "content": "My email is john@example.com"}]
    data = {"model": "gpt-4", "messages": messages, "litellm_call_id": "test123"}

    result = await handler.async_pre_call_hook(
        user_api_key_dict=None,
        cache=None,
        data=data,
        call_type="completion",
    )
    # Should not block in warn mode
    assert isinstance(result, dict)
    # Should have warning header
    assert "extra_headers" in result
    assert result["extra_headers"]["X-Ceil-DLP-Warning"] == "violations_detected"


@pytest.mark.asyncio
async def test_middleware_mode_warn_blocked_type():
    """Test warn mode with blocked type: log warning but don't block."""
    config = Config(mode="warn")
    handler = CeilDLPHandler(config=config)
    messages = [{"role": "user", "content": "My credit card is 4111111111111111"}]
    data = {"model": "gpt-4", "messages": messages, "litellm_call_id": "test123"}

    result = await handler.async_pre_call_hook(
        user_api_key_dict=None,
        cache=None,
        data=data,
        call_type="completion",
    )
    # Should not block even for blocked types in warn mode
    assert isinstance(result, dict)
    # Should have warning header
    assert "extra_headers" in result
    assert result["extra_headers"]["X-Ceil-DLP-Warning"] == "violations_detected"


@pytest.mark.asyncio
async def test_middleware_mode_enforce():
    """Test enforce mode: block and mask according to policies."""
    config = Config(mode="enforce")
    handler = CeilDLPHandler(config=config)
    messages = [{"role": "user", "content": "My credit card is 4111111111111111"}]
    data = {"model": "gpt-4", "messages": messages, "litellm_call_id": "test123"}

    result = await handler.async_pre_call_hook(
        user_api_key_dict=None,
        cache=None,
        data=data,
        call_type="completion",
    )
    # Should block in enforce mode
    assert isinstance(result, str)
    assert "blocked" in result.lower()


def test_middleware_mode_config_from_yaml(tmp_path):
    """Test mode configuration loaded from YAML."""
    config_file = tmp_path / "config.yaml"
    config_data = {"mode": "observe"}
    config_file.write_text(yaml.dump(config_data))

    config = Config.from_yaml(config_file)
    assert config.mode == "observe"


def test_middleware_mode_config_from_dict():
    """Test mode configuration from dict."""
    config = Config.from_dict({"mode": "warn"})
    assert config.mode == "warn"


def test_middleware_mode_config_default():
    """Test that mode defaults to enforce."""
    config = Config()
    assert config.mode == "enforce"


def test_middleware_mode_config_env_var(monkeypatch):
    """Test mode configuration from environment variable."""
    monkeypatch.setenv("CEIL_DLP_MODE", "observe")
    config = Config()
    assert config.mode == "observe"


@pytest.mark.asyncio
async def test_middleware_model_aware_policy_allow_list():
    """Test model-aware policy with allow list - model in list should skip policy."""
    from ceil_dlp.config import ModelRules, Policy

    config = Config()
    # Create policy that allows specific models
    config.policies["email"] = Policy(
        action="block",
        enabled=True,
        models=ModelRules(allow=["openai/gpt-4", "self-hosted/.*"]),
    )

    handler = CeilDLPHandler(config=config)
    messages = [{"role": "user", "content": "My email is john@example.com"}]

    # Model in allow list - should skip policy (allow request)
    data = {"model": "openai/gpt-4", "messages": messages}
    result = await handler.async_pre_call_hook(
        user_api_key_dict=None,
        cache=None,
        data=data,
        call_type="completion",
    )
    assert isinstance(result, dict)  # Request should be allowed


@pytest.mark.asyncio
async def test_middleware_model_aware_policy_allow_list_no_match():
    """Test model-aware policy with allow list - model not in list should apply policy."""
    from ceil_dlp.config import ModelRules, Policy

    config = Config()
    config.policies["email"] = Policy(
        action="block",
        enabled=True,
        models=ModelRules(allow=["self-hosted/.*"]),
    )

    handler = CeilDLPHandler(config=config)
    messages = [{"role": "user", "content": "My email is john@example.com"}]

    # Model not in allow list - should apply policy (block request)
    data = {"model": "openai/gpt-4", "messages": messages}
    result = await handler.async_pre_call_hook(
        user_api_key_dict=None,
        cache=None,
        data=data,
        call_type="completion",
    )
    assert isinstance(result, str)  # Request should be blocked
    assert "email" in result.lower()


@pytest.mark.asyncio
async def test_middleware_model_aware_policy_block_list():
    """Test model-aware policy with block list - model in list should apply policy."""
    from ceil_dlp.config import ModelRules, Policy

    config = Config()
    config.policies["email"] = Policy(
        action="block",
        enabled=True,
        models=ModelRules(block=["openai/.*"]),
    )

    handler = CeilDLPHandler(config=config)
    messages = [{"role": "user", "content": "My email is john@example.com"}]

    # Model in block list - should apply policy (block request)
    data = {"model": "openai/gpt-4", "messages": messages}
    result = await handler.async_pre_call_hook(
        user_api_key_dict=None,
        cache=None,
        data=data,
        call_type="completion",
    )
    assert isinstance(result, str)  # Request should be blocked


@pytest.mark.asyncio
async def test_middleware_model_aware_policy_block_list_no_match():
    """Test model-aware policy with block list - model not in list should skip policy."""
    from ceil_dlp.config import ModelRules, Policy

    config = Config()
    config.policies["email"] = Policy(
        action="block",
        enabled=True,
        models=ModelRules(block=["openai/.*"]),
    )

    handler = CeilDLPHandler(config=config)
    messages = [{"role": "user", "content": "My email is john@example.com"}]

    # Model not in block list - should skip policy (allow request)
    data = {"model": "self-hosted/llama2", "messages": messages}
    result = await handler.async_pre_call_hook(
        user_api_key_dict=None,
        cache=None,
        data=data,
        call_type="completion",
    )
    assert isinstance(result, dict)  # Request should be allowed


@pytest.mark.asyncio
async def test_middleware_model_aware_policy_both_lists():
    """Test model-aware policy with both allow and block lists - block takes precedence."""
    from ceil_dlp.config import ModelRules, Policy

    config = Config()
    config.policies["email"] = Policy(
        action="block",
        enabled=True,
        models=ModelRules(allow=["openai/.*"], block=["openai/gpt-4"]),
    )

    handler = CeilDLPHandler(config=config)
    messages = [{"role": "user", "content": "My email is john@example.com"}]

    # Model in both lists - block should take precedence
    data = {"model": "openai/gpt-4", "messages": messages}
    result = await handler.async_pre_call_hook(
        user_api_key_dict=None,
        cache=None,
        data=data,
        call_type="completion",
    )
    assert isinstance(result, str)  # Request should be blocked (block takes precedence)


@pytest.mark.asyncio
async def test_middleware_model_aware_policy_no_models_field():
    """Test policy without models field - should apply to all models (backward compatible)."""
    config = Config()
    # Default policy has no models field
    handler = CeilDLPHandler(config=config)
    messages = [{"role": "user", "content": "My credit card is 4111111111111111"}]

    # Should block regardless of model (backward compatible behavior)
    data = {"model": "openai/gpt-4", "messages": messages}
    result = await handler.async_pre_call_hook(
        user_api_key_dict=None,
        cache=None,
        data=data,
        call_type="completion",
    )
    assert isinstance(result, str)  # Request should be blocked


@pytest.mark.asyncio
async def test_middleware_model_aware_policy_regex_pattern():
    """Test model-aware policy with regex pattern matching."""
    from ceil_dlp.config import ModelRules, Policy

    config = Config()
    config.policies["email"] = Policy(
        action="block",
        enabled=True,
        models=ModelRules(allow=["self-hosted/.*", "local/.*"]),
    )

    handler = CeilDLPHandler(config=config)
    messages = [{"role": "user", "content": "My email is john@example.com"}]

    # Test regex pattern matching
    data1 = {"model": "self-hosted/llama2", "messages": messages}
    result1 = await handler.async_pre_call_hook(
        user_api_key_dict=None,
        cache=None,
        data=data1,
        call_type="completion",
    )
    assert isinstance(result1, dict)  # Should allow (matches self-hosted/.*)

    data2 = {"model": "local/ollama", "messages": messages}
    result2 = await handler.async_pre_call_hook(
        user_api_key_dict=None,
        cache=None,
        data=data2,
        call_type="completion",
    )
    assert isinstance(result2, dict)  # Should allow (matches local/.*)

    data3 = {"model": "openai/gpt-4", "messages": messages}
    result3 = await handler.async_pre_call_hook(
        user_api_key_dict=None,
        cache=None,
        data=data3,
        call_type="completion",
    )
    assert isinstance(result3, str)  # Should block (doesn't match allow patterns)


@pytest.mark.asyncio
async def test_middleware_model_aware_policy_exact_match():
    """Test model-aware policy with exact match (no regex)."""
    from ceil_dlp.config import ModelRules, Policy

    config = Config()
    config.policies["email"] = Policy(
        action="block",
        enabled=True,
        models=ModelRules(allow=["openai/gpt-4"]),
    )

    handler = CeilDLPHandler(config=config)
    messages = [{"role": "user", "content": "My email is john@example.com"}]

    # Exact match
    data1 = {"model": "openai/gpt-4", "messages": messages}
    result1 = await handler.async_pre_call_hook(
        user_api_key_dict=None,
        cache=None,
        data=data1,
        call_type="completion",
    )
    assert isinstance(result1, dict)  # Should allow (exact match)

    # Similar but not exact
    data2 = {"model": "openai/gpt-3.5", "messages": messages}
    result2 = await handler.async_pre_call_hook(
        user_api_key_dict=None,
        cache=None,
        data=data2,
        call_type="completion",
    )
    assert isinstance(result2, str)  # Should block (not exact match)


@pytest.mark.asyncio
async def test_middleware_image_redaction_in_messages():
    """Test image redaction in messages."""
    import base64

    from ceil_dlp.utils import create_image_with_text

    handler = CeilDLPHandler()
    # Create an image with PII
    image_text = "Contact: john@example.com"
    image_bytes = create_image_with_text(image_text)

    # Create messages with base64-encoded image
    image_base64 = base64.b64encode(image_bytes).decode("utf-8")
    messages = [
        {
            "role": "user",
            "content": [
                {"type": "text", "text": "What's in this image?"},
                {
                    "type": "image_url",
                    "image_url": {"url": f"data:image/png;base64,{image_base64}"},
                },
            ],
        }
    ]

    # Mock image detection to return email PII
    with (
        patch.object(handler.detector, "detect", return_value={}),
        patch(
            "ceil_dlp.middleware.detect_pii_in_image",
            return_value={"email": [("[email_detected_in_image]", 0, 1)]},
        ),
    ):
        # Create images_with_pii list
        images_with_pii = [(image_bytes, {"email": [("[email_detected_in_image]", 0, 1)]})]
        pii_types_to_mask = {"email"}

        # Mock redact_image to return modified bytes
        redacted_bytes = b"redacted_image_data"
        with patch("ceil_dlp.middleware.redact_image", return_value=redacted_bytes):
            modified = handler._redact_images_in_messages(
                messages, images_with_pii, pii_types_to_mask
            )

            # Check that image was replaced
            assert modified != messages
            image_item = modified[0]["content"][1]
            assert image_item["type"] == "image_url"
            # Image URL should contain redacted base64
            redacted_base64 = base64.b64encode(redacted_bytes).decode("utf-8")
            assert redacted_base64 in image_item["image_url"]["url"]


@pytest.mark.asyncio
async def test_middleware_image_redaction_no_pii_to_mask():
    """Test image redaction when no PII types need masking."""
    handler = CeilDLPHandler()
    messages = [{"role": "user", "content": "Hello"}]
    images_with_pii: list[tuple[bytes, dict[str, list[tuple[str, int, int]]]]] = []
    pii_types_to_mask: set[str] = set()

    modified = handler._redact_images_in_messages(messages, images_with_pii, pii_types_to_mask)
    assert modified == messages


@pytest.mark.asyncio
async def test_middleware_image_redaction_different_pii_types():
    """Test image redaction when image has PII but different types than what needs masking."""
    import base64

    from ceil_dlp.utils import create_image_with_text

    handler = CeilDLPHandler()
    image_bytes = create_image_with_text("Contact: john@example.com")
    image_base64 = base64.b64encode(image_bytes).decode("utf-8")

    messages = [
        {
            "role": "user",
            "content": [
                {
                    "type": "image_url",
                    "image_url": {"url": f"data:image/png;base64,{image_base64}"},
                }
            ],
        }
    ]

    # Image has email, but we only want to mask phone
    images_with_pii = [(image_bytes, {"email": [("[email_detected_in_image]", 0, 1)]})]
    pii_types_to_mask = {"phone"}

    modified = handler._redact_images_in_messages(messages, images_with_pii, pii_types_to_mask)
    # Image should not be redacted since email is not in pii_types_to_mask
    assert modified == messages


@pytest.mark.asyncio
async def test_middleware_image_redaction_image_type_format():
    """Test image redaction with 'image' type (direct image data)."""
    import base64

    from ceil_dlp.utils import create_image_with_text

    handler = CeilDLPHandler()
    image_bytes = create_image_with_text("Contact: john@example.com")
    image_base64 = base64.b64encode(image_bytes).decode("utf-8")

    messages = [
        {
            "role": "user",
            "content": [{"type": "image", "image": f"data:image/png;base64,{image_base64}"}],
        }
    ]

    images_with_pii = [(image_bytes, {"email": [("[email_detected_in_image]", 0, 1)]})]
    pii_types_to_mask = {"email"}

    redacted_bytes = b"redacted_image_data"
    with patch("ceil_dlp.middleware.redact_image", return_value=redacted_bytes):
        modified = handler._redact_images_in_messages(messages, images_with_pii, pii_types_to_mask)

        # Check that image was replaced
        image_item = modified[0]["content"][0]
        assert image_item["type"] == "image"
        redacted_base64 = base64.b64encode(redacted_bytes).decode("utf-8")
        assert redacted_base64 in image_item["image"]


@pytest.mark.asyncio
async def test_middleware_image_redaction_bytes_format():
    """Test image redaction with bytes image data."""
    from ceil_dlp.utils import create_image_with_text

    handler = CeilDLPHandler()
    image_bytes = create_image_with_text("Contact: john@example.com")

    messages = [{"role": "user", "content": [{"type": "image", "image": image_bytes}]}]

    images_with_pii = [(image_bytes, {"email": [("[email_detected_in_image]", 0, 1)]})]
    pii_types_to_mask = {"email"}

    redacted_bytes = b"redacted_image_data"
    with patch("ceil_dlp.middleware.redact_image", return_value=redacted_bytes):
        modified = handler._redact_images_in_messages(messages, images_with_pii, pii_types_to_mask)

        # Check that image was replaced with base64 data URL
        image_item = modified[0]["content"][0]
        assert image_item["type"] == "image"
        assert isinstance(image_item["image"], str)
        assert "data:image/png;base64," in image_item["image"]


@pytest.mark.asyncio
async def test_middleware_image_redaction_error_handling():
    """Test image redaction error handling."""
    import base64

    from ceil_dlp.utils import create_image_with_text

    handler = CeilDLPHandler()
    image_bytes = create_image_with_text("Contact: john@example.com")
    image_base64 = base64.b64encode(image_bytes).decode("utf-8")

    messages = [
        {
            "role": "user",
            "content": [
                {
                    "type": "image_url",
                    "image_url": {"url": f"data:image/png;base64,{image_base64}"},
                }
            ],
        }
    ]

    images_with_pii = [(image_bytes, {"email": [("[email_detected_in_image]", 0, 1)]})]
    pii_types_to_mask = {"email"}

    # Mock redact_image to raise an error
    with patch("ceil_dlp.middleware.redact_image", side_effect=Exception("Redaction failed")):
        # Should not crash, should return original messages
        modified = handler._redact_images_in_messages(messages, images_with_pii, pii_types_to_mask)
        # Original messages should be preserved on error
        assert len(modified) == len(messages)


@pytest.mark.asyncio
async def test_middleware_image_redaction_invalid_base64():
    """Test image redaction with invalid base64 data."""
    handler = CeilDLPHandler()
    messages = [
        {
            "role": "user",
            "content": [
                {
                    "type": "image_url",
                    "image_url": {"url": "data:image/png;base64,invalid_base64!!!"},
                }
            ],
        }
    ]

    images_with_pii: list[tuple[bytes, dict[str, list[tuple[str, int, int]]]]] = []
    pii_types_to_mask: set[str] = set()

    # Should handle invalid base64 gracefully
    modified = handler._redact_images_in_messages(messages, images_with_pii, pii_types_to_mask)
    assert modified == messages


@pytest.mark.asyncio
async def test_middleware_pre_call_hook_with_image_pii():
    """Test pre_call_hook with image containing PII."""
    import base64

    from ceil_dlp.utils import create_image_with_text

    handler = CeilDLPHandler()
    # Create image with email
    image_bytes = create_image_with_text("Contact: john@example.com")
    image_base64 = base64.b64encode(image_bytes).decode("utf-8")

    messages = [
        {
            "role": "user",
            "content": [
                {"type": "text", "text": "What's in this image?"},
                {
                    "type": "image_url",
                    "image_url": {"url": f"data:image/png;base64,{image_base64}"},
                },
            ],
        }
    ]

    data = {
        "model": "gpt-4",
        "messages": messages,
        "litellm_call_id": "test123",
    }

    # Mock image detection
    with patch(
        "ceil_dlp.middleware.detect_pii_in_image",
        return_value={"email": [("[email_detected_in_image]", 0, 1)]},
    ):
        # Mock redact_image to return modified bytes
        redacted_bytes = b"redacted"
        with patch("ceil_dlp.middleware.redact_image", return_value=redacted_bytes):
            result = await handler.async_pre_call_hook(
                user_api_key_dict=None,
                cache=None,
                data=data,
                call_type="completion",
            )

            # Should mask email (default policy is mask for email)
            assert isinstance(result, dict)
            # Image should be redacted in the result
            result_messages = result.get("messages", [])
            assert len(result_messages) > 0
            # Check that image URL was modified (contains redacted base64)
            image_item = result_messages[0]["content"][1]
            redacted_base64 = base64.b64encode(redacted_bytes).decode("utf-8")
            assert redacted_base64 in image_item["image_url"]["url"]


@pytest.mark.asyncio
async def test_middleware_pre_call_hook_image_blocked():
    """Test pre_call_hook blocking request when image contains blocked PII."""
    import base64

    from ceil_dlp.config import Config
    from ceil_dlp.utils import create_image_with_text

    # Configure to block credit cards
    config = Config()
    config.policies["credit_card"].action = "block"
    handler = CeilDLPHandler(config=config)

    image_bytes = create_image_with_text("Card: 4111111111111111")
    image_base64 = base64.b64encode(image_bytes).decode("utf-8")

    messages = [
        {
            "role": "user",
            "content": [
                {
                    "type": "image_url",
                    "image_url": {"url": f"data:image/png;base64,{image_base64}"},
                }
            ],
        }
    ]

    data = {"model": "gpt-4", "messages": messages, "litellm_call_id": "test123"}

    # Mock image detection to find credit card
    with patch(
        "ceil_dlp.middleware.detect_pii_in_image",
        return_value={"credit_card": [("[credit_card_detected_in_image]", 0, 1)]},
    ):
        result = await handler.async_pre_call_hook(
            user_api_key_dict=None,
            cache=None,
            data=data,
            call_type="completion",
        )

        # Should block the request
        assert isinstance(result, str)
        assert "blocked" in result.lower()
        assert "credit_card" in result.lower()
