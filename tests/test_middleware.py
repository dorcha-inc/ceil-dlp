"""Tests for middleware/LiteLLM integration."""

from typing import Any
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


def test_middleware_pre_call_hook_no_pii():
    """Test pre-call hook with no PII detected."""
    handler = CeilDLPHandler()
    messages = [{"role": "user", "content": "Hello world"}]
    kwargs = {"litellm_call_id": "test123"}

    error, modified_kwargs = handler._pre_call_hook(
        user_id="user1", _model="gpt-4", messages=messages, kwargs=kwargs
    )
    assert error is None
    assert modified_kwargs == kwargs


def test_middleware_pre_call_hook_blocked_pii():
    """Test pre-call hook blocking high-risk PII."""
    handler = CeilDLPHandler()
    messages = [{"role": "user", "content": "My credit card is 4111111111111111"}]
    kwargs = {"litellm_call_id": "test123"}

    error, modified_kwargs = handler._pre_call_hook(
        user_id="user1", _model="gpt-4", messages=messages, kwargs=kwargs
    )
    assert error is not None
    assert "blocked" in error.lower()
    assert modified_kwargs is None


def test_middleware_pre_call_hook_masked_pii():
    """Test pre-call hook masking medium-risk PII."""
    handler = CeilDLPHandler()
    messages = [{"role": "user", "content": "My email is john@example.com"}]
    kwargs = {"messages": messages, "litellm_call_id": "test123"}

    error, modified_kwargs = handler._pre_call_hook(
        user_id="user1", _model="gpt-4", messages=messages, kwargs=kwargs
    )
    assert error is None
    assert modified_kwargs is not None
    # Check that messages were modified
    assert "[REDACTED_EMAIL]" in str(modified_kwargs.get("messages", []))


@pytest.mark.asyncio
async def test_middleware_async_pre_call_hook():
    """Test async pre-call hook wrapper."""
    handler = CeilDLPHandler()
    messages = [{"role": "user", "content": "Hello"}]
    kwargs: dict[str, Any] = {}

    # Test that it calls the sync method
    error, modified_kwargs = await handler.async_pre_call_hook(
        user_id="user1", _model="gpt-4", messages=messages, kwargs=kwargs
    )
    # Should return None error and same kwargs for normal text
    assert error is None
    assert modified_kwargs == kwargs


def test_middleware_pre_call_hook_empty_text():
    """Test pre-call hook with empty text content."""
    handler = CeilDLPHandler()
    messages = [{"role": "user", "content": None}]
    kwargs = {"litellm_call_id": "test123"}

    error, modified_kwargs = handler._pre_call_hook(
        user_id="user1", _model="gpt-4", messages=messages, kwargs=kwargs
    )
    assert error is None
    assert modified_kwargs == kwargs


def test_middleware_pre_call_hook_disabled_policy():
    """Test pre-call hook with disabled policy."""
    config = Config()
    config.policies["email"].enabled = False
    handler = CeilDLPHandler(config=config)
    messages = [{"role": "user", "content": "My email is john@example.com"}]
    kwargs = {"litellm_call_id": "test123"}

    error, modified_kwargs = handler._pre_call_hook(
        user_id="user1", _model="gpt-4", messages=messages, kwargs=kwargs
    )
    # Should not block or mask since policy is disabled
    assert error is None
    assert modified_kwargs == kwargs


def test_middleware_pre_call_hook_no_policy():
    """Test pre-call hook with PII type that has no policy."""
    handler = CeilDLPHandler()
    # Use a detector that finds something not in default policies
    messages = [{"role": "user", "content": "test"}]
    kwargs = {"litellm_call_id": "test123"}

    error, modified_kwargs = handler._pre_call_hook(
        user_id="user1", _model="gpt-4", messages=messages, kwargs=kwargs
    )
    assert error is None


@pytest.mark.asyncio
async def test_middleware_async_pre_call_hook_exception():
    """Test async pre-call hook exception handling."""

    handler = CeilDLPHandler()
    messages = [{"role": "user", "content": "Hello"}]
    kwargs: dict[str, Any] = {}

    # Mock _pre_call_hook to raise an exception
    with patch.object(handler, "_pre_call_hook", side_effect=Exception("Test error")):
        error, modified_kwargs = await handler.async_pre_call_hook(
            user_id="user1", _model="gpt-4", messages=messages, kwargs=kwargs
        )
        # Should return None error and original kwargs on exception
        assert error is None
        assert modified_kwargs == kwargs


@pytest.mark.asyncio
async def test_middleware_async_post_call_success_hook():
    """Test async post-call success hook."""
    handler = CeilDLPHandler()
    result = await handler.async_post_call_success_hook(
        user_id="user1",
        model="gpt-4",
        messages=[{"role": "user", "content": "Hello"}],
        kwargs={},
        response={"content": "Hi"},
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


def test_middleware_mode_observe():
    """Test observe mode: log but never block or mask."""
    config = Config(mode="observe")
    handler = CeilDLPHandler(config=config)
    messages = [{"role": "user", "content": "My credit card is 4111111111111111"}]
    kwargs = {"litellm_call_id": "test123"}

    error, modified_kwargs = handler._pre_call_hook(
        user_id="user1", _model="gpt-4", messages=messages, kwargs=kwargs
    )
    # Should not block in observe mode
    assert error is None
    assert modified_kwargs == kwargs


def test_middleware_mode_warn():
    """Test warn mode: mask but never block, add warning header."""
    config = Config(mode="warn")
    handler = CeilDLPHandler(config=config)
    messages = [{"role": "user", "content": "My email is john@example.com"}]
    kwargs = {"litellm_call_id": "test123"}

    error, modified_kwargs = handler._pre_call_hook(
        user_id="user1", _model="gpt-4", messages=messages, kwargs=kwargs
    )
    # Should not block in warn mode
    assert error is None
    assert modified_kwargs is not None
    # Should have warning header
    assert "extra_headers" in modified_kwargs
    assert modified_kwargs["extra_headers"]["X-Ceil-DLP-Warning"] == "violations_detected"


def test_middleware_mode_warn_blocked_type():
    """Test warn mode with blocked type: log warning but don't block."""
    config = Config(mode="warn")
    handler = CeilDLPHandler(config=config)
    messages = [{"role": "user", "content": "My credit card is 4111111111111111"}]
    kwargs = {"litellm_call_id": "test123"}

    error, modified_kwargs = handler._pre_call_hook(
        user_id="user1", _model="gpt-4", messages=messages, kwargs=kwargs
    )
    # Should not block even for blocked types in warn mode
    assert error is None
    assert modified_kwargs == kwargs
    # Should have warning header
    assert "extra_headers" in modified_kwargs
    assert modified_kwargs["extra_headers"]["X-Ceil-DLP-Warning"] == "violations_detected"


def test_middleware_mode_enforce():
    """Test enforce mode: block and mask according to policies."""
    config = Config(mode="enforce")
    handler = CeilDLPHandler(config=config)
    messages = [{"role": "user", "content": "My credit card is 4111111111111111"}]
    kwargs = {"litellm_call_id": "test123"}

    error, modified_kwargs = handler._pre_call_hook(
        user_id="user1", _model="gpt-4", messages=messages, kwargs=kwargs
    )
    # Should block in enforce mode
    assert error is not None
    assert "blocked" in error.lower()


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


def test_middleware_model_aware_policy_allow_list():
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
    error, _ = handler._pre_call_hook("user1", "openai/gpt-4", messages, {})
    assert error is None  # Request should be allowed


def test_middleware_model_aware_policy_allow_list_no_match():
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
    error, _ = handler._pre_call_hook("user1", "openai/gpt-4", messages, {})
    assert error is not None  # Request should be blocked
    assert "email" in error.lower()


def test_middleware_model_aware_policy_block_list():
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
    error, _ = handler._pre_call_hook("user1", "openai/gpt-4", messages, {})
    assert error is not None  # Request should be blocked


def test_middleware_model_aware_policy_block_list_no_match():
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
    error, _ = handler._pre_call_hook("user1", "self-hosted/llama2", messages, {})
    assert error is None  # Request should be allowed


def test_middleware_model_aware_policy_both_lists():
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
    error, _ = handler._pre_call_hook("user1", "openai/gpt-4", messages, {})
    assert error is not None  # Request should be blocked (block takes precedence)


def test_middleware_model_aware_policy_no_models_field():
    """Test policy without models field - should apply to all models (backward compatible)."""
    config = Config()
    # Default policy has no models field
    handler = CeilDLPHandler(config=config)
    messages = [{"role": "user", "content": "My credit card is 4111111111111111"}]

    # Should block regardless of model (backward compatible behavior)
    error, _ = handler._pre_call_hook("user1", "openai/gpt-4", messages, {})
    assert error is not None  # Request should be blocked


def test_middleware_model_aware_policy_regex_pattern():
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
    error1, _ = handler._pre_call_hook("user1", "self-hosted/llama2", messages, {})
    assert error1 is None  # Should allow (matches self-hosted/.*)

    error2, _ = handler._pre_call_hook("user1", "local/ollama", messages, {})
    assert error2 is None  # Should allow (matches local/.*)

    error3, _ = handler._pre_call_hook("user1", "openai/gpt-4", messages, {})
    assert error3 is not None  # Should block (doesn't match allow patterns)


def test_middleware_model_aware_policy_exact_match():
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
    error1, _ = handler._pre_call_hook("user1", "openai/gpt-4", messages, {})
    assert error1 is None  # Should allow (exact match)

    # Similar but not exact
    error2, _ = handler._pre_call_hook("user1", "openai/gpt-3.5", messages, {})
    assert error2 is not None  # Should block (not exact match)
