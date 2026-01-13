"""Tests for ceil_dlp_callback module."""

import importlib

from ceil_dlp.ceil_dlp_callback import proxy_handler_instance
from ceil_dlp.middleware import CeilDLPHandler


def test_callback_module_default_handler():
    """Test that callback module exports a handler instance."""
    assert proxy_handler_instance is not None
    assert isinstance(proxy_handler_instance, CeilDLPHandler)


def test_callback_module_with_config_path(tmp_path, monkeypatch):
    """Test callback module with CEIL_DLP_CONFIG_PATH set."""
    # Create a test config file
    config_file = tmp_path / "test_config.yaml"
    config_file.write_text(
        "mode: observe\npolicies:\n  email:\n    action: mask\n    enabled: true\n"
    )

    # Set environment variable
    monkeypatch.setenv("CEIL_DLP_CONFIG_PATH", str(config_file))

    # Reload the module to pick up the new env var
    import ceil_dlp.ceil_dlp_callback

    importlib.reload(ceil_dlp.ceil_dlp_callback)

    # Check that handler was created with config
    handler = ceil_dlp.ceil_dlp_callback.proxy_handler_instance
    assert handler.config.mode == "observe"
    email_policy = handler.config.get_policy("email")
    assert email_policy is not None
    assert email_policy.action == "mask"

    # Clean up - restore original
    monkeypatch.delenv("CEIL_DLP_CONFIG_PATH", raising=False)
    importlib.reload(ceil_dlp.ceil_dlp_callback)


def test_callback_module_with_invalid_config_path(monkeypatch):
    """Test callback module with invalid CEIL_DLP_CONFIG_PATH."""
    # Set environment variable to non-existent file
    monkeypatch.setenv("CEIL_DLP_CONFIG_PATH", "/nonexistent/path.yaml")

    # Reload the module
    import ceil_dlp.ceil_dlp_callback

    importlib.reload(ceil_dlp.ceil_dlp_callback)

    # Should fall back to default handler
    handler = ceil_dlp.ceil_dlp_callback.proxy_handler_instance
    assert isinstance(handler, CeilDLPHandler)
    # Should use default config (enforce mode)
    assert handler.config.mode == "enforce"

    # Clean up
    monkeypatch.delenv("CEIL_DLP_CONFIG_PATH", raising=False)
    importlib.reload(ceil_dlp.ceil_dlp_callback)
