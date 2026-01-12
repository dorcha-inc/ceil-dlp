"""ceil-dlp: Data Loss Prevention plugin for LiteLLM."""

import os
from typing import Literal, cast

from ceil_dlp.middleware import CeilDLPHandler, create_handler

__version__ = "1.0.0"
__all__ = ["CeilDLPHandler", "create_handler", "setup_litellm"]

Mode = Literal["observe", "warn", "enforce"]


def setup_litellm(
    mode: Mode | None = None,
    config_path: str | None = None,
    **kwargs,
) -> dict:
    """
    Drop-in setup for LiteLLM proxy - makes ceil-dlp zero-friction to use.

    Usage:
        # In your LiteLLM config.yaml or Python code:
        from ceil_dlp import setup_litellm

        # Option 1: Simplest - just enable with defaults
        litellm_config = setup_litellm()

        # Option 2: Set mode
        litellm_config = setup_litellm(mode="observe")

        # Option 3: Use config file
        litellm_config = setup_litellm(config_path="/path/to/ceil-dlp.yaml")

    Args:
        mode: Operational mode (observe/warn/enforce).
              Defaults to CEIL_DLP_MODE env var or "enforce"
        config_path: Path to ceil-dlp config YAML file (optional)
        **kwargs: Additional config parameters (passed to Config.from_dict)

    Returns:
        Dictionary with LiteLLM configuration to add to your config:
        {
            "general_settings": {
                "custom_callback": "ceil_dlp.CeilDLPHandler",
                "custom_callback_params": {...}
            }
        }
    """
    # Determine mode from parameter, env var, or default
    if mode is None:
        env_mode_str = os.getenv("CEIL_DLP_MODE", "enforce")
        mode = cast(Mode | None, env_mode_str)

    # Build callback params
    callback_params: dict = {}

    if config_path:
        callback_params["config_path"] = config_path
    elif kwargs or mode != "enforce":
        # Only pass params if we have custom settings
        if mode != "enforce":
            callback_params["mode"] = mode
        if kwargs:
            callback_params.update(kwargs)

    result: dict = {
        "general_settings": {
            "custom_callback": "ceil_dlp.CeilDLPHandler",
        }
    }

    if callback_params:
        result["general_settings"]["custom_callback_params"] = callback_params

    return result
