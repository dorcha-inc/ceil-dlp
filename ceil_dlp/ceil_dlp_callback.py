"""Callback module for LiteLLM integration.

This module exports a handler instance that LiteLLM can import.
"""

import os
from pathlib import Path

from ceil_dlp.middleware import CeilDLPHandler, create_handler

# Create handler instance for LiteLLM
# Users can override by setting CEIL_DLP_CONFIG_PATH environment variable
_config_path = os.getenv("CEIL_DLP_CONFIG_PATH")
if _config_path and Path(_config_path).is_file():
    proxy_handler_instance = create_handler(config_path=_config_path)
else:
    proxy_handler_instance = CeilDLPHandler()
