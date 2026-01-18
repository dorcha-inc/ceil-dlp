"""ceil-dlp: Data Loss Prevention plugin for LiteLLM."""

import logging
import os
import sys

from rich.logging import RichHandler

from ceil_dlp.middleware import CeilDLPHandler, create_handler


def _setup_logger() -> None:
    """Setup the logger for ceil-dlp with pretty formatting using Rich.

    Args:
        None

    Returns:
        None
    """
    root_logger = logging.getLogger("ceil_dlp")
    if not root_logger.handlers:
        handler = RichHandler(
            rich_tracebacks=True,
            show_time=True,
            show_level=True,
            markup=True,
        )
        root_logger.addHandler(handler)
        # Prevent propagation to root logger to avoid duplicate messages
        root_logger.propagate = False

    env_log_level = os.getenv("CEIL_DLP_LOG_LEVEL", "INFO").upper()
    log_level = getattr(logging, env_log_level, None)
    if log_level is None:
        print(f"invalid ceil-dlp log level: {env_log_level}", file=sys.stderr)
        return
    root_logger.setLevel(log_level)


# Setup logger when package is imported
_setup_logger()

__all__ = [
    "CeilDLPHandler",
    "create_handler",
]
