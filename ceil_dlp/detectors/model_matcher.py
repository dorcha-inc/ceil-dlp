"""Model matching utility for model-aware policies."""

import logging
import re

logger = logging.getLogger(__name__)


def matches_model(model: str, pattern: str) -> bool:
    """
    Check if model name matches pattern (exact match or regex).

    Args:
        model: Model name to check
        pattern: Pattern to match (exact string or regex)

    Returns:
        True if model matches pattern
    """
    # Check if pattern contains regex special characters
    regex_chars = r"[*?.^$\[\](){}|+]"

    if not re.search(regex_chars, pattern):
        return model == pattern

    try:
        return bool(re.match(pattern, model))
    except re.error as e:
        logger.debug("invalid regular expression pattern: %s: %s", pattern, e)
        return False
