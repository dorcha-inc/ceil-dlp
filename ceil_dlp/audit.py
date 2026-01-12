"""Secure audit logging for DLP events."""

import hashlib
import logging
from datetime import UTC, datetime
from pathlib import Path

from pythonjsonlogger import json


def hash_pii(value: str, length: int = 16) -> str:
    """
    Hash PII value for secure logging.

    Args:
        value: PII value to hash
        length: Length of the hash to return

    Returns:
        SHA256 hash of the value truncated to the given length
    """
    return hashlib.sha256(value.encode()).hexdigest()[:length]


class AuditLogger:
    """Secure audit logger for DLP events."""

    def __init__(self, log_path: str | None = None) -> None:
        """
        Initialize audit logger.

        Args:
            log_path: Path to log file. If None, logs to stdout via logging.
        """
        self.log_path = log_path
        self.logger = logging.getLogger("ceil_dlp.audit")

        # Configure logger if not already configured
        if not self.logger.handlers:
            log_path_obj = Path(log_path) if log_path else None
            self._configure_logger(log_path_obj)

        # Use JSON formatter for structured logging
        formatter = json.JsonFormatter()
        for handler in self.logger.handlers:
            handler.setFormatter(formatter)

    def _configure_logger(self, log_path: Path | None = None) -> None:
        """Configure the logger.

        Args:
            log_path: Path to log file. If None, logs to stdout via logging.
        """
        self.logger.setLevel(logging.INFO)
        self.logger.propagate = False

        if log_path:
            # Ensure directory exists
            log_path.parent.mkdir(parents=True, exist_ok=True)
            # File handler for audit logs
            file_handler = logging.FileHandler(log_path, mode="a")
            file_handler.setLevel(logging.INFO)
            self.logger.addHandler(file_handler)
            return

        # Stream handler for stdout
        stream_handler = logging.StreamHandler()
        stream_handler.setLevel(logging.INFO)
        self.logger.addHandler(stream_handler)

    def log_detection(
        self,
        user_id: str | None,
        pii_type: str,
        action: str,
        redacted_items: list[str],
        request_id: str | None = None,
        mode: str | None = None,
    ) -> None:
        """
        Log a PII detection event.

        Args:
            user_id: User identifier (if available)
            pii_type: Type of PII detected
            action: Action taken (block/mask/observe/warn)
            redacted_items: List of detected PII values (will be hashed)
            request_id: Request identifier (if available)
            mode: Operational mode (observe/warn/enforce)
        """
        hashed_items = [hash_pii(item, length=16) for item in redacted_items]

        # Use extra parameter to pass structured data to JSON logger
        extra_data = {
            "timestamp": datetime.now(UTC).isoformat(),
            "user_id": user_id,
            "request_id": request_id,
            "pii_type": pii_type,
            "action": action,
            "hashed_pii": hashed_items,
            "count": len(redacted_items),
        }
        if mode:
            extra_data["mode"] = mode

        self.logger.info("PII detection event", extra=extra_data)

    def log_block(
        self,
        user_id: str | None,
        pii_types: list[str],
        request_id: str | None = None,
        mode: str | None = None,
    ) -> None:
        """
        Log a blocked request.

        Args:
            user_id: User identifier
            pii_types: List of PII types that caused the block
            request_id: Request identifier
            mode: Operational mode (observe/warn/enforce)
        """
        # Use extra parameter to pass structured data to JSON logger
        extra_data = {
            "timestamp": datetime.now(UTC).isoformat(),
            "user_id": user_id,
            "request_id": request_id,
            "action": "blocked",
            "pii_types": pii_types,
        }
        if mode:
            extra_data["mode"] = mode

        self.logger.info("Request blocked", extra=extra_data)
