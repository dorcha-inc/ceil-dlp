"""Tests for audit logging."""

import logging
from pathlib import Path
from unittest.mock import patch

from ceil_dlp.audit import AuditLogger, hash_pii


def test_hash_pii():
    """Test PII hashing function."""
    value = "test@example.com"
    hashed = hash_pii(value)
    assert len(hashed) == 16
    assert isinstance(hashed, str)
    assert hashed.isalnum() or all(c in "0123456789abcdef" for c in hashed)

    # Test with custom length
    hashed_long = hash_pii(value, length=32)
    assert len(hashed_long) == 32

    # Test that same value produces same hash
    hashed2 = hash_pii(value)
    assert hashed == hashed2


def test_audit_logger_init_without_path():
    """Test AuditLogger initialization without log path (stdout)."""
    logger = AuditLogger()
    assert logger.log_path is None
    assert len(logger.logger.handlers) > 0
    # Should have StreamHandler
    assert any(isinstance(h, logging.StreamHandler) for h in logger.logger.handlers)


def test_audit_logger_init_with_path(tmp_path: Path):
    """Test AuditLogger initialization with log path."""
    log_file = tmp_path / "audit.log"
    # Clear any existing handlers to test fresh initialization
    logging.getLogger("ceil_dlp.audit").handlers.clear()
    logger = AuditLogger(log_path=str(log_file))
    assert logger.log_path == str(log_file)
    assert log_file.parent.exists()
    assert any(isinstance(h, logging.FileHandler) for h in logger.logger.handlers)


def test_audit_logger_log_detection():
    """Test logging PII detection events."""
    logger = AuditLogger()
    # Mock the logger.info to capture calls
    with patch.object(logger.logger, "info") as mock_info:
        logger.log_detection(
            user_id="user123",
            pii_type="email",
            action="mask",
            redacted_items=["john@example.com", "jane@example.com"],
            request_id="req456",
        )
        mock_info.assert_called_once()
        call_args = mock_info.call_args
        assert call_args[0][0] == "PII detection event"
        extra = call_args[1]["extra"]
        assert extra["user_id"] == "user123"
        assert extra["pii_type"] == "email"
        assert extra["action"] == "mask"
        assert len(extra["hashed_pii"]) == 2
        assert extra["count"] == 2


def test_audit_logger_log_detection_no_user_id():
    """Test logging PII detection without user_id."""
    logger = AuditLogger()
    with patch.object(logger.logger, "info") as mock_info:
        logger.log_detection(
            user_id=None,
            pii_type="credit_card",
            action="block",
            redacted_items=["4111111111111111"],
        )
        mock_info.assert_called_once()
        extra = mock_info.call_args[1]["extra"]
        assert extra["user_id"] is None


def test_audit_logger_log_block():
    """Test logging blocked requests."""
    logger = AuditLogger()
    with patch.object(logger.logger, "info") as mock_info:
        logger.log_block(
            user_id="user123",
            pii_types=["credit_card", "ssn"],
            request_id="req789",
        )
        mock_info.assert_called_once()
        call_args = mock_info.call_args
        assert call_args[0][0] == "Request blocked"
        extra = call_args[1]["extra"]
        assert extra["user_id"] == "user123"
        assert extra["action"] == "blocked"
        assert extra["pii_types"] == ["credit_card", "ssn"]


def test_audit_logger_log_to_file(tmp_path: Path):
    """Test that audit logger writes to file."""
    log_file = tmp_path / "audit.log"
    # Clear any existing handlers
    logging.getLogger("ceil_dlp.audit").handlers.clear()
    logger = AuditLogger(log_path=str(log_file))

    logger.log_detection(
        user_id="user123",
        pii_type="email",
        action="mask",
        redacted_items=["test@example.com"],
    )

    # Force flush and close handlers
    for handler in logger.logger.handlers:
        handler.flush()
        handler.close()

    assert log_file.exists()
    content = log_file.read_text()
    assert "PII detection event" in content
    assert "user123" in content
