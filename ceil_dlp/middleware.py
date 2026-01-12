"""LiteLLM middleware implementation for ceil-dlp."""

import logging
import os
from pathlib import Path
from typing import Any

from litellm import CustomLogger

from ceil_dlp.audit import AuditLogger
from ceil_dlp.config import Config, Policy
from ceil_dlp.detectors.image_detector import detect_pii_in_image
from ceil_dlp.detectors.model_matcher import matches_model
from ceil_dlp.detectors.pii_detector import PIIDetector
from ceil_dlp.redaction import apply_redaction

logger = logging.getLogger(__name__)


def create_handler(config_path: str | None = None, **kwargs) -> "CeilDLPHandler":
    """
    Factory function to create CeilDLPHandler from LiteLLM config.

    Args:
        config_path: Path to YAML config file (optional)
        **kwargs: Additional config parameters

    Returns:
        CeilDLPHandler instance
    """
    if config_path and os.path.exists(config_path):
        config = Config.from_yaml(config_path)
    elif kwargs:
        config = Config.from_dict(kwargs)
    else:
        config = Config()

    return CeilDLPHandler(config=config)


class CeilDLPHandler(CustomLogger):
    """LiteLLM custom logger that implements DLP functionality."""

    def __init__(self, config: Config | None = None, config_path: Path | None = None) -> None:
        """
        Initialize CeilDLP handler.

        Args:
            config: Configuration instance. If None, uses defaults or loads from config_path.
            config_path: Path to YAML config file (alternative to passing config directly).
        """
        super().__init__()
        if config:
            self.config = config
        elif config_path and config_path.is_file():
            self.config = Config.from_yaml(config_path)
        else:
            self.config = Config()

        # Convert list to set for PIIDetector
        enabled_types = (
            set(self.config.enabled_pii_types) if self.config.enabled_pii_types else None
        )
        self.detector = PIIDetector(enabled_types=enabled_types)
        self.audit_logger = AuditLogger(log_path=self.config.audit_log_path)

    def _should_apply_policy(self, policy: Policy, model: str) -> bool:
        """
        Determine if policy should apply to this model.

        Args:
            policy: Policy to check
            model: Model name to check against

        Returns:
            True if policy should apply, False otherwise
        """
        if policy.models is None:
            return True  # Apply to all models (backward compatible)

        # Check block list first (explicit blocks take precedence)
        if policy.models.block:
            for pattern in policy.models.block:
                if matches_model(model, pattern):
                    return True  # Block this model, apply policy

        # Check allow list (explicit allows override)
        if policy.models.allow:
            for pattern in policy.models.allow:
                if matches_model(model, pattern):
                    return False  # Allow this model, skip policy

        # Default: if block list exists but no match, don't apply
        # If only allow list exists and no match, apply policy
        return policy.models.block is None  # Block list exists but no match -> False, else True

    def _pre_call_hook(
        self,
        user_id: str,
        _model: str,
        messages: list[Any],
        kwargs: dict[str, Any],
    ) -> tuple[str | None, dict[str, Any] | None]:
        """
        Internal pre-call hook implementation.

        Detects PII in request messages and applies policies (block/mask).
        This is a synchronous method called by the async wrapper.

        Args:
            user_id: User identifier
            _model: Model name (unused)
            messages: List of messages in the request
            kwargs: Additional arguments (may be modified in-place)

        Returns:
            Tuple of (error_message, modified_kwargs)
            If error_message is not None, the request should be blocked.
        """
        # Extract text and images from messages
        text_content = self._extract_text_from_messages(messages)
        images = self._extract_images_from_messages(messages)

        # Detect PII in text
        detections = self.detector.detect(text_content) if text_content else {}

        # Detect PII in images
        if images:
            enabled_types = (
                set(self.config.enabled_pii_types) if self.config.enabled_pii_types else None
            )
            for image_data in images:
                image_detections = detect_pii_in_image(image_data, enabled_types=enabled_types)
                # Merge image detections with text detections
                for pii_type, matches in image_detections.items():
                    if pii_type not in detections:
                        detections[pii_type] = []
                    detections[pii_type].extend(matches)

        if not detections:
            # No PII detected, allow request
            return None, kwargs

        if not detections:
            # No PII detected, allow request
            return None, kwargs

        # Get current mode
        mode = self.config.mode

        # Check policies and determine actions
        blocked_types = []
        masked_types = {}

        for pii_type, matches in detections.items():
            policy = self.config.get_policy(pii_type)
            if not policy or not policy.enabled:
                continue

            # Check model-aware policy
            if not self._should_apply_policy(policy, _model):
                continue  # Skip this policy for this model

            if policy.action == "block":
                blocked_types.append(pii_type)
            elif policy.action == "mask":
                masked_types[pii_type] = matches

        # Handle based on mode
        if mode == "observe":
            # Observe mode: log all detections but never block or mask
            for pii_type, matches in detections.items():
                policy = self.config.get_policy(pii_type)
                if policy and policy.enabled:
                    # Check model-aware policy
                    if not self._should_apply_policy(policy, _model):
                        continue  # Skip this policy for this model
                    matched_texts = [match[0] for match in matches]
                    self.audit_logger.log_detection(
                        user_id=user_id,
                        pii_type=pii_type,
                        action="observe",
                        redacted_items=matched_texts,
                        request_id=kwargs.get("litellm_call_id"),
                        mode=mode,
                    )
            # Always allow request in observe mode
            return None, kwargs

        elif mode == "warn":
            # Warn mode: apply masking but never block, add warning header
            if masked_types:
                redacted_text, redacted_items = apply_redaction(text_content, masked_types)

                # Update messages with redacted text
                modified_messages = self._replace_text_in_messages(
                    messages, text_content, redacted_text
                )
                kwargs["messages"] = modified_messages

                # Log the masking
                for pii_type, items in redacted_items.items():
                    self.audit_logger.log_detection(
                        user_id=user_id,
                        pii_type=pii_type,
                        action="mask",
                        redacted_items=items,
                        request_id=kwargs.get("litellm_call_id"),
                        mode=mode,
                    )

            # Log blocked types as warnings (but don't block)
            if blocked_types:
                for pii_type in blocked_types:
                    matches = detections[pii_type]
                    matched_texts = [match[0] for match in matches]
                    self.audit_logger.log_detection(
                        user_id=user_id,
                        pii_type=pii_type,
                        action="warn",
                        redacted_items=matched_texts,
                        request_id=kwargs.get("litellm_call_id"),
                        mode=mode,
                    )

            # Add warning header if any violations detected
            if blocked_types or masked_types:
                # Try to add warning header via kwargs
                # LiteLLM may support custom headers
                if "extra_headers" not in kwargs:
                    kwargs["extra_headers"] = {}
                kwargs["extra_headers"]["X-Ceil-DLP-Warning"] = "violations_detected"

            # Always allow request in warn mode
            return None, kwargs

        else:  # enforce mode (default)
            # Enforce mode: block and mask according to policies
            if blocked_types:
                self.audit_logger.log_block(
                    user_id=user_id,
                    pii_types=blocked_types,
                    request_id=kwargs.get("litellm_call_id"),
                    mode=mode,
                )
                return (
                    f"Request blocked: Detected sensitive data ({', '.join(blocked_types)})",
                    None,
                )

            # Apply masking for medium-risk PII
            if masked_types:
                redacted_text, redacted_items = apply_redaction(text_content, masked_types)

                # Update messages with redacted text
                modified_messages = self._replace_text_in_messages(
                    messages, text_content, redacted_text
                )
                kwargs["messages"] = modified_messages

                # Log the masking
                for pii_type, items in redacted_items.items():
                    self.audit_logger.log_detection(
                        user_id=user_id,
                        pii_type=pii_type,
                        action="mask",
                        redacted_items=items,
                        request_id=kwargs.get("litellm_call_id"),
                        mode=mode,
                    )

            return None, kwargs

    async def async_pre_call_hook(  # type: ignore[override]
        self,
        user_id: str,
        _model: str,
        messages: list[Any],
        kwargs: dict[str, Any],
    ) -> tuple[str | None, dict[str, Any] | None]:
        """
        Hook called before LLM API call. Detects and handles PII.

        Args:
            user_id: User identifier
            model: Model name
            messages: List of messages in the request
            kwargs: Additional arguments

        Returns:
            Tuple of (error_message, modified_kwargs)
            If error_message is not None, the request is blocked.
        """
        try:
            return self._pre_call_hook(user_id, _model, messages, kwargs)

        except Exception as e:
            # Fail-safe: log error but don't block request
            logger.error(f"CeilDLP error in pre_call_hook: {e}", exc_info=True)
            return None, kwargs

    async def async_post_call_success_hook(  # type: ignore[override]
        self,
        user_id: str,  # noqa: ARG002
        model: str,  # noqa: ARG002
        messages: list[Any],  # noqa: ARG002
        kwargs: dict[str, Any],  # noqa: ARG002
        response: Any,  # noqa: ARG002
    ) -> dict[str, Any] | None:
        """
        Hook called after successful LLM response.

        Currently a no-op. Reserved for future DLP features like deanonymization
        (reversing pseudonyms in responses).

        Args:
            user_id: User identifier
            model: Model name
            messages: Original messages
            kwargs: Request arguments
            response: LLM response

        Returns:
            None (no modifications to response)
        """
        # Note(jadidbourbaki): noop for now, the plan is to add something like Whistledown here [1].
        # [1]: https://arxiv.org/pdf/2511.13319
        return None

    def _extract_text_from_messages(self, messages: list[Any]) -> str:
        """Extract text content from LiteLLM messages format."""
        text_parts = []
        for msg in messages:
            if isinstance(msg, dict):
                content = msg.get("content")
                if content is None:
                    continue
                if isinstance(content, str):
                    if content:  # Only add non-empty strings
                        text_parts.append(content)
                elif isinstance(content, list):
                    # Handle multimodal content (OpenAI format)
                    for item in content:
                        if isinstance(item, dict) and item.get("type") == "text":
                            text_value = item.get("text", "")
                            if text_value:  # Only add non-empty text
                                text_parts.append(text_value)
            elif isinstance(msg, str):
                if msg:  # Only add non-empty strings
                    text_parts.append(msg)

        return " ".join(text_parts)

    def _extract_images_from_messages(self, messages: list[Any]) -> list[bytes]:
        """
        Extract images from LiteLLM messages format.

        Supports:
        - Base64-encoded images (data:image/...;base64,...)
        - Image URLs (will need to be downloaded, not implemented yet)

        Args:
            messages: List of messages in LiteLLM format

        Returns:
            List of image data as bytes
        """
        import base64

        images: list[bytes] = []

        for msg in messages:
            if isinstance(msg, dict):
                content = msg.get("content")
                if content is None:
                    continue
                if isinstance(content, list):
                    # Handle multimodal content (OpenAI format)
                    for item in content:
                        if isinstance(item, dict):
                            item_type = item.get("type")
                            if item_type == "image_url":
                                # OpenAI format: {"type": "image_url", "image_url": {"url": "..."}}
                                image_url_data = item.get("image_url", {})
                                url = (
                                    image_url_data.get("url", "")
                                    if isinstance(image_url_data, dict)
                                    else ""
                                )
                                if url.startswith("data:image"):
                                    # Base64-encoded image
                                    try:
                                        # Extract base64 data (format: data:image/png;base64,<data>)
                                        header, data = url.split(",", 1)
                                        image_bytes = base64.b64decode(data)
                                        images.append(image_bytes)
                                    except Exception as e:
                                        logger.warning(f"Failed to decode base64 image: {e}")
                                # TODO: Support image URLs (would need to download)
                            elif item_type == "image":
                                # Direct image data
                                image_data = item.get("image", "")
                                if isinstance(image_data, bytes):
                                    images.append(image_data)
                                elif isinstance(image_data, str) and image_data.startswith(
                                    "data:image"
                                ):
                                    try:
                                        header, data = image_data.split(",", 1)
                                        image_bytes = base64.b64decode(data)
                                        images.append(image_bytes)
                                    except Exception as e:
                                        logger.warning(f"Failed to decode base64 image: {e}")

        return images

    def _replace_text_in_messages(
        self, messages: list[Any], old_text: str, new_text: str
    ) -> list[Any]:
        """Replace text in messages while preserving structure."""
        modified = []
        for msg in messages:
            if isinstance(msg, dict):
                new_msg = msg.copy()
                content = msg.get("content", "")
                if isinstance(content, str):
                    new_msg["content"] = content.replace(old_text, new_text)
                elif isinstance(content, list):
                    # Handle multimodal content
                    new_content = []
                    for item in content:
                        if isinstance(item, dict) and item.get("type") == "text":
                            new_item = item.copy()
                            new_item["text"] = item.get("text", "").replace(old_text, new_text)
                            new_content.append(new_item)
                        else:
                            new_content.append(item)
                    new_msg["content"] = new_content
                modified.append(new_msg)
            else:
                # String message - convert to dict format
                modified.append({"content": str(msg).replace(old_text, new_text)})

        return modified
