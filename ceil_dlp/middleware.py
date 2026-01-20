"""LiteLLM middleware implementation for ceil-dlp."""

import base64
import logging
import os
from pathlib import Path
from typing import Any, Literal

from litellm.caching.dual_cache import DualCache
from litellm.integrations.custom_logger import CustomLogger
from litellm.proxy.proxy_server import UserAPIKeyAuth

from ceil_dlp.audit import AuditLogger
from ceil_dlp.config import Config, Policy
from ceil_dlp.detectors.image_detector import detect_pii_in_image
from ceil_dlp.detectors.model_matcher import matches_model
from ceil_dlp.detectors.pdf_detector import detect_pii_in_pdf
from ceil_dlp.detectors.text_detector import detect_pii_in_text
from ceil_dlp.redaction import redact_image, redact_pdf, redact_text
from ceil_dlp.whistledown import WhistledownCache, whistledown_transform_text

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

    def __init__(
        self,
        config: Config | None = None,
        config_path: str | Path | None = None,
        **kwargs,
    ) -> None:
        """
        Initialize CeilDLP handler.

        When loaded by LiteLLM from YAML config, LiteLLM will call this with:
        CeilDLPHandler(**custom_callback_params)

        So if your YAML has:
          custom_callback_params:
            mode: observe

        LiteLLM calls: CeilDLPHandler(mode="observe")

        The **kwargs captures these parameters so we can pass them to Config.from_dict().

        Args:
            config: Configuration instance. If provided, used directly.
            config_path: Path to YAML config file. If provided, loads config from file.
            **kwargs: Parameters from custom_callback_params (e.g., mode, policies, etc.).
                     These are passed to Config.from_dict() to create the config.
        """
        super().__init__()
        if config:
            # Explicit config object takes precedence
            self.config = config
        elif config_path:
            # Load from file if path provided
            config_path_obj = Path(config_path)
            if config_path_obj.is_file():
                self.config = Config.from_yaml(config_path_obj)
            else:
                raise ValueError(f"Config file not found: {config_path}")
        elif kwargs:
            # LiteLLM passes custom_callback_params as kwargs
            # e.g., mode="observe" becomes kwargs={"mode": "observe"}
            self.config = Config.from_dict(kwargs)
        else:
            # No parameters, use defaults
            self.config = Config()

        # Store enabled_types for PII detection
        self.enabled_types = (
            set(self.config.enabled_pii_types) if self.config.enabled_pii_types else None
        )
        self.audit_logger = AuditLogger(log_path=self.config.audit_log_path)
        self.whistledown_cache = WhistledownCache()

        # Log initialization
        logger.info(
            "\n[ ceil-dlp plugin initialized ]\n",
        )

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
            return True  # No model rules specified, apply policy by default

        # Check block list first (explicit blocks take precedence)
        if policy.models.block:
            for pattern in policy.models.block:
                if matches_model(model, pattern):
                    return True  # Model matches block list, apply policy

        # Check allow list (explicit allows override policy)
        if policy.models.allow:
            for pattern in policy.models.allow:
                if matches_model(model, pattern):
                    return False  # Model matches allow list, skip policy

        # Default behavior:
        # If block list exists but model doesn't match: don't apply policy
        # If only allow list exists and model doesn't match: apply policy
        return policy.models.block is None

    def _process_pii_detection(
        self,
        messages: list[Any],
        model: str,
    ) -> tuple[
        dict[str, list[tuple[str, int, int]]],
        list[str],
        dict[str, list[tuple[str, int, int]]],
        dict[str, list[tuple[str, int, int]]],
        str,
        list[tuple[bytes, dict[str, list[tuple[str, int, int]]]]],
        list[tuple[bytes, dict[str, list[tuple[str, int, int]]]]],
    ]:
        """
        Core PII detection and policy application logic.

        Args:
            messages: List of messages to check
            model: Model name

        Returns:
            Tuple of (detections, blocked_types, masked_types, whistledown_types, text_content, images_with_pii, pdfs_with_pii)
            where images_with_pii and pdfs_with_pii are lists of (data, detections) tuples
        """
        # Extract text, images, and PDFs from messages
        text_content = self._extract_text_from_messages(messages)
        images = self._extract_images_from_messages(messages)
        pdfs = self._extract_pdfs_from_messages(messages)

        # Detect PII in text
        detections = (
            detect_pii_in_text(
                text_content,
                enabled_types=self.enabled_types,
                ner_strength=self.config.ner_strength,
            )
            if text_content
            else {}
        )

        # Detect PII in images and track which images have PII
        images_with_pii: list[tuple[bytes, dict[str, list[tuple[str, int, int]]]]] = []
        if images:
            enabled_types = (
                set(self.config.enabled_pii_types) if self.config.enabled_pii_types else None
            )
            for image_data in images:
                image_detections = detect_pii_in_image(image_data, enabled_types=enabled_types)
                if image_detections:
                    # Track this image and its detections
                    images_with_pii.append((image_data, image_detections))
                # Merge image detections with text detections
                for pii_type, matches in image_detections.items():
                    if pii_type not in detections:
                        detections[pii_type] = []
                    detections[pii_type].extend(matches)

        # Detect PII in PDFs and track which PDFs have PII
        pdfs_with_pii: list[tuple[bytes, dict[str, list[tuple[str, int, int]]]]] = []
        if pdfs:
            enabled_types = (
                set(self.config.enabled_pii_types) if self.config.enabled_pii_types else None
            )
            for pdf_data in pdfs:
                pdf_detections = detect_pii_in_pdf(pdf_data, enabled_types=enabled_types)
                if pdf_detections:
                    # Track this PDF and its detections
                    pdfs_with_pii.append((pdf_data, pdf_detections))
                # Merge PDF detections with text detections
                for pii_type, matches in pdf_detections.items():
                    if pii_type not in detections:
                        detections[pii_type] = []
                    detections[pii_type].extend(matches)

        if not detections:
            return {}, [], {}, {}, text_content, [], []

        # Check policies and determine actions
        blocked_types = []
        masked_types = {}
        whistledown_types = {}

        for pii_type, matches in detections.items():
            policy = self.config.get_policy(pii_type)
            if not policy or not policy.enabled:
                continue

            # Check model-aware policy
            if not self._should_apply_policy(policy, model):
                continue  # Skip this policy for this model

            if policy.action == "block":
                blocked_types.append(pii_type)
            elif policy.action == "mask":
                masked_types[pii_type] = matches
            elif policy.action == "whistledown":
                whistledown_types[pii_type] = matches

        return (
            detections,
            blocked_types,
            masked_types,
            whistledown_types,
            text_content,
            images_with_pii,
            pdfs_with_pii,
        )

    async def async_pre_call_hook(  # type: ignore[override]
        self,
        user_api_key_dict: UserAPIKeyAuth | None,
        cache: DualCache | None,  # noqa: ARG002
        data: dict[str, Any],
        call_type: Literal[
            "completion",
            "text_completion",
            "embeddings",
            "image_generation",
            "moderation",
            "audio_transcription",
        ],
    ) -> dict[str, Any] | str | Exception | None:
        """
        Proxy-specific hook called before LLM API call. Detects and handles PII.

        According to LiteLLM proxy documentation:
        https://docs.litellm.ai/docs/proxy/call_hooks

        Args:
            user_api_key_dict: User API key authentication info
            cache: Dual cache instance
            data: Request data dictionary containing model, messages, etc.
            call_type: Type of API call (completion, embeddings, etc.)

        Returns:
            - Modified data dict to continue with request
            - String to reject request with custom message
            - Exception to reject request with error
            - None to use original data
        """
        try:
            # Extract model and messages from data dict
            model = data.get("model", "")
            messages = data.get("messages", [])
            user_id = getattr(user_api_key_dict, "user_id", None) or data.get("user", "unknown")

            logger.debug(
                f"CeilDLP pre_call_hook called for model={model}, user_id={user_id}, call_type={call_type}"
            )

            # Only process completion calls (chat/text completions)
            # LiteLLM may pass "acompletion" (async) or "completion" (sync)
            # Check if call_type contains "completion" to handle both sync and async variants
            if "completion" not in call_type:
                logger.debug(f"Skipping non-completion call_type: {call_type}")
                return data

            # Use shared detection logic
            (
                detections,
                blocked_types,
                masked_types,
                whistledown_types,
                text_content,
                images_with_pii,
                pdfs_with_pii,
            ) = self._process_pii_detection(messages, model)

            logger.debug(
                f"CeilDLP detection results: detections={list(detections.keys())}, "
                f"blocked_types={blocked_types}, masked_types={list(masked_types.keys())}, "
                f"whistledown_types={list(whistledown_types.keys())}, "
                f"mode={self.config.mode}"
            )

            if not detections:
                # No PII detected, allow request
                logger.debug("No PII detected, allowing request")
                return data

            mode = self.config.mode

            # Handle based on mode
            if mode == "observe":
                # Observe mode: log all detections but never block or mask
                for pii_type, matches in detections.items():
                    policy = self.config.get_policy(pii_type)
                    if policy and policy.enabled:
                        # Check model-aware policy
                        if not self._should_apply_policy(policy, model):
                            continue  # Skip this policy for this model
                        matched_texts = [match[0] for match in matches]
                        self.audit_logger.log_detection(
                            user_id=user_id,
                            pii_type=pii_type,
                            action="observe",
                            redacted_items=matched_texts,
                            request_id=data.get("litellm_call_id"),
                            mode=mode,
                        )
                # Always allow request in observe mode
                return data

            else:  # enforce mode (default)
                # Enforce mode: block and mask according to policies
                if blocked_types:
                    self.audit_logger.log_block(
                        user_id=user_id,
                        pii_types=blocked_types,
                        request_id=data.get("litellm_call_id"),
                        mode=mode,
                    )
                    # Return rejection message as string
                    return f"[ceil-dlp] Request blocked: Detected sensitive data ({', '.join(blocked_types)})"

                # Apply masking for medium-risk PII
                if masked_types:
                    redacted_text, redacted_items = redact_text(
                        text_content, detections=masked_types, ner_strength=self.config.ner_strength
                    )

                    # Update messages with redacted text
                    modified_messages = self._replace_text_in_messages(
                        messages, text_content, redacted_text
                    )

                    # Redact images that have PII detected
                    if images_with_pii:
                        # Determine which PII types in images should be masked
                        image_pii_types_to_mask = set(masked_types.keys())
                        modified_messages = self._redact_images_in_messages(
                            modified_messages, images_with_pii, image_pii_types_to_mask
                        )

                    # Redact PDFs that have PII detected
                    if pdfs_with_pii:
                        # Determine which PII types in PDFs should be masked
                        pdf_pii_types_to_mask = set(masked_types.keys())
                        modified_messages = self._redact_pdfs_in_messages(
                            modified_messages, pdfs_with_pii, pdf_pii_types_to_mask
                        )

                    data["messages"] = modified_messages

                    # Log the masking
                    for pii_type, items in redacted_items.items():
                        self.audit_logger.log_detection(
                            user_id=user_id,
                            pii_type=pii_type,
                            action="mask",
                            redacted_items=items,
                            request_id=data.get("litellm_call_id"),
                            mode=mode,
                        )

                if whistledown_types:
                    request_id = data.get("litellm_call_id", "unknown")
                    transformed_text, transformed_items = whistledown_transform_text(
                        text_content,
                        detections=whistledown_types,
                        cache=self.whistledown_cache,
                        request_id=request_id,
                    )

                    # Update messages with transformed text
                    modified_messages = self._replace_text_in_messages(
                        messages, text_content, transformed_text
                    )

                    # Note(jadidbourbaki): Images and PDFs with Whistledown action fall back to masking
                    # since overlaying replacement tokens on images is complex
                    if images_with_pii:
                        image_pii_types_to_mask = set(whistledown_types.keys())
                        modified_messages = self._redact_images_in_messages(
                            modified_messages, images_with_pii, image_pii_types_to_mask
                        )

                    if pdfs_with_pii:
                        pdf_pii_types_to_mask = set(whistledown_types.keys())
                        modified_messages = self._redact_pdfs_in_messages(
                            modified_messages, pdfs_with_pii, pdf_pii_types_to_mask
                        )

                    data["messages"] = modified_messages

                    # Store request_id for post-call hook to reverse transformations
                    data["_whistledown_request_id"] = request_id

                    # Log the transformation
                    for pii_type, items in transformed_items.items():
                        self.audit_logger.log_detection(
                            user_id=user_id,
                            pii_type=pii_type,
                            action="whistledown",
                            redacted_items=items,
                            request_id=request_id,
                            mode=mode,
                        )

                return data

        except Exception as e:
            # Fail-safe: log error but don't block request
            logger.error(f"CeilDLP error in pre_call_hook: {e}", exc_info=True)
            return data

    async def async_post_call_success_hook(
        self,
        data: dict[str, Any],
        user_api_key_dict: UserAPIKeyAuth | None,  # noqa: ARG002
        response: Any,
    ) -> Any | None:
        """
        Hook called after successful LLM response.

        For Whistledown types, this reverses the pseudonymization so the user sees
        original values in the response, preserving conversational coherence.

        Based on the Whistledown paper: https://arxiv.org/pdf/2511.13319

        Args:
            data: Request data dictionary
            user_api_key_dict: User API key authentication info
            response: LLM response object

        Returns:
            Modified response with reversed transformations, or None (no modifications)
        """
        try:
            # Check if this request used Whistledown
            request_id = data.get("_whistledown_request_id")
            if not request_id:
                return None

            logger.debug(f"reversing whistledown transformations for request_id={request_id}")

            # Transform response content back to original values
            # Handle both streaming and non-streaming responses
            if hasattr(response, "choices"):
                for choice in response.choices:
                    if (
                        hasattr(choice, "message")
                        and hasattr(choice.message, "content")
                        and choice.message.content
                    ):
                        # Reverse transform the content
                        original_content = self.whistledown_cache.reverse_transform(
                            request_id, choice.message.content
                        )
                        choice.message.content = original_content
                        logger.debug(f"reversed message content for request_id={request_id}")

            # Clean up cache for this request
            self.whistledown_cache.clear_request(request_id)

            return response

        except Exception as e:
            logger.error(f"error in post_call_hook: {e}", exc_info=True)
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

        images: list[bytes] = []

        for msg in messages:
            if not isinstance(msg, dict):
                continue
            content = msg.get("content")

            if content is None or not isinstance(content, list):
                continue

            # Handle multimodal content (OpenAI format)
            for item in content:
                if not isinstance(item, dict):
                    continue
                item_type = item.get("type")
                if item_type == "image_url":
                    # OpenAI format: {"type": "image_url", "image_url": {"url": "..."}}
                    image_url_data = item.get("image_url", {})
                    url = image_url_data.get("url", "") if isinstance(image_url_data, dict) else ""
                    if url.startswith("data:image"):
                        # Base64-encoded image
                        try:
                            # Extract base64 data (format: data:image/png;base64,<data>)
                            header, data = url.split(",", 1)
                            image_bytes = base64.b64decode(data)
                            images.append(image_bytes)
                        except Exception as e:
                            logger.warning(f"Failed to decode base64 image: {e}")
                    # TODO(jadidbourbaki): would do we do with image URLs? Do we need to download them?

                elif item_type == "image":
                    # Direct image data
                    image_data = item.get("image", "")
                    if isinstance(image_data, bytes):
                        images.append(image_data)
                    elif isinstance(image_data, str) and image_data.startswith("data:image"):
                        try:
                            _header, data = image_data.split(",", 1)
                            image_bytes = base64.b64decode(data)
                            images.append(image_bytes)
                        except Exception as e:
                            logger.warning(f"Failed to decode base64 image: {e}")

        return images

    def _extract_pdfs_from_messages(self, messages: list[Any]) -> list[bytes]:
        """
        Extract PDFs from LiteLLM messages format.

        Supports:
        - Base64-encoded PDFs (data:application/pdf;base64,...)
        - PDF URLs (will need to be downloaded, not implemented yet)

        Args:
            messages: List of messages in LiteLLM format

        Returns:
            List of PDF data as bytes
        """
        pdfs: list[bytes] = []

        for msg in messages:
            if not isinstance(msg, dict):
                continue

            content = msg.get("content")
            if content is None or not isinstance(content, list):
                continue

            # Handle multimodal content (OpenAI format)
            for item in content:
                if not isinstance(item, dict):
                    continue

                item_type = item.get("type")
                if item_type == "file" or item_type == "document":
                    # Check for PDF file
                    file_data = item.get("file", {})
                    if isinstance(file_data, dict):
                        url = file_data.get("url", "")
                        if url.startswith("data:application/pdf"):
                            # Base64-encoded PDF
                            try:
                                header, data = url.split(",", 1)
                                pdf_bytes = base64.b64decode(data)
                                pdfs.append(pdf_bytes)
                            except Exception as e:
                                logger.warning(f"Failed to decode base64 PDF: {e}")
                    elif isinstance(file_data, str) and file_data.startswith(
                        "data:application/pdf"
                    ):
                        try:
                            header, data = file_data.split(",", 1)
                            pdf_bytes = base64.b64decode(data)
                            pdfs.append(pdf_bytes)
                        except Exception as e:
                            logger.warning(f"Failed to decode base64 PDF: {e}")
                elif item_type == "pdf_url" or item_type == "document_url":
                    # Direct PDF URL
                    url_data = item.get("pdf_url") or item.get("document_url", {})
                    url = (
                        url_data.get("url", "")
                        if isinstance(url_data, dict)
                        else (url_data if isinstance(url_data, str) else "")
                    )
                    if url.startswith("data:application/pdf"):
                        try:
                            _header, data = url.split(",", 1)
                            pdf_bytes = base64.b64decode(data)
                            pdfs.append(pdf_bytes)
                        except Exception as e:
                            logger.warning(f"Failed to decode base64 PDF: {e}")

                    # TODO(jadidbourbaki): would do we do with PDF URLs? Do we need to download them?

        return pdfs

    def _replace_text_in_messages(
        self, messages: list[Any], old_text: str, new_text: str
    ) -> list[Any]:
        """Replace text in messages while preserving structure."""
        modified = []
        for msg in messages:
            if not isinstance(msg, dict):
                # String message - convert to dict format
                modified.append({"content": str(msg).replace(old_text, new_text)})
                continue
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
        return modified

    def _redact_images_in_messages(
        self,
        messages: list[Any],
        images_with_pii: list[tuple[bytes, dict[str, list[tuple[str, int, int]]]]],
        pii_types_to_mask: set[str],
    ) -> list[Any]:
        """
        Redact images in messages that contain PII types that should be masked.

        Args:
            messages: List of messages (may be modified from text redaction)
            images_with_pii: List of (image_data, image_detections) tuples
            pii_types_to_mask: Set of PII types that should be masked

        Returns:
            Modified messages with redacted images
        """

        # Create a mapping of original image bytes to redacted image bytes
        image_redaction_map: dict[bytes, bytes] = {}

        for image_data, image_detections in images_with_pii:
            # Check if this image has any PII types that should be masked
            image_pii_types = set(image_detections.keys())
            if image_pii_types.intersection(pii_types_to_mask):
                # This image has PII that should be masked, redact it
                try:
                    # Get the PII types in this image that need masking
                    types_to_redact = list(image_pii_types.intersection(pii_types_to_mask))
                    redacted_image = redact_image(
                        image_data,
                        pii_types=types_to_redact,
                        ocr_strength=self.config.ocr_strength,
                        ner_strength=self.config.ner_strength,
                    )
                    image_redaction_map[image_data] = redacted_image
                    logger.debug(f"Redacted image with PII types: {types_to_redact}")
                except Exception as e:
                    logger.error(f"Failed to redact image: {e}", exc_info=True)
                    # Continue with original image on error

        if not image_redaction_map:
            # No images to redact
            return messages

        # Replace images in messages
        modified = []

        for msg in messages:
            if not isinstance(msg, dict):
                modified.append(msg)
                continue
            new_msg = msg.copy()
            content = msg.get("content")

            if not isinstance(content, list):
                modified.append(msg)
                continue
            # Handle multimodal content
            new_content = []
            for item in content:
                if not isinstance(item, dict):
                    new_content.append(item)
                    continue
                item_type = item.get("type")

                # Handle image_url type (OpenAI format)
                if item_type == "image_url":
                    image_url_data = item.get("image_url", {})
                    url = image_url_data.get("url", "") if isinstance(image_url_data, dict) else ""

                    if not url or not url.startswith("data:image"):
                        new_content.append(item)
                        continue

                    try:
                        header, data = url.split(",", 1)
                        image_bytes = base64.b64decode(data)

                        if image_bytes in image_redaction_map:
                            # Replace with redacted image
                            redacted_image = image_redaction_map[image_bytes]
                            redacted_base64 = base64.b64encode(redacted_image).decode("utf-8")

                            # Preserve the original header (data:image/png;base64)
                            new_url = f"{header},{redacted_base64}"
                            new_item = item.copy()
                            new_item["image_url"] = {"url": new_url}
                            new_content.append(new_item)
                            continue
                    except Exception as e:
                        logger.warning(f"Failed to process image URL: {e}")

                # Handle image type (direct image data)
                elif item_type == "image":
                    image_data = item.get("image", "")
                    image_bytes_direct: bytes | None = None

                    if isinstance(image_data, bytes):
                        image_bytes_direct = image_data
                    elif isinstance(image_data, str) and image_data.startswith("data:image"):
                        try:
                            header, data = image_data.split(",", 1)
                            image_bytes_direct = base64.b64decode(data)
                        except Exception as e:
                            logger.warning(f"Failed to decode base64 image: {e}")

                    if image_bytes_direct and image_bytes_direct in image_redaction_map:
                        # Replace with redacted image
                        redacted_image = image_redaction_map[image_bytes_direct]
                        redacted_base64 = base64.b64encode(redacted_image).decode("utf-8")

                        # Preserve the original format
                        if isinstance(image_data, str) and image_data.startswith("data:image"):
                            header, _ = image_data.split(",", 1)
                            new_image_data = f"{header},{redacted_base64}"
                        else:
                            # If it was bytes, convert to base64 data URL
                            new_image_data = f"data:image/png;base64,{redacted_base64}"

                        new_item = item.copy()
                        new_item["image"] = new_image_data
                        new_content.append(new_item)
                        continue

                # Keep non-image items and unredacted images as-is
                new_content.append(item)

            new_msg["content"] = new_content
            modified.append(new_msg)

        return modified

    def _redact_pdfs_in_messages(
        self,
        messages: list[Any],
        pdfs_with_pii: list[tuple[bytes, dict[str, list[tuple[str, int, int]]]]],
        pii_types_to_mask: set[str],
    ) -> list[Any]:
        """
        Redact PDFs in messages that contain PII types that should be masked.

        Args:
            messages: List of messages (may be modified from text/image redaction)
            pdfs_with_pii: List of (pdf_data, pdf_detections) tuples
            pii_types_to_mask: Set of PII types that should be masked

        Returns:
            Modified messages with redacted PDFs
        """

        # Create a mapping of original PDF bytes to redacted PDF bytes
        pdf_redaction_map: dict[bytes, bytes] = {}

        for pdf_data, pdf_detections in pdfs_with_pii:
            # Check if this PDF has any PII types that should be masked
            pdf_pii_types = set(pdf_detections.keys())
            if pdf_pii_types.intersection(pii_types_to_mask):
                # This PDF has PII that should be masked, redact it
                try:
                    # Get the PII types in this PDF that need masking
                    types_to_redact = list(pdf_pii_types.intersection(pii_types_to_mask))
                    redacted_pdf = redact_pdf(
                        pdf_data,
                        pii_types=types_to_redact,
                        ocr_strength=self.config.ocr_strength,
                        ner_strength=self.config.ner_strength,
                    )
                    pdf_redaction_map[pdf_data] = redacted_pdf
                    logger.debug(f"Redacted PDF with PII types: {types_to_redact}")
                except Exception as e:
                    logger.error(f"Failed to redact PDF: {e}", exc_info=True)
                    # Continue with original PDF on error

        if not pdf_redaction_map:
            # No PDFs to redact
            return messages

        # Replace PDFs in messages
        modified = []

        for msg in messages:
            if not isinstance(msg, dict):
                modified.append(msg)
                continue
            new_msg = msg.copy()
            content = msg.get("content")

            if not isinstance(content, list):
                modified.append(msg)
                continue
            # Handle multimodal content
            new_content = []
            for item in content:
                if not isinstance(item, dict):
                    new_content.append(item)
                    continue
                item_type = item.get("type")

                # Handle file/document type (OpenAI format)
                if item_type in ("file", "document"):
                    file_data = item.get("file", {})
                    url = ""
                    if isinstance(file_data, dict):
                        url = file_data.get("url", "")
                    elif isinstance(file_data, str):
                        url = file_data

                    if not url or not url.startswith("data:application/pdf"):
                        new_content.append(item)
                        continue

                    try:
                        header, data = url.split(",", 1)
                        pdf_bytes = base64.b64decode(data)

                        if pdf_bytes in pdf_redaction_map:
                            # Replace with redacted PDF
                            redacted_pdf = pdf_redaction_map[pdf_bytes]
                            redacted_base64 = base64.b64encode(redacted_pdf).decode("utf-8")

                            # Preserve the original header (data:application/pdf;base64)
                            new_url = f"{header},{redacted_base64}"
                            new_item = item.copy()
                            if isinstance(file_data, dict):
                                new_item["file"] = {"url": new_url}
                            else:
                                new_item["file"] = new_url
                            new_content.append(new_item)
                            continue
                    except Exception as e:
                        logger.warning(f"Failed to process PDF URL: {e}")

                # Handle pdf_url/document_url type (direct PDF URL)
                elif item_type in ("pdf_url", "document_url"):
                    url_data = item.get("pdf_url") or item.get("document_url", {})
                    url = (
                        url_data.get("url", "")
                        if isinstance(url_data, dict)
                        else (url_data if isinstance(url_data, str) else "")
                    )

                    if not url or not url.startswith("data:application/pdf"):
                        new_content.append(item)
                        continue

                    try:
                        header, data = url.split(",", 1)
                        pdf_bytes = base64.b64decode(data)

                        if pdf_bytes in pdf_redaction_map:
                            # Replace with redacted PDF
                            redacted_pdf = pdf_redaction_map[pdf_bytes]
                            redacted_base64 = base64.b64encode(redacted_pdf).decode("utf-8")

                            # Preserve the original header
                            new_url = f"{header},{redacted_base64}"
                            new_item = item.copy()
                            if item_type == "pdf_url":
                                new_item["pdf_url"] = {"url": new_url}
                            else:
                                new_item["document_url"] = {"url": new_url}
                            new_content.append(new_item)
                            continue
                    except Exception as e:
                        logger.warning(f"Failed to process PDF URL: {e}")

                # Keep non-PDF items and unredacted PDFs as-is
                new_content.append(item)

            new_msg["content"] = new_content
            modified.append(new_msg)

        return modified
