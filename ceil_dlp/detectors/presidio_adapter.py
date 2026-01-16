"""Adapter to integrate Presidio for standard PII detection."""

import logging
from functools import lru_cache

from presidio_analyzer import AnalyzerEngine

from ceil_dlp.detectors.patterns import PatternMatch

logger = logging.getLogger(__name__)

PRESIDIO_TO_PII_TYPE: dict[str, str] = {
    "EMAIL_ADDRESS": "email",
    "PHONE_NUMBER": "phone",
    "US_SSN": "ssn",
    "CREDIT_CARD": "credit_card",
    "INTERNATIONAL_PHONE_NUMBER": "phone",
}


@lru_cache(maxsize=1)
def get_analyzer() -> AnalyzerEngine:
    """Get cached AnalyzerEngine instance to avoid expensive re-initialization.

    This is shared across all Presidio-based detection modules (text, image, redaction)
    to ensure we only create one analyzer instance per process.
    """
    return AnalyzerEngine()


def _detect_with_presidio(text: str) -> dict[str, list[PatternMatch]]:
    analyzer = get_analyzer()
    results = analyzer.analyze(text=text, language="en")
    detections: dict[str, list[PatternMatch]] = {}
    for result in results:
        entity_type = result.entity_type
        pii_type = PRESIDIO_TO_PII_TYPE.get(entity_type)
        if pii_type:
            matched_text = text[result.start : result.end]
            match = (matched_text, result.start, result.end)
            if pii_type not in detections:
                detections[pii_type] = []
            detections[pii_type].append(match)
    return detections


def detect_with_presidio(text: str) -> dict[str, list[PatternMatch]]:
    """
    Detect standard PII using Presidio.

    Args:
        text: Input text to scan

    Returns:
        Dictionary mapping PII type to list of matches.
        Each match is a tuple: (matched_text, start_pos, end_pos)
    """
    try:
        return _detect_with_presidio(text)
    except Exception as e:
        raise RuntimeError("Failed to detect PII with Presidio") from e
