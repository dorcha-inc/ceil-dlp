"""Configuration management for ceil-dlp."""

import os
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, Field, model_validator


class ModelRules(BaseModel):
    """Model matching rules for policy application."""

    allow: list[str] | None = None  # Models/patterns that bypass policy (skip enforcement)
    block: list[str] | None = None  # Models/patterns that trigger policy (enforce)


class Policy(BaseModel):
    """Represents a DLP policy for a PII type."""

    action: Literal["block", "mask", "observe", "whistledown"]
    enabled: bool = Field(
        default=True, description="Whether to apply this policy. If False, the policy is ignored."
    )
    models: ModelRules | None = None  # If None, apply to all models


class Config(BaseModel):
    """Configuration for ceil-dlp."""

    policies: dict[str, Policy] = Field(default_factory=dict)
    audit_log_path: str | None = Field(default_factory=lambda: os.getenv("CEIL_DLP_AUDIT_LOG"))
    enabled_pii_types: list[str] = Field(default_factory=list)
    mode: Literal["observe", "enforce"] = Field(default="enforce")
    default_policy: Policy | None = Field(
        default=None,
        description="Default policy to apply to any PII type that doesn't have an explicit policy. "
        "If None, defaults to masking all detected PII.",
    )
    ocr_strength: int = Field(
        default=3,
        ge=1,
        le=3,
        description="Number of OCR models to use in ensemble (1=light docTR only, 2=light docTR+Tesseract, 3=all three including heavy docTR).",
    )
    ner_strength: int = Field(
        default=3,
        ge=1,
        le=3,
        description="NER model strength: 1=en_core_web_lg (fastest), 2=spaCy+transformer ensemble (balanced), 3=spaCy+transformer+GLiNER ensemble (best coverage, slower). Default is 3.",
    )

    @model_validator(mode="after")
    def override_mode_from_env(self) -> "Config":
        """Override mode from environment variable if set."""
        env_mode = os.getenv("CEIL_DLP_MODE")
        if env_mode and env_mode in ("observe", "enforce"):
            self.mode = env_mode  # type: ignore[assignment]
        return self

    @classmethod
    def from_yaml(cls, config_path: str | Path) -> "Config":
        """
        Load configuration from YAML file.

        Args:
            config_path: Path to YAML config file

        Returns:
            Config instance
        """
        with open(config_path) as f:
            data = yaml.safe_load(f) or {}
        return cls.model_validate(data)

    @classmethod
    def from_dict(cls, config_dict: dict) -> "Config":
        """
        Create config from dictionary.

        Args:
            config_dict: Configuration dictionary

        Returns:
            Config instance
        """
        return cls.model_validate(config_dict)

    def get_policy(self, pii_type: str) -> Policy | None:
        """Get policy for a PII type.

        Returns explicit policy if it exists, otherwise returns default_policy.
        If default_policy is None, returns None (no default policies).
        """
        explicit_policy = self.policies.get(pii_type)
        if explicit_policy is not None:
            return explicit_policy
        # Return default_policy if set, otherwise None
        return self.default_policy
