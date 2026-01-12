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

    action: Literal["block", "mask"]
    enabled: bool = True
    models: ModelRules | None = None  # If None, apply to all models


class Config(BaseModel):
    """Configuration for ceil-dlp."""

    # Default policies - high-risk items block, medium-risk mask
    _DEFAULT_POLICIES: dict[str, dict[str, str | bool]] = {
        "credit_card": {"action": "block", "enabled": True},
        "ssn": {"action": "block", "enabled": True},
        "api_key": {"action": "block", "enabled": True},
        "pem_key": {"action": "block", "enabled": True},
        "jwt_token": {"action": "block", "enabled": True},
        "high_entropy_token": {"action": "block", "enabled": True},
        "email": {"action": "mask", "enabled": True},
        "phone": {"action": "mask", "enabled": True},
    }

    policies: dict[str, Policy] = Field(
        default_factory=lambda: {
            k: Policy(
                action=v["action"],  # type: ignore[arg-type]
                enabled=bool(v["enabled"]),
            )
            for k, v in {
                "credit_card": {"action": "block", "enabled": True},
                "ssn": {"action": "block", "enabled": True},
                "api_key": {"action": "block", "enabled": True},
                "pem_key": {"action": "block", "enabled": True},
                "jwt_token": {"action": "block", "enabled": True},
                "high_entropy_token": {"action": "block", "enabled": True},
                "email": {"action": "mask", "enabled": True},
                "phone": {"action": "mask", "enabled": True},
            }.items()
        }
    )
    audit_log_path: str | None = Field(default_factory=lambda: os.getenv("CEIL_DLP_AUDIT_LOG"))
    enabled_pii_types: list[str] = Field(default_factory=list)
    mode: Literal["observe", "warn", "enforce"] = Field(default="enforce")

    @model_validator(mode="after")
    def merge_policies_with_defaults(self) -> "Config":
        """Merge user-provided policies with defaults."""
        # Always start with defaults, then update with user-provided policies
        defaults = {
            k: Policy(
                action=v["action"],  # type: ignore[arg-type]
                enabled=bool(v["enabled"]),
            )
            for k, v in self._DEFAULT_POLICIES.items()
        }
        defaults.update(self.policies)
        self.policies = defaults

        # Override mode from environment variable if set
        env_mode = os.getenv("CEIL_DLP_MODE")
        if env_mode and env_mode in ("observe", "warn", "enforce"):
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
        """Get policy for a PII type."""
        return self.policies.get(pii_type)
