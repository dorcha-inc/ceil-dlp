"""Tests for configuration management."""

from pathlib import Path

import yaml

from ceil_dlp.config import Config, ModelRules, Policy


def test_config_default_policies():
    """Test that Config has default policies."""
    config = Config()
    assert "credit_card" in config.policies
    assert "ssn" in config.policies
    assert "api_key" in config.policies
    assert "email" in config.policies
    assert "phone" in config.policies

    # Check default actions
    assert config.policies["credit_card"].action == "block"
    assert config.policies["ssn"].action == "block"
    assert config.policies["api_key"].action == "block"
    assert config.policies["email"].action == "mask"
    assert config.policies["phone"].action == "mask"


def test_config_from_dict():
    """Test creating Config from dictionary."""
    config_dict = {
        "policies": {
            "email": {"action": "block", "enabled": True},
        }
    }
    config = Config.from_dict(config_dict)
    assert config.policies["email"].action == "block"
    # Should still have defaults for other types
    assert "credit_card" in config.policies


def test_config_from_yaml(tmp_path: Path):
    """Test loading Config from YAML file."""
    config_file = tmp_path / "config.yaml"
    config_data = {
        "policies": {
            "email": {"action": "block", "enabled": True},
            "phone": {"action": "mask", "enabled": False},
        },
        "audit_log_path": "/tmp/audit.log",
    }
    config_file.write_text(yaml.dump(config_data))

    config = Config.from_yaml(config_file)
    assert config.policies["email"].action == "block"
    assert config.policies["phone"].enabled is False
    assert config.audit_log_path == "/tmp/audit.log"


def test_config_from_yaml_empty_file(tmp_path: Path):
    """Test loading Config from empty YAML file."""
    config_file = tmp_path / "config.yaml"
    config_file.write_text("")

    config = Config.from_yaml(config_file)
    # Should use defaults
    assert "credit_card" in config.policies


def test_config_get_policy():
    """Test getting policy for a PII type."""
    config = Config()
    policy = config.get_policy("email")
    assert policy is not None
    assert isinstance(policy, Policy)
    assert policy.action == "mask"

    # Test non-existent policy
    policy = config.get_policy("nonexistent")
    assert policy is None


def test_config_merge_policies_with_defaults():
    """Test that user policies merge with defaults."""
    config = Config.from_dict(
        {
            "policies": {
                "email": {"action": "block", "enabled": True},
            }
        }
    )
    # Should have both user policy and defaults
    assert config.policies["email"].action == "block"
    assert config.policies["credit_card"].action == "block"  # default
    assert config.policies["ssn"].action == "block"  # default


def test_config_audit_log_path_from_env(monkeypatch):
    """Test that audit_log_path can be set from environment."""
    monkeypatch.setenv("CEIL_DLP_AUDIT_LOG", "/custom/path/audit.log")
    config = Config()
    assert config.audit_log_path == "/custom/path/audit.log"


def test_config_mode_default():
    """Test that mode defaults to enforce."""
    config = Config()
    assert config.mode == "enforce"


def test_config_mode_from_yaml(tmp_path):
    """Test mode configuration from YAML."""
    config_file = tmp_path / "config.yaml"
    config_data = {"mode": "observe"}
    config_file.write_text(yaml.dump(config_data))

    config = Config.from_yaml(config_file)
    assert config.mode == "observe"


def test_config_mode_from_dict():
    """Test mode configuration from dict."""
    config = Config.from_dict({"mode": "warn"})
    assert config.mode == "warn"


def test_config_mode_env_var(monkeypatch):
    """Test mode configuration from environment variable."""
    monkeypatch.setenv("CEIL_DLP_MODE", "observe")
    config = Config()
    assert config.mode == "observe"


def test_config_new_pii_types_defaults():
    """Test that new PII types have default policies."""
    config = Config()
    assert "pem_key" in config.policies
    assert "jwt_token" in config.policies
    assert "high_entropy_token" in config.policies
    assert config.policies["pem_key"].action == "block"
    assert config.policies["jwt_token"].action == "block"
    assert config.policies["high_entropy_token"].action == "block"


def test_policy_model():
    """Test Policy model."""
    policy = Policy(action="block", enabled=True)
    assert policy.action == "block"
    assert policy.enabled is True

    policy2 = Policy(action="mask", enabled=False)
    assert policy2.action == "mask"
    assert policy2.enabled is False


def test_policy_with_models():
    """Test Policy with model-aware rules."""
    models = ModelRules(allow=["openai/.*"], block=["anthropic/.*"])
    policy = Policy(action="block", enabled=True, models=models)
    assert policy.models is not None
    assert policy.models.allow == ["openai/.*"]
    assert policy.models.block == ["anthropic/.*"]


def test_policy_without_models():
    """Test Policy without models (backward compatible)."""
    policy = Policy(action="block", enabled=True)
    assert policy.models is None


def test_model_rules():
    """Test ModelRules model."""
    rules = ModelRules(allow=["self-hosted/.*"], block=["openai/.*"])
    assert rules.allow == ["self-hosted/.*"]
    assert rules.block == ["openai/.*"]

    rules2 = ModelRules(allow=None, block=None)
    assert rules2.allow is None
    assert rules2.block is None


def test_config_model_aware_policy_from_yaml(tmp_path):
    """Test loading model-aware policy from YAML."""
    config_file = tmp_path / "config.yaml"
    config_data = {
        "policies": {
            "email": {
                "action": "block",
                "enabled": True,
                "models": {
                    "allow": ["self-hosted/.*"],
                    "block": ["openai/.*"],
                },
            }
        }
    }
    config_file.write_text(yaml.dump(config_data))

    config = Config.from_yaml(config_file)
    email_policy = config.policies["email"]
    assert email_policy.models is not None
    assert email_policy.models.allow == ["self-hosted/.*"]
    assert email_policy.models.block == ["openai/.*"]


def test_config_model_aware_policy_from_dict():
    """Test creating model-aware policy from dict."""
    config_dict = {
        "policies": {
            "email": {
                "action": "block",
                "enabled": True,
                "models": {
                    "allow": ["self-hosted/.*"],
                },
            }
        }
    }
    config = Config.from_dict(config_dict)
    email_policy = config.policies["email"]
    assert email_policy.models is not None
    assert email_policy.models.allow == ["self-hosted/.*"]
    assert email_policy.models.block is None
