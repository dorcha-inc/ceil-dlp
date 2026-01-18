"""Tests for configuration management."""

from pathlib import Path

import yaml

from ceil_dlp.config import Config, ModelRules, Policy


def test_config_default_policies():
    """Test that Config starts with empty policies."""
    config = Config()
    # No default policies - policies dict should be empty
    assert config.policies == {}


def test_config_from_dict():
    """Test creating Config from dictionary."""
    config_dict = {
        "policies": {
            "email": {"action": "block", "enabled": True},
        }
    }
    config = Config.from_dict(config_dict)
    assert config.policies["email"].action == "block"
    # Only the explicitly set policy should be present
    assert len(config.policies) == 1


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
    # Should have empty policies
    assert config.policies == {}


def test_config_get_policy():
    """Test getting policy for a PII type."""
    config = Config()
    # No default policies, so should return None
    policy = config.get_policy("email")
    assert policy is None

    # Add a policy explicitly
    config.policies["email"] = Policy(action="mask", enabled=True)
    policy = config.get_policy("email")
    assert policy is not None
    assert isinstance(policy, Policy)
    assert policy.action == "mask"

    # Test non-existent policy
    policy = config.get_policy("nonexistent")
    assert policy is None


def test_config_get_policy_with_default():
    """Test getting policy with default_policy set."""
    config = Config()
    # Set a default policy
    config.default_policy = Policy(action="mask", enabled=True)

    # Get policy for a type that doesn't have explicit policy
    policy = config.get_policy("email")
    assert policy is not None
    assert policy == config.default_policy
    assert policy.action == "mask"

    # Explicit policy should override default
    config.policies["email"] = Policy(action="block", enabled=True)
    policy = config.get_policy("email")
    assert policy is not None
    assert policy.action == "block"
    assert policy != config.default_policy


def test_config_default_policy_from_dict():
    """Test default_policy loaded from dict."""
    config_dict = {
        "default_policy": {"action": "mask", "enabled": True},
        "policies": {
            "email": {"action": "block", "enabled": True},
        },
    }
    config = Config.from_dict(config_dict)
    assert config.default_policy is not None
    assert config.default_policy.action == "mask"
    # Explicit policy should still work
    assert config.policies["email"].action == "block"


def test_config_default_policy_from_yaml(tmp_path):
    """Test default_policy loaded from YAML."""
    config_file = tmp_path / "config.yaml"
    config_data = {
        "default_policy": {"action": "observe", "enabled": True},
        "policies": {
            "email": {"action": "block", "enabled": True},
        },
    }
    config_file.write_text(yaml.dump(config_data))

    config = Config.from_yaml(config_file)
    assert config.default_policy is not None
    assert config.default_policy.action == "observe"
    # Explicit policy should still work
    assert config.policies["email"].action == "block"


def test_config_merge_policies_with_defaults():
    """Test that user policies are set correctly."""
    config = Config.from_dict(
        {
            "policies": {
                "email": {"action": "block", "enabled": True},
            }
        }
    )
    # Should have only the user policy
    assert config.policies["email"].action == "block"
    assert len(config.policies) == 1


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
    config = Config.from_dict({"mode": "observe"})
    assert config.mode == "observe"


def test_config_mode_env_var(monkeypatch):
    """Test mode configuration from environment variable."""
    monkeypatch.setenv("CEIL_DLP_MODE", "observe")
    config = Config()
    assert config.mode == "observe"


def test_config_new_pii_types_defaults():
    """Test that new PII types don't have default policies."""
    config = Config()
    # No default policies
    assert "pem_key" not in config.policies
    assert "jwt_token" not in config.policies
    # get_policy should return None
    assert config.get_policy("pem_key") is None
    assert config.get_policy("jwt_token") is None


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
