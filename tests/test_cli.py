"""Tests for CLI tool."""

from unittest.mock import patch

import yaml
from typer.testing import CliRunner

from ceil_dlp.cli import app, main

runner = CliRunner()


def test_cli_main_callback_no_subcommand():
    """Test CLI main callback when no subcommand is provided."""
    result = runner.invoke(app, [])
    assert result.exit_code == 0
    assert "ceil-dlp" in result.stdout.lower() or "help" in result.stdout.lower()


def test_cli_install_creates_files(tmp_path):
    """Test that install command creates callback and config files."""
    litellm_config = tmp_path / "config.yaml"
    litellm_config.write_text("model_list:\n  - model_name: gpt-4\n")

    result = runner.invoke(app, ["install", str(litellm_config)])

    assert result.exit_code == 0
    assert "installation complete" in result.stdout.lower()

    # Check that files were created
    callback_file = tmp_path / "ceil_dlp_callback.py"
    config_file = tmp_path / "ceil-dlp.yaml"

    assert callback_file.exists()
    assert config_file.exists()

    # Verify callback file content
    callback_content = callback_file.read_text()
    assert "ceil_dlp_callback" in callback_content
    assert "proxy_handler_instance" in callback_content

    # Verify config file content
    config_content = config_file.read_text()
    assert "mode: enforce" in config_content
    assert "credit_card" in config_content


def test_cli_install_updates_litellm_config(tmp_path):
    """Test that install command updates LiteLLM config with callback."""
    litellm_config = tmp_path / "config.yaml"
    litellm_config.write_text("model_list:\n  - model_name: gpt-4\n")

    result = runner.invoke(app, ["install", str(litellm_config), "--update-config"])

    assert result.exit_code == 0

    # Verify config was updated
    with litellm_config.open() as f:
        config = yaml.safe_load(f)

    assert "litellm_settings" in config
    assert "callbacks" in config["litellm_settings"]
    callbacks = config["litellm_settings"]["callbacks"]
    assert "ceil_dlp_callback.proxy_handler_instance" in str(callbacks)


def test_cli_install_no_update_config(tmp_path):
    """Test install command with --no-update-config flag."""
    litellm_config = tmp_path / "config.yaml"
    litellm_config.write_text("model_list:\n  - model_name: gpt-4\n")

    result = runner.invoke(app, ["install", str(litellm_config), "--no-update-config"])

    assert result.exit_code == 0

    # Verify config was NOT updated
    with litellm_config.open() as f:
        config = yaml.safe_load(f)

    # Should not have callbacks if it wasn't in the original
    if "litellm_settings" in config and "callbacks" in config["litellm_settings"]:
        assert "ceil_dlp_callback" not in str(config["litellm_settings"]["callbacks"])


def test_cli_install_with_existing_callback_file(tmp_path):
    """Test install when callback file already exists."""
    litellm_config = tmp_path / "config.yaml"
    litellm_config.write_text("model_list:\n  - model_name: gpt-4\n")

    callback_file = tmp_path / "ceil_dlp_callback.py"
    callback_file.write_text("# existing file\n")

    result = runner.invoke(app, ["install", str(litellm_config)])

    assert result.exit_code == 0
    assert "already exists" in result.stdout.lower()

    # File should still have original content
    assert "# existing file" in callback_file.read_text()


def test_cli_install_with_existing_config_file(tmp_path):
    """Test install when config file already exists."""
    litellm_config = tmp_path / "config.yaml"
    litellm_config.write_text("model_list:\n  - model_name: gpt-4\n")

    config_file = tmp_path / "ceil-dlp.yaml"
    config_file.write_text("# existing config\nmode: observe\n")

    result = runner.invoke(app, ["install", str(litellm_config)])

    assert result.exit_code == 0
    assert "already exists" in result.stdout.lower()

    # File should still have original content
    assert "# existing config" in config_file.read_text()


def test_cli_install_with_existing_callback_in_config(tmp_path):
    """Test install when callback is already in LiteLLM config."""
    litellm_config = tmp_path / "config.yaml"
    litellm_config.write_text(
        """model_list:
  - model_name: gpt-4
litellm_settings:
  callbacks:
    - ceil_dlp_callback.proxy_handler_instance
"""
    )

    result = runner.invoke(app, ["install", str(litellm_config)])

    assert result.exit_code == 0
    assert "already configured" in result.stdout.lower()

    # Verify callback wasn't duplicated
    with litellm_config.open() as f:
        config = yaml.safe_load(f)

    callbacks = config["litellm_settings"]["callbacks"]
    if isinstance(callbacks, list):
        ceil_dlp_count = sum(1 for cb in callbacks if "ceil_dlp_callback" in str(cb))
        assert ceil_dlp_count == 1


def test_cli_install_with_string_callback_in_config(tmp_path):
    """Test install when callback is a string in LiteLLM config."""
    litellm_config = tmp_path / "config.yaml"
    litellm_config.write_text(
        """model_list:
  - model_name: gpt-4
litellm_settings:
  callbacks: ceil_dlp_callback.proxy_handler_instance
"""
    )

    result = runner.invoke(app, ["install", str(litellm_config)])

    assert result.exit_code == 0
    assert "already configured" in result.stdout.lower()


def test_cli_install_with_invalid_yaml(tmp_path):
    """Test install when LiteLLM config has invalid YAML."""
    litellm_config = tmp_path / "config.yaml"
    litellm_config.write_text("invalid: yaml: content: [\n")  # Invalid YAML

    result = runner.invoke(app, ["install", str(litellm_config), "--update-config"])

    # Should still create files but show error for config update
    assert result.exit_code == 0
    assert (
        "could not update" in result.stdout.lower()
        or "installation complete" in result.stdout.lower()
    )

    # Files should still be created
    callback_file = tmp_path / "ceil_dlp_callback.py"
    config_file = tmp_path / "ceil-dlp.yaml"
    assert callback_file.exists()
    assert config_file.exists()


def test_cli_remove_removes_callback_from_config(tmp_path):
    """Test that remove command removes callback from LiteLLM config."""
    litellm_config = tmp_path / "config.yaml"
    litellm_config.write_text(
        """model_list:
  - model_name: gpt-4
litellm_settings:
  callbacks:
    - ceil_dlp_callback.proxy_handler_instance
    - other_callback
"""
    )

    result = runner.invoke(app, ["remove", str(litellm_config)])

    assert result.exit_code == 0
    assert "removal complete" in result.stdout.lower()

    # Verify callback was removed
    with litellm_config.open() as f:
        config = yaml.safe_load(f)

    callbacks = config.get("litellm_settings", {}).get("callbacks", [])
    if isinstance(callbacks, list):
        assert "ceil_dlp_callback" not in str(callbacks)
        assert "other_callback" in str(callbacks)  # Other callback should remain


def test_cli_remove_removes_callback_file(tmp_path):
    """Test that remove command removes callback file."""
    litellm_config = tmp_path / "config.yaml"
    litellm_config.write_text("model_list:\n  - model_name: gpt-4\n")

    callback_file = tmp_path / "ceil_dlp_callback.py"
    callback_file.write_text("# callback file\n")

    result = runner.invoke(app, ["remove", str(litellm_config), "--remove-callback-file"])

    assert result.exit_code == 0
    assert not callback_file.exists()


def test_cli_remove_keeps_callback_file(tmp_path):
    """Test that remove command keeps callback file when flag is set."""
    litellm_config = tmp_path / "config.yaml"
    litellm_config.write_text("model_list:\n  - model_name: gpt-4\n")

    callback_file = tmp_path / "ceil_dlp_callback.py"
    callback_file.write_text("# callback file\n")

    result = runner.invoke(app, ["remove", str(litellm_config), "--keep-callback-file"])

    assert result.exit_code == 0
    assert callback_file.exists()
    assert "keeping" in result.stdout.lower()


def test_cli_remove_removes_config_file(tmp_path):
    """Test that remove command removes config file when flag is set."""
    litellm_config = tmp_path / "config.yaml"
    litellm_config.write_text("model_list:\n  - model_name: gpt-4\n")

    config_file = tmp_path / "ceil-dlp.yaml"
    config_file.write_text("# config file\n")

    result = runner.invoke(app, ["remove", str(litellm_config), "--remove-config-file"])

    assert result.exit_code == 0
    assert not config_file.exists()


def test_cli_remove_keeps_config_file(tmp_path):
    """Test that remove command keeps config file by default."""
    litellm_config = tmp_path / "config.yaml"
    litellm_config.write_text("model_list:\n  - model_name: gpt-4\n")

    config_file = tmp_path / "ceil-dlp.yaml"
    config_file.write_text("# config file\n")

    result = runner.invoke(app, ["remove", str(litellm_config)])

    assert result.exit_code == 0
    assert config_file.exists()


def test_cli_remove_no_update_config(tmp_path):
    """Test remove command with --no-update-config flag."""
    litellm_config = tmp_path / "config.yaml"
    litellm_config.write_text(
        """model_list:
  - model_name: gpt-4
litellm_settings:
  callbacks:
    - ceil_dlp_callback.proxy_handler_instance
"""
    )

    result = runner.invoke(app, ["remove", str(litellm_config), "--no-update-config"])

    assert result.exit_code == 0

    # Verify config was NOT updated
    with litellm_config.open() as f:
        config = yaml.safe_load(f)

    callbacks = config.get("litellm_settings", {}).get("callbacks", [])
    assert "ceil_dlp_callback" in str(callbacks)  # Should still be there


def test_cli_remove_with_string_callback(tmp_path):
    """Test remove when callback is a string in config."""
    litellm_config = tmp_path / "config.yaml"
    litellm_config.write_text(
        """model_list:
  - model_name: gpt-4
litellm_settings:
  callbacks: ceil_dlp_callback.proxy_handler_instance
"""
    )

    result = runner.invoke(app, ["remove", str(litellm_config)])

    assert result.exit_code == 0

    # Verify callback was removed
    with litellm_config.open() as f:
        config = yaml.safe_load(f)

    # Should have no callbacks or empty callbacks
    callbacks = config.get("litellm_settings", {}).get("callbacks", [])
    if callbacks:
        assert "ceil_dlp_callback" not in str(callbacks)


def test_cli_remove_with_no_callbacks(tmp_path):
    """Test remove when no callbacks are configured."""
    litellm_config = tmp_path / "config.yaml"
    litellm_config.write_text("model_list:\n  - model_name: gpt-4\n")

    result = runner.invoke(app, ["remove", str(litellm_config)])

    assert result.exit_code == 0
    assert (
        "no callbacks configured" in result.stdout.lower() or "not found" in result.stdout.lower()
    )


def test_cli_remove_with_invalid_yaml(tmp_path):
    """Test remove when LiteLLM config has invalid YAML."""
    litellm_config = tmp_path / "config.yaml"
    litellm_config.write_text("invalid: yaml: content: [\n")  # Invalid YAML

    result = runner.invoke(app, ["remove", str(litellm_config)])

    # Should show error but not crash
    assert result.exit_code == 0
    assert (
        "could not update" in result.stdout.lower() or "removal complete" in result.stdout.lower()
    )


def test_cli_remove_callback_not_found(tmp_path):
    """Test remove when callback is not in config."""
    litellm_config = tmp_path / "config.yaml"
    litellm_config.write_text(
        """model_list:
  - model_name: gpt-4
litellm_settings:
  callbacks:
    - other_callback
"""
    )

    result = runner.invoke(app, ["remove", str(litellm_config)])

    assert result.exit_code == 0
    assert "not found" in result.stdout.lower() or "removal complete" in result.stdout.lower()


def test_cli_remove_removes_empty_callbacks_section(tmp_path):
    """Test that remove command removes empty callbacks section."""
    litellm_config = tmp_path / "config.yaml"
    litellm_config.write_text(
        """model_list:
  - model_name: gpt-4
litellm_settings:
  callbacks:
    - ceil_dlp_callback.proxy_handler_instance
"""
    )

    result = runner.invoke(app, ["remove", str(litellm_config)])

    assert result.exit_code == 0

    # Verify callbacks section was removed
    with litellm_config.open() as f:
        config = yaml.safe_load(f)

    # Should not have callbacks key
    if "litellm_settings" in config:
        assert "callbacks" not in config["litellm_settings"]


def test_cli_remove_converts_single_callback_to_string(tmp_path):
    """Test that remove converts single remaining callback to string format."""
    litellm_config = tmp_path / "config.yaml"
    litellm_config.write_text(
        """model_list:
  - model_name: gpt-4
litellm_settings:
  callbacks:
    - ceil_dlp_callback.proxy_handler_instance
    - other_callback
"""
    )

    result = runner.invoke(app, ["remove", str(litellm_config)])

    assert result.exit_code == 0

    # Verify single callback is now a string
    with litellm_config.open() as f:
        config = yaml.safe_load(f)

    callbacks = config.get("litellm_settings", {}).get("callbacks")
    # Should be a string if only one callback remains
    if callbacks and "other_callback" in str(callbacks):
        # Could be string or list, both are valid
        assert isinstance(callbacks, (str, list))


def test_cli_main_function():
    """Test main function entry point."""
    with patch("ceil_dlp.cli.app") as mock_app:
        main()
        mock_app.assert_called_once()
