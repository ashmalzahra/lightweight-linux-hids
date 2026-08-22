"""Unit tests for configuration loading."""

import pytest

from lightweight_hids.config import ConfigError, load_config


VALID_CONFIG = """
runtime:
  poll_interval_seconds: 5
  state_directory: .hids-state

storage:
  events_path: var/events.jsonl
  alerts_path: var/alerts.jsonl

monitors:
  authentication:
    enabled: true
    log_path: /var/log/auth.log

  file_integrity:
    enabled: true
    paths:
      - var/lab/monitored

  processes:
    enabled: true
"""


def test_load_config_returns_parsed_data(tmp_path) -> None:
    config_path = tmp_path / "config.yaml"
    config_path.write_text(VALID_CONFIG, encoding="utf-8")

    config = load_config(config_path)

    assert config["runtime"]["poll_interval_seconds"] == 5
    assert config["storage"]["events_path"] == "var/events.jsonl"
    assert config["monitors"]["authentication"]["enabled"] is True


def test_load_config_rejects_missing_file(tmp_path) -> None:
    with pytest.raises(ConfigError, match="not found"):
        load_config(tmp_path / "missing.yaml")


def test_load_config_rejects_empty_document(tmp_path) -> None:
    config_path = tmp_path / "empty.yaml"
    config_path.write_text("", encoding="utf-8")

    with pytest.raises(ConfigError, match="root must be a mapping"):
        load_config(config_path)


def test_load_config_rejects_nonpositive_poll_interval(tmp_path) -> None:
    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        VALID_CONFIG.replace(
            "poll_interval_seconds: 5",
            "poll_interval_seconds: 0",
        ),
        encoding="utf-8",
    )

    with pytest.raises(ConfigError, match="positive number"):
        load_config(config_path)

def test_config_rejects_empty_file_integrity_paths(tmp_path):
    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        """
runtime:
  poll_interval_seconds: 5
  state_directory: .hids-state

storage:
  events_path: var/events.jsonl
  alerts_path: var/alerts.jsonl

monitors:
  file_integrity:
    enabled: true
    paths: []
""",
        encoding="utf-8",
    )

    with pytest.raises(
        ConfigError,
        match="monitors.file_integrity.paths",
    ):
        load_config(config_path)


def test_config_rejects_non_boolean_file_integrity_enabled(tmp_path):
    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        """
runtime:
  poll_interval_seconds: 5
  state_directory: .hids-state

storage:
  events_path: var/events.jsonl
  alerts_path: var/alerts.jsonl

monitors:
  file_integrity:
    enabled: yes-please
    paths:
      - var/lab/monitored
""",
        encoding="utf-8",
    )

    with pytest.raises(
        ConfigError,
        match="monitors.file_integrity.enabled",
    ):
        load_config(config_path)


def test_config_rejects_non_boolean_authentication_enabled(tmp_path):
    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        VALID_CONFIG.replace(
            "authentication:\n    enabled: true",
            "authentication:\n    enabled: yes-please",
        ),
        encoding="utf-8",
    )

    with pytest.raises(
        ConfigError,
        match="monitors.authentication.enabled",
    ):
        load_config(config_path)


def test_config_rejects_empty_authentication_log_path(tmp_path):
    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        VALID_CONFIG.replace(
            "log_path: /var/log/auth.log",
            "log_path: ''",
        ),
        encoding="utf-8",
    )

    with pytest.raises(
        ConfigError,
        match="monitors.authentication.log_path",
    ):
        load_config(config_path)


def test_config_rejects_non_boolean_processes_enabled(tmp_path):
    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        VALID_CONFIG.replace(
            "processes:\n    enabled: true",
            "processes:\n    enabled: yes-please",
        ),
        encoding="utf-8",
    )

    with pytest.raises(
        ConfigError,
        match="monitors.processes.enabled",
    ):
        load_config(config_path)
