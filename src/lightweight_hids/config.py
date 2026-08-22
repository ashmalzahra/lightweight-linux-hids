"""Configuration loading and validation."""

from pathlib import Path
from typing import Any

import yaml


class ConfigError(ValueError):
    """Raised when configuration is missing or invalid."""


def load_config(path: str | Path) -> dict[str, Any]:
    """Load and validate a YAML configuration file."""
    config_path = Path(path)

    if not config_path.is_file():
        raise ConfigError(f"configuration file not found: {config_path}")

    with config_path.open("r", encoding="utf-8") as file:
        data = yaml.safe_load(file)

    if not isinstance(data, dict):
        raise ConfigError("configuration root must be a mapping")

    for section in ("runtime", "storage", "monitors"):
        if section not in data:
            raise ConfigError(f"missing required section: {section}")

        if not isinstance(data[section], dict):
            raise ConfigError(f"section must be a mapping: {section}")

    poll_interval = data["runtime"].get("poll_interval_seconds")

    if (
        isinstance(poll_interval, bool)
        or not isinstance(poll_interval, (int, float))
        or poll_interval <= 0
    ):
        raise ConfigError(
            "runtime.poll_interval_seconds must be a positive number"
        )

    for key in ("events_path", "alerts_path"):
        value = data["storage"].get(key)

        if not isinstance(value, str) or not value.strip():
            raise ConfigError(f"storage.{key} must be a non-empty string")

    state_directory = data["runtime"].get("state_directory")

    if not isinstance(state_directory, str) or not state_directory.strip():
        raise ConfigError(
            "runtime.state_directory must be a non-empty string"
        )

    file_integrity = data["monitors"].get("file_integrity")

    if not isinstance(file_integrity, dict):
        raise ConfigError(
            "monitors.file_integrity must be a mapping"
        )

    enabled = file_integrity.get("enabled")

    if not isinstance(enabled, bool):
        raise ConfigError(
            "monitors.file_integrity.enabled must be a boolean"
        )

    paths = file_integrity.get("paths")

    if (
        not isinstance(paths, list)
        or not paths
        or not all(
            isinstance(path, str) and path.strip()
            for path in paths
        )
    ):
        raise ConfigError(
            "monitors.file_integrity.paths must be "
            "a non-empty list of strings"
        )

    authentication = data["monitors"].get("authentication")

    if not isinstance(authentication, dict):
        raise ConfigError(
            "monitors.authentication must be a mapping"
        )

    authentication_enabled = authentication.get("enabled")

    if not isinstance(authentication_enabled, bool):
        raise ConfigError(
            "monitors.authentication.enabled must be a boolean"
        )

    authentication_log_path = authentication.get("log_path")

    if (
        not isinstance(authentication_log_path, str)
        or not authentication_log_path.strip()
    ):
        raise ConfigError(
            "monitors.authentication.log_path must be "
            "a non-empty string"
        )

    processes = data["monitors"].get("processes")

    if not isinstance(processes, dict):
        raise ConfigError("monitors.processes must be a mapping")

    processes_enabled = processes.get("enabled")

    if not isinstance(processes_enabled, bool):
        raise ConfigError(
            "monitors.processes.enabled must be a boolean"
        )

    return data
