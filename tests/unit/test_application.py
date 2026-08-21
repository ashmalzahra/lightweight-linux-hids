"""Unit tests for application construction."""

from pathlib import Path

from lightweight_hids.application import create_application
from lightweight_hids.monitors.authentication import AuthenticationMonitor
from lightweight_hids.monitors.file_integrity import FileIntegrityMonitor


def test_create_application_resolves_configured_paths(tmp_path) -> None:
    project_root = Path(__file__).parents[2]

    application = create_application(
        config_path=project_root / "config" / "default.yaml",
        rules_path=project_root / "config" / "rules.yaml",
        base_directory=tmp_path,
    )

    file_integrity_monitor = next(
        monitor
        for monitor in application.monitors
        if isinstance(monitor, FileIntegrityMonitor)
    )
    authentication_monitor = next(
        monitor
        for monitor in application.monitors
        if isinstance(monitor, AuthenticationMonitor)
    )

    assert len(application.monitors) == 2
    assert file_integrity_monitor.paths == (
        (tmp_path / "var" / "lab" / "monitored").resolve(),
    )
    assert file_integrity_monitor.baseline_path == (
        tmp_path / ".hids-state" / "file_integrity_baseline.json"
    ).resolve()
    assert authentication_monitor.state_path == (
        tmp_path / ".hids-state" / "authentication_cursor.json"
    ).resolve()
    assert application.event_store.path == (
        tmp_path / "var" / "events.jsonl"
    ).resolve()
    assert application.alert_store.path == (
        tmp_path / "var" / "alerts.jsonl"
    ).resolve()
    assert len(application.rule_engine.rules) == 5
