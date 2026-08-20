"""Unit tests for application construction."""

from pathlib import Path

from lightweight_hids.application import create_application


def test_create_application_resolves_configured_paths(tmp_path) -> None:
    project_root = Path(__file__).parents[2]

    application = create_application(
        config_path=project_root / "config" / "default.yaml",
        rules_path=project_root / "config" / "rules.yaml",
        base_directory=tmp_path,
    )

    assert application.monitor.paths == (
        (tmp_path / "var" / "lab" / "monitored").resolve(),
    )
    assert application.monitor.baseline_path == (
        tmp_path / ".hids-state" / "file_integrity_baseline.json"
    ).resolve()
    assert application.event_store.path == (
        tmp_path / "var" / "events.jsonl"
    ).resolve()
    assert application.alert_store.path == (
        tmp_path / "var" / "alerts.jsonl"
    ).resolve()
    assert len(application.rule_engine.rules) == 2
