"""Integration tests for the HIDS command-line interface."""

from pathlib import Path

from lightweight_hids.cli import main
from lightweight_hids.storage import JsonlStore


def test_cli_initializes_and_scans_file_integrity(tmp_path, capsys) -> None:
    project_root = Path(__file__).parents[2]
    config_path = tmp_path / "config.yaml"
    config_text = (project_root / "config" / "default.yaml").read_text(
        encoding="utf-8"
    )
    config_path.write_text(
        config_text.replace(
            "authentication:\n    enabled: true",
            "authentication:\n    enabled: false",
        ).replace(
            "processes:\n    enabled: true",
            "processes:\n    enabled: false",
        ),
        encoding="utf-8",
    )
    monitored_directory = tmp_path / "var" / "lab" / "monitored"
    monitored_directory.mkdir(parents=True)
    monitored_file = monitored_directory / "important.txt"
    monitored_file.write_text("trusted content", encoding="utf-8")

    common_arguments = [
        "--config",
        str(config_path),
        "--rules",
        str(project_root / "config" / "rules.yaml"),
        "--base-directory",
        str(tmp_path),
    ]

    initialize_result = main([*common_arguments, "initialize"])
    initialize_output = capsys.readouterr().out

    assert initialize_result == 0
    assert "Initialized 1 monitor(s)." in initialize_output

    monitored_file.unlink()

    scan_result = main([*common_arguments, "scan"])
    scan_output = capsys.readouterr().out

    assert scan_result == 0
    assert "Detected 1 event(s); generated 1 alert(s)." in scan_output

    stored_events = JsonlStore(tmp_path / "var" / "events.jsonl").read_all()
    stored_alerts = JsonlStore(tmp_path / "var" / "alerts.jsonl").read_all()

    assert stored_events[0]["event_type"] == "file_deleted"
    assert stored_alerts[0]["rule_id"] == "FIM-001"

    show_events_result = main(
        [
            *common_arguments,
            "show-events",
            "--source",
            "file_integrity",
            "--event-type",
            "file_deleted",
            "--limit",
            "1",
        ]
    )
    events_output = capsys.readouterr().out

    assert show_events_result == 0
    assert '"event_type": "file_deleted"' in events_output

    show_alerts_result = main(
        [
            *common_arguments,
            "show-alerts",
            "--rule-id",
            "FIM-001",
            "--limit",
            "1",
        ]
    )
    alerts_output = capsys.readouterr().out

    assert show_alerts_result == 0
    assert '"rule_id": "FIM-001"' in alerts_output
