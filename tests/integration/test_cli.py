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
