"""Integration test for the file-integrity detection pipeline."""

from pathlib import Path

from lightweight_hids.application import HidsApplication
from lightweight_hids.monitors.file_integrity import FileIntegrityMonitor
from lightweight_hids.rules import RuleEngine, load_rules
from lightweight_hids.storage import JsonlStore


def test_deleted_file_produces_stored_event_and_alert(tmp_path) -> None:
    monitored_directory = tmp_path / "monitored"
    monitored_directory.mkdir()

    monitored_file = monitored_directory / "important.txt"
    monitored_file.write_text("trusted content", encoding="utf-8")

    project_root = Path(__file__).parents[2]
    rule_engine = RuleEngine(load_rules(project_root / "config" / "rules.yaml"))
    event_store = JsonlStore(tmp_path / "output" / "events.jsonl")
    alert_store = JsonlStore(tmp_path / "output" / "alerts.jsonl")
    monitor = FileIntegrityMonitor(
        paths=[monitored_directory],
        baseline_path=tmp_path / "state" / "baseline.json",
        host="test-host",
    )
    application = HidsApplication(
        monitor=monitor,
        rule_engine=rule_engine,
        event_store=event_store,
        alert_store=alert_store,
    )

    application.initialize_baseline()
    monitored_file.unlink()

    events, alerts = application.scan_once()

    assert len(events) == 1
    assert events[0].event_type == "file_deleted"
    assert len(alerts) == 1
    assert alerts[0].rule_id == "FIM-001"
    assert alerts[0].event_ids == [events[0].event_id]

    stored_events = event_store.read_all()
    stored_alerts = alert_store.read_all()

    assert stored_events[0]["event_id"] == events[0].event_id
    assert stored_alerts[0]["alert_id"] == alerts[0].alert_id
