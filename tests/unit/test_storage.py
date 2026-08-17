"""Unit tests for JSON Lines storage."""

import json

from lightweight_hids.models import Alert, Event
from lightweight_hids.storage import JsonlStore


def test_store_writes_event(tmp_path) -> None:
    output_path = tmp_path / "nested" / "events.jsonl"
    store = JsonlStore(output_path)

    event = Event(
        event_type="file_modified",
        source="file_integrity",
        host="test-host",
        data={"path": "/tmp/example.txt"},
        event_id="event-1",
    )

    store.append(event)

    assert output_path.exists()

    lines = output_path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1

    record = json.loads(lines[0])
    assert record["event_id"] == "event-1"
    assert record["event_type"] == "file_modified"


def test_store_appends_without_overwriting(tmp_path) -> None:
    store = JsonlStore(tmp_path / "alerts.jsonl")

    first = Alert(
        rule_id="TEST-001",
        title="First alert",
        description="First test alert",
        severity="low",
        event_ids=["event-1"],
        evidence={},
        alert_id="alert-1",
    )
    second = Alert(
        rule_id="TEST-002",
        title="Second alert",
        description="Second test alert",
        severity="medium",
        event_ids=["event-2"],
        evidence={},
        alert_id="alert-2",
    )

    store.append(first)
    store.append(second)

    records = store.read_all()

    assert len(records) == 2
    assert records[0]["alert_id"] == "alert-1"
    assert records[1]["alert_id"] == "alert-2"


def test_read_all_returns_empty_list_for_missing_file(tmp_path) -> None:
    store = JsonlStore(tmp_path / "missing.jsonl")

    assert store.read_all() == []