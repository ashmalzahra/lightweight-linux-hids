"""Unit tests for the core data models."""

from datetime import datetime, timezone

import pytest

from lightweight_hids.models import Alert, Event


def test_event_creates_unique_ids() -> None:
    first = Event(
        event_type="file_modified",
        source="file_integrity",
        host="test-host",
        data={"path": "/tmp/example.txt"},
    )
    second = Event(
        event_type="file_modified",
        source="file_integrity",
        host="test-host",
        data={"path": "/tmp/example.txt"},
    )

    assert first.event_id != second.event_id


def test_event_serializes_to_json_compatible_dictionary() -> None:
    timestamp = datetime(2026, 8, 17, 1, 30, tzinfo=timezone.utc)

    event = Event(
        event_type="authentication_failure",
        source="systemd_journal",
        host="test-host",
        data={"user": "testuser", "source_ip": "192.168.56.10"},
        raw="Failed password for testuser",
        timestamp=timestamp,
        event_id="event-123",
    )

    result = event.to_dict()

    assert result["event_id"] == "event-123"
    assert result["event_type"] == "authentication_failure"
    assert result["timestamp"] == "2026-08-17T01:30:00+00:00"
    assert result["data"]["user"] == "testuser"
    assert result["raw"] == "Failed password for testuser"


def test_event_rejects_naive_timestamp() -> None:
    with pytest.raises(ValueError, match="timezone-aware"):
        Event(
            event_type="file_modified",
            source="file_integrity",
            host="test-host",
            data={},
            timestamp=datetime(2026, 8, 17, 1, 30),
        )


def test_event_rejects_empty_event_type() -> None:
    with pytest.raises(ValueError, match="event_type cannot be empty"):
        Event(
            event_type=" ",
            source="file_integrity",
            host="test-host",
            data={},
        )


def test_alert_serializes_to_json_compatible_dictionary() -> None:
    alert = Alert(
        rule_id="AUTH-001",
        title="Repeated authentication failures",
        description="Five failures occurred within sixty seconds.",
        severity="medium",
        event_ids=["event-1", "event-2"],
        evidence={"source_ip": "192.168.56.10", "count": 5},
        alert_id="alert-123",
    )

    result = alert.to_dict()

    assert result["alert_id"] == "alert-123"
    assert result["rule_id"] == "AUTH-001"
    assert result["severity"] == "medium"
    assert result["event_ids"] == ["event-1", "event-2"]
    assert result["evidence"]["count"] == 5


def test_alert_rejects_unknown_severity() -> None:
    with pytest.raises(ValueError, match="severity must be one of"):
        Alert(
            rule_id="TEST-001",
            title="Test alert",
            description="Test description",
            severity="extreme",
            event_ids=["event-1"],
            evidence={},
        )


def test_alert_requires_at_least_one_event() -> None:
    with pytest.raises(ValueError, match="event_ids cannot be empty"):
        Alert(
            rule_id="TEST-001",
            title="Test alert",
            description="Test description",
            severity="low",
            event_ids=[],
            evidence={},
        )