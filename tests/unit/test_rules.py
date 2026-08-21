"""Unit tests for configurable detection rules."""

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from lightweight_hids.models import Event
from lightweight_hids.rules import (
    RuleEngine,
    SingleEventRule,
    ThresholdRule,
    load_rules,
)


def make_rule(**overrides) -> SingleEventRule:
    values = {
        "rule_id": "USER-001",
        "event_type": "privilege_group_membership_added",
        "title": "User added to administrative group",
        "description": "A user was added to sudo.",
        "severity": "high",
        "conditions": {"group": "sudo"},
        "enabled": True,
    }
    values.update(overrides)
    return SingleEventRule(**values)


def make_threshold_rule(**overrides) -> ThresholdRule:
    values = {
        "rule_id": "AUTH-001",
        "event_type": "authentication_failed",
        "title": "Repeated authentication failures",
        "description": "Three failures occurred within sixty seconds.",
        "severity": "high",
        "conditions": {"service": "sudo"},
        "group_by": ("user",),
        "threshold": 3,
        "window_seconds": 60.0,
        "enabled": True,
    }
    values.update(overrides)
    return ThresholdRule(**values)


def make_authentication_event(
    event_id: str,
    user: str,
    timestamp: datetime,
):
    return Event(
        event_type="authentication_failed",
        source="authentication",
        host="test-host",
        data={"service": "sudo", "user": user},
        timestamp=timestamp,
        event_id=event_id,
    )


def test_matching_event_generates_alert() -> None:
    event = Event(
        event_type="privilege_group_membership_added",
        source="user_monitor",
        host="test-host",
        data={"user": "testuser", "group": "sudo"},
        event_id="event-1",
    )
    engine = RuleEngine([make_rule()])

    alerts = engine.evaluate(event)

    assert len(alerts) == 1
    assert alerts[0].rule_id == "USER-001"
    assert alerts[0].event_ids == ["event-1"]
    assert alerts[0].evidence["user"] == "testuser"


def test_different_event_type_does_not_match() -> None:
    event = Event(
        event_type="user_created",
        source="user_monitor",
        host="test-host",
        data={"user": "testuser", "group": "sudo"},
    )
    engine = RuleEngine([make_rule()])

    assert engine.evaluate(event) == []


def test_condition_value_must_match() -> None:
    event = Event(
        event_type="privilege_group_membership_added",
        source="user_monitor",
        host="test-host",
        data={"user": "testuser", "group": "developers"},
    )
    engine = RuleEngine([make_rule()])

    assert engine.evaluate(event) == []


def test_disabled_rule_does_not_match() -> None:
    event = Event(
        event_type="privilege_group_membership_added",
        source="user_monitor",
        host="test-host",
        data={"user": "testuser", "group": "sudo"},
    )
    engine = RuleEngine([make_rule(enabled=False)])

    assert engine.evaluate(event) == []


def test_load_rules_from_yaml(tmp_path) -> None:
    rules_path = tmp_path / "rules.yaml"
    rules_path.write_text(
        """
rules:
  - id: TEST-001
    kind: single_event
    enabled: true
    event_type: file_deleted
    title: File deleted
    description: A monitored file was deleted.
    severity: high
    conditions: {}
""",
        encoding="utf-8",
    )

    rules = load_rules(rules_path)

    assert len(rules) == 1
    assert rules[0].rule_id == "TEST-001"
    assert rules[0].event_type == "file_deleted"


def test_load_threshold_rule_from_yaml(tmp_path) -> None:
    rules_path = tmp_path / "rules.yaml"
    rules_path.write_text(
        """
rules:
  - id: AUTH-001
    kind: threshold
    enabled: true
    event_type: authentication_failed
    title: Repeated authentication failures
    description: Three failures occurred within sixty seconds.
    severity: high
    conditions:
      service: sudo
    group_by:
      - user
    threshold: 3
    window_seconds: 60
""",
        encoding="utf-8",
    )

    rules = load_rules(rules_path)

    assert len(rules) == 1
    assert isinstance(rules[0], ThresholdRule)
    assert rules[0].group_by == ("user",)
    assert rules[0].threshold == 3
    assert rules[0].window_seconds == 60.0


@pytest.mark.parametrize(
    ("event_type", "expected_rule_id"),
    [
        ("file_deleted", "FIM-001"),
        ("file_modified", "FIM-002"),
        ("file_added", "FIM-003"),
        ("file_metadata_changed", "FIM-004"),
    ],
)
def test_configured_file_integrity_rules_generate_alerts(
    event_type,
    expected_rule_id,
) -> None:
    project_root = Path(__file__).parents[2]
    engine = RuleEngine(
        load_rules(project_root / "config" / "rules.yaml")
    )
    event = Event(
        event_type=event_type,
        source="file_integrity",
        host="test-host",
        data={"path": "/tmp/monitored/example.txt"},
    )

    alerts = engine.evaluate(event)

    assert len(alerts) == 1
    assert alerts[0].rule_id == expected_rule_id
    assert alerts[0].event_ids == [event.event_id]


def test_threshold_rule_alerts_on_third_failure() -> None:
    start = datetime(2026, 8, 21, 12, 0, tzinfo=timezone.utc)
    engine = RuleEngine([make_threshold_rule()])
    events = [
        make_authentication_event("event-1", "ashmal", start),
        make_authentication_event(
            "event-2",
            "ashmal",
            start + timedelta(seconds=20),
        ),
        make_authentication_event(
            "event-3",
            "ashmal",
            start + timedelta(seconds=40),
        ),
    ]

    assert engine.evaluate(events[0]) == []
    assert engine.evaluate(events[1]) == []

    alerts = engine.evaluate(events[2])

    assert len(alerts) == 1
    assert alerts[0].rule_id == "AUTH-001"
    assert alerts[0].event_ids == ["event-1", "event-2", "event-3"]
    assert alerts[0].evidence["count"] == 3
    assert alerts[0].evidence["group"] == {"user": "ashmal"}


def test_threshold_rule_does_not_combine_different_users() -> None:
    start = datetime(2026, 8, 21, 12, 0, tzinfo=timezone.utc)
    engine = RuleEngine([make_threshold_rule()])

    alerts = []

    for index, user in enumerate(("alice", "bob", "charlie")):
        event = make_authentication_event(
            f"event-{index}",
            user,
            start + timedelta(seconds=index),
        )
        alerts.extend(engine.evaluate(event))

    assert alerts == []


def test_threshold_rule_expires_old_failures() -> None:
    start = datetime(2026, 8, 21, 12, 0, tzinfo=timezone.utc)
    engine = RuleEngine([make_threshold_rule()])
    events = [
        make_authentication_event("event-1", "ashmal", start),
        make_authentication_event(
            "event-2",
            "ashmal",
            start + timedelta(seconds=30),
        ),
        make_authentication_event(
            "event-3",
            "ashmal",
            start + timedelta(seconds=61),
        ),
    ]

    alerts = []

    for event in events:
        alerts.extend(engine.evaluate(event))

    assert alerts == []
