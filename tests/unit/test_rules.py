"""Unit tests for configurable single-event rules."""

from pathlib import Path

import pytest

from lightweight_hids.models import Event
from lightweight_hids.rules import (
    RuleEngine,
    SingleEventRule,
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
