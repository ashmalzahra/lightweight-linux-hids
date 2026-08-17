"""Core event and alert data models."""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4


def utc_now() -> datetime:
    """Return the current time as a timezone-aware UTC datetime."""
    return datetime.now(timezone.utc)


def new_id() -> str:
    """Return a random UUID encoded as a string."""
    return str(uuid4())


def require_aware_datetime(value: datetime, field_name: str) -> None:
    """Reject timestamps that do not include timezone information."""
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{field_name} must be timezone-aware")


@dataclass(slots=True)
class Event:
    """A normalized observation produced by a monitor."""

    event_type: str
    source: str
    host: str
    data: dict[str, Any]
    raw: str | None = None
    timestamp: datetime = field(default_factory=utc_now)
    event_id: str = field(default_factory=new_id)

    def __post_init__(self) -> None:
        """Validate the event immediately after creation."""
        if not self.event_type.strip():
            raise ValueError("event_type cannot be empty")

        if not self.source.strip():
            raise ValueError("source cannot be empty")

        if not self.host.strip():
            raise ValueError("host cannot be empty")

        require_aware_datetime(self.timestamp, "timestamp")

    def to_dict(self) -> dict[str, Any]:
        """Convert the event into a JSON-compatible dictionary."""
        return {
            "event_id": self.event_id,
            "event_type": self.event_type,
            "timestamp": self.timestamp.astimezone(timezone.utc).isoformat(),
            "source": self.source,
            "host": self.host,
            "data": dict(self.data),
            "raw": self.raw,
        }


@dataclass(slots=True)
class Alert:
    """A structured alert produced when a detection rule matches."""

    rule_id: str
    title: str
    description: str
    severity: str
    event_ids: list[str]
    evidence: dict[str, Any]
    timestamp: datetime = field(default_factory=utc_now)
    alert_id: str = field(default_factory=new_id)

    ALLOWED_SEVERITIES = {"info", "low", "medium", "high", "critical"}

    def __post_init__(self) -> None:
        """Validate the alert immediately after creation."""
        if not self.rule_id.strip():
            raise ValueError("rule_id cannot be empty")

        if not self.title.strip():
            raise ValueError("title cannot be empty")

        if self.severity not in self.ALLOWED_SEVERITIES:
            allowed = ", ".join(sorted(self.ALLOWED_SEVERITIES))
            raise ValueError(f"severity must be one of: {allowed}")

        if not self.event_ids:
            raise ValueError("event_ids cannot be empty")

        require_aware_datetime(self.timestamp, "timestamp")

    def to_dict(self) -> dict[str, Any]:
        """Convert the alert into a JSON-compatible dictionary."""
        return {
            "alert_id": self.alert_id,
            "rule_id": self.rule_id,
            "timestamp": self.timestamp.astimezone(timezone.utc).isoformat(),
            "event_ids": list(self.event_ids),
            "title": self.title,
            "description": self.description,
            "severity": self.severity,
            "evidence": dict(self.evidence),
        }