"""Application orchestration for the HIDS components."""

from lightweight_hids.models import Alert, Event
from lightweight_hids.monitors.file_integrity import (
    FileIntegrityMonitor,
    FileState,
)
from lightweight_hids.rules import RuleEngine
from lightweight_hids.storage import JsonlStore


class HidsApplication:
    """Coordinate monitoring, rule evaluation, and storage."""

    def __init__(
        self,
        monitor: FileIntegrityMonitor,
        rule_engine: RuleEngine,
        event_store: JsonlStore,
        alert_store: JsonlStore,
    ) -> None:
        self.monitor = monitor
        self.rule_engine = rule_engine
        self.event_store = event_store
        self.alert_store = alert_store

    def initialize_baseline(self) -> dict[str, FileState]:
        """Create or deliberately replace the trusted file baseline."""
        return self.monitor.initialize()

    def scan_once(self) -> tuple[list[Event], list[Alert]]:
        """Run one scan, persist events, and persist generated alerts."""
        events = self.monitor.scan()
        alerts: list[Alert] = []

        for event in events:
            self.event_store.append(event)
            generated_alerts = self.rule_engine.evaluate(event)

            for alert in generated_alerts:
                self.alert_store.append(alert)

            alerts.extend(generated_alerts)

        return events, alerts
