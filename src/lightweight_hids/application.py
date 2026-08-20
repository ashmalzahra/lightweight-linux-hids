"""Application orchestration for the HIDS components."""

from pathlib import Path

from lightweight_hids.config import ConfigError, load_config
from lightweight_hids.models import Alert, Event
from lightweight_hids.monitors.file_integrity import (
    FileIntegrityMonitor,
    FileState,
)
from lightweight_hids.rules import RuleEngine, load_rules
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


def resolve_path(base_directory: Path, configured_path: str | Path) -> Path:
    """Resolve a configured path relative to the application base directory."""
    path = Path(configured_path)

    if path.is_absolute():
        return path

    return (base_directory / path).resolve()


def create_application(
    config_path: str | Path,
    rules_path: str | Path,
    base_directory: str | Path,
) -> HidsApplication:
    """Build a configured file-integrity HIDS application."""
    base = Path(base_directory).resolve()
    config = load_config(resolve_path(base, config_path))
    file_integrity = config["monitors"]["file_integrity"]

    if not file_integrity["enabled"]:
        raise ConfigError("file-integrity monitor is disabled")

    monitored_paths = [
        resolve_path(base, path)
        for path in file_integrity["paths"]
    ]
    state_directory = resolve_path(
        base,
        config["runtime"]["state_directory"],
    )
    monitor = FileIntegrityMonitor(
        paths=monitored_paths,
        baseline_path=(
            state_directory / "file_integrity_baseline.json"
        ),
    )
    rule_engine = RuleEngine(
        load_rules(resolve_path(base, rules_path))
    )
    event_store = JsonlStore(
        resolve_path(base, config["storage"]["events_path"])
    )
    alert_store = JsonlStore(
        resolve_path(base, config["storage"]["alerts_path"])
    )

    return HidsApplication(
        monitor=monitor,
        rule_engine=rule_engine,
        event_store=event_store,
        alert_store=alert_store,
    )
