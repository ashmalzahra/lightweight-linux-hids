"""Application orchestration for the HIDS components."""

from pathlib import Path
from typing import Iterable, Protocol

from lightweight_hids.config import ConfigError, load_config
from lightweight_hids.models import Alert, Event
from lightweight_hids.monitors.authentication import AuthenticationMonitor
from lightweight_hids.monitors.file_integrity import (
    FileIntegrityMonitor,
)
from lightweight_hids.monitors.processes import ProcessMonitor
from lightweight_hids.rules import RuleEngine, load_rules
from lightweight_hids.storage import JsonlStore


class Monitor(Protocol):
    """Behavior required from every application monitor."""

    def initialize(self) -> object:
        """Establish the monitor's initial trusted state."""
        ...

    def scan(self) -> list[Event]:
        """Return relevant events observed since initialization."""
        ...


class HidsApplication:
    """Coordinate monitoring, rule evaluation, and storage."""

    def __init__(
        self,
        monitors: Iterable[Monitor],
        rule_engine: RuleEngine,
        event_store: JsonlStore,
        alert_store: JsonlStore,
        poll_interval_seconds: float,
    ) -> None:
        self.monitors = tuple(monitors)
        self.rule_engine = rule_engine
        self.event_store = event_store
        self.alert_store = alert_store
        self.poll_interval_seconds = poll_interval_seconds

    def initialize_monitors(self) -> None:
        """Establish initial state for every enabled monitor."""
        for monitor in self.monitors:
            monitor.initialize()

    def scan_once(self) -> tuple[list[Event], list[Alert]]:
        """Run one scan, persist events, and persist generated alerts."""
        events: list[Event] = []
        alerts: list[Alert] = []

        for monitor in self.monitors:
            events.extend(monitor.scan())

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
    """Build a configured HIDS application."""
    base = Path(base_directory).resolve()
    config = load_config(resolve_path(base, config_path))
    state_directory = resolve_path(
        base,
        config["runtime"]["state_directory"],
    )
    monitors: list[Monitor] = []
    file_integrity = config["monitors"]["file_integrity"]

    if file_integrity["enabled"]:
        monitored_paths = [
            resolve_path(base, path)
            for path in file_integrity["paths"]
        ]
        monitors.append(
            FileIntegrityMonitor(
                paths=monitored_paths,
                baseline_path=(
                    state_directory / "file_integrity_baseline.json"
                ),
                active_state_path=(
                    state_directory / "file_integrity_active.json"
                ),
            )
        )

    authentication = config["monitors"]["authentication"]

    if authentication["enabled"]:
        monitors.append(
            AuthenticationMonitor(
                log_path=resolve_path(base, authentication["log_path"]),
                state_path=(
                    state_directory / "authentication_cursor.json"
                ),
            )
        )

    processes = config["monitors"]["processes"]

    if processes["enabled"]:
        monitors.append(
            ProcessMonitor(
                state_path=state_directory / "processes.json",
            )
        )

    if not monitors:
        raise ConfigError("at least one monitor must be enabled")

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
        monitors=monitors,
        rule_engine=rule_engine,
        event_store=event_store,
        alert_store=alert_store,
        poll_interval_seconds=float(
            config["runtime"]["poll_interval_seconds"]
        ),
    )
