"""Polling-based Linux process activity monitoring."""

import json
import socket
from collections.abc import Callable, Iterable
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import psutil

from lightweight_hids.models import Event


@dataclass(frozen=True, slots=True)
class ProcessState:
    """Observable state for one running process."""

    pid: int
    create_time: float
    parent_pid: int | None
    name: str | None
    executable: str | None
    command_line: list[str]
    username: str | None

    @property
    def identity(self) -> str:
        """Identify this process instance despite later PID reuse."""
        return f"{self.pid}:{self.create_time!r}"


def collect_process_snapshot(
    process_provider: Callable[..., Iterable[Any]] = psutil.process_iter,
) -> dict[str, ProcessState]:
    """Collect the processes that can be observed safely."""
    snapshot: dict[str, ProcessState] = {}
    attributes = [
        "pid",
        "create_time",
        "ppid",
        "name",
        "exe",
        "cmdline",
        "username",
    ]

    for process in process_provider(attrs=attributes, ad_value=None):
        try:
            information = process.info
            create_time = information.get("create_time")

            if create_time is None:
                continue

            state = ProcessState(
                pid=int(information["pid"]),
                create_time=float(create_time),
                parent_pid=information.get("ppid"),
                name=information.get("name"),
                executable=information.get("exe"),
                command_line=list(information.get("cmdline") or []),
                username=information.get("username"),
            )
        except (
            KeyError,
            TypeError,
            ValueError,
            psutil.AccessDenied,
            psutil.NoSuchProcess,
            psutil.ZombieProcess,
        ):
            continue

        snapshot[state.identity] = state

    return snapshot


def save_process_snapshot(
    path: Path,
    snapshot: dict[str, ProcessState],
) -> None:
    """Persist the most recently observed process snapshot."""
    path.parent.mkdir(parents=True, exist_ok=True)
    data = {
        identity: asdict(state)
        for identity, state in snapshot.items()
    }
    path.write_text(
        json.dumps(data, indent=2, sort_keys=True),
        encoding="utf-8",
    )


def load_process_snapshot(path: Path) -> dict[str, ProcessState]:
    """Load the previously observed process snapshot."""
    data = json.loads(path.read_text(encoding="utf-8"))
    return {
        identity: ProcessState(**state_data)
        for identity, state_data in data.items()
    }


def compare_process_snapshots(
    previous: dict[str, ProcessState],
    current: dict[str, ProcessState],
    host: str,
) -> list[Event]:
    """Return process-started and process-stopped Events."""
    events: list[Event] = []
    previous_identities = set(previous)
    current_identities = set(current)

    for identity in sorted(current_identities - previous_identities):
        state = current[identity]
        events.append(
            Event(
                event_type="process_started",
                source="processes",
                host=host,
                timestamp=datetime.fromtimestamp(
                    state.create_time,
                    tz=timezone.utc,
                ),
                data=asdict(state),
            )
        )

    for identity in sorted(previous_identities - current_identities):
        state = previous[identity]
        events.append(
            Event(
                event_type="process_stopped",
                source="processes",
                host=host,
                data=asdict(state),
            )
        )

    return events


class ProcessMonitor:
    """Compare consecutive process snapshots."""

    def __init__(
        self,
        state_path: Path,
        host: str | None = None,
        collector: Callable[[], dict[str, ProcessState]] = (
            collect_process_snapshot
        ),
    ) -> None:
        self.state_path = state_path
        self.host = host or socket.gethostname()
        self.collector = collector

    def initialize(self) -> dict[str, ProcessState]:
        """Record currently running processes without emitting Events."""
        snapshot = self.collector()
        save_process_snapshot(self.state_path, snapshot)
        return snapshot

    def scan(self) -> list[Event]:
        """Compare current processes with the previous observation."""
        if not self.state_path.exists():
            raise FileNotFoundError(
                "Process snapshot does not exist. "
                "Initialize the monitor before scanning."
            )

        previous = load_process_snapshot(self.state_path)
        current = self.collector()
        events = compare_process_snapshots(
            previous=previous,
            current=current,
            host=self.host,
        )
        save_process_snapshot(self.state_path, current)
        return events
