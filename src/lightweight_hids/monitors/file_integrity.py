import json
import socket
from dataclasses import asdict, dataclass
from hashlib import sha256
from pathlib import Path
from typing import Iterable

from lightweight_hids.models import Event


@dataclass(frozen=True)
class FileState:
    path: str
    sha256: str
    size: int
    mode: int
    modified_time_ns: int


def calculate_sha256(path: Path) -> str:
    digest = sha256()

    with path.open("rb") as file:
        while chunk := file.read(8192):
            digest.update(chunk)

    return digest.hexdigest()


def inspect_file(path: Path) -> FileState:
    metadata = path.stat()

    return FileState(
        path=str(path),
        sha256=calculate_sha256(path),
        size=metadata.st_size,
        mode=metadata.st_mode,
        modified_time_ns=metadata.st_mtime_ns,
    )

def build_snapshot(paths: Iterable[Path]) -> dict[str, FileState]:
    snapshot: dict[str, FileState] = {}

    for monitored_path in paths:
        monitored_path = monitored_path.resolve()

        if monitored_path.is_file():
            snapshot[str(monitored_path)] = inspect_file(monitored_path)

        elif monitored_path.is_dir():
            for file_path in sorted(monitored_path.rglob("*")):
                if file_path.is_file() and not file_path.is_symlink():
                    resolved_path = file_path.resolve()
                    snapshot[str(resolved_path)] = inspect_file(resolved_path)

    return snapshot

def save_baseline(
    baseline_path: Path,
    snapshot: dict[str, FileState],
) -> None:
    baseline_path.parent.mkdir(parents=True, exist_ok=True)

    baseline_data = {
        path: asdict(state)
        for path, state in snapshot.items()
    }

    baseline_path.write_text(
        json.dumps(baseline_data, indent=2, sort_keys=True),
        encoding="utf-8",
    )


def load_baseline(baseline_path: Path) -> dict[str, FileState]:
    baseline_data = json.loads(
        baseline_path.read_text(encoding="utf-8")
    )

    return {
        path: FileState(**state_data)
        for path, state_data in baseline_data.items()
    }

def compare_snapshots(
    baseline: dict[str, FileState],
    current: dict[str, FileState],
    host: str,
) -> list[Event]:
    events: list[Event] = []

    baseline_paths = set(baseline)
    current_paths = set(current)

    added_paths = current_paths - baseline_paths
    deleted_paths = baseline_paths - current_paths
    common_paths = baseline_paths & current_paths

    for path in sorted(added_paths):
        events.append(
            Event(
                event_type="file_added",
                source="file_integrity",
                host=host,
                data={
                    "path": path,
                    "current_state": asdict(current[path]),
                },
                raw=None,
            )
        )

    for path in sorted(deleted_paths):
        events.append(
            Event(
                event_type="file_deleted",
                source="file_integrity",
                host=host,
                data={
                    "path": path,
                    "baseline_state": asdict(baseline[path]),
                },
                raw=None,
            )
        )

    for path in sorted(common_paths):
        old_state = baseline[path]
        new_state = current[path]

        if old_state.sha256 != new_state.sha256:
            events.append(
                Event(
                    event_type="file_modified",
                    source="file_integrity",
                    host=host,
                    data={
                        "path": path,
                        "baseline_state": asdict(old_state),
                        "current_state": asdict(new_state),
                    },
                    raw=None,
                )
            )

        if old_state.mode != new_state.mode:
            events.append(
                Event(
                    event_type="file_metadata_changed",
                    source="file_integrity",
                    host=host,
                    data={
                        "path": path,
                        "changed_fields": ["mode"],
                        "baseline_state": asdict(old_state),
                        "current_state": asdict(new_state),
                    },
                    raw=None,
                )
            )

    return events


def finding_record(event: Event) -> dict[str, object]:
    """Return the stable parts that identify one active file finding."""
    return {
        "event_type": event.event_type,
        "data": dict(event.data),
    }


def finding_signature(record: dict[str, object]) -> str:
    """Return a canonical string used to compare active findings."""
    return json.dumps(record, sort_keys=True, separators=(",", ":"))


def save_active_findings(path: Path, events: Iterable[Event]) -> None:
    """Persist the file differences currently active."""
    path.parent.mkdir(parents=True, exist_ok=True)
    records = [finding_record(event) for event in events]
    path.write_text(
        json.dumps(records, indent=2, sort_keys=True),
        encoding="utf-8",
    )


def load_active_signatures(path: Path) -> set[str]:
    """Load signatures for previously reported active findings."""
    if not path.exists():
        return set()

    records = json.loads(path.read_text(encoding="utf-8"))
    return {finding_signature(record) for record in records}

class FileIntegrityMonitor:
    def __init__(
        self,
        paths: Iterable[Path],
        baseline_path: Path,
        active_state_path: Path,
        host: str | None = None,
    ) -> None:
        self.paths = tuple(paths)
        self.baseline_path = baseline_path
        self.active_state_path = active_state_path
        self.host = host or socket.gethostname()

    def initialize(self) -> dict[str, FileState]:
        snapshot = build_snapshot(self.paths)
        save_baseline(self.baseline_path, snapshot)
        save_active_findings(self.active_state_path, [])
        return snapshot

    def scan(self) -> list[Event]:
        if not self.baseline_path.exists():
            raise FileNotFoundError(
                "File-integrity baseline does not exist. "
                "Initialize the monitor before scanning."
            )

        baseline = load_baseline(self.baseline_path)
        current = build_snapshot(self.paths)

        current_findings = compare_snapshots(
            baseline=baseline,
            current=current,
            host=self.host,
        )
        previous_signatures = load_active_signatures(
            self.active_state_path
        )
        new_events = [
            event
            for event in current_findings
            if finding_signature(finding_record(event))
            not in previous_signatures
        ]
        save_active_findings(
            self.active_state_path,
            current_findings,
        )
        return new_events
