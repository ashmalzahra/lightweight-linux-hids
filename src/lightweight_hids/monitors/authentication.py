"""Parse Linux authentication records into normalized Events."""

import json
import re
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path

from lightweight_hids.models import Event


LOG_LINE_PATTERN = re.compile(
    r"^(?P<timestamp>\S+)\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<program>[A-Za-z0-9_.-]+)(?:\[\d+\])?:\s+"
    r"(?P<message>.*)$"
)
FIELD_PATTERN = re.compile(
    r"(?P<key>logname|uid|euid|tty|ruser|rhost|user)="
    r"(?P<value>\S*)"
)
SUDO_FAILURE_MARKER = "pam_unix(sudo:auth): authentication failure;"


@dataclass(frozen=True, slots=True)
class LogCursor:
    """Remember a byte position in one particular log file."""

    device: int
    inode: int
    offset: int


def parse_authentication_line(line: str) -> Event | None:
    """Return a normalized sudo-authentication failure, or None."""
    match = LOG_LINE_PATTERN.match(line.strip())

    if match is None:
        return None

    if match.group("program") != "sudo":
        return None

    message = match.group("message")

    if SUDO_FAILURE_MARKER not in message:
        return None

    try:
        timestamp = datetime.fromisoformat(match.group("timestamp"))
    except ValueError:
        return None

    if timestamp.tzinfo is None or timestamp.utcoffset() is None:
        return None

    fields = {
        field_match.group("key"): field_match.group("value")
        for field_match in FIELD_PATTERN.finditer(message)
    }

    return Event(
        event_type="authentication_failed",
        source="authentication",
        host=match.group("host"),
        timestamp=timestamp,
        data={
            "service": "sudo",
            "user": fields.get("user") or None,
            "uid": int(fields["uid"]) if fields.get("uid") else None,
            "effective_uid": (
                int(fields["euid"]) if fields.get("euid") else None
            ),
            "terminal": fields.get("tty") or None,
            "requesting_user": fields.get("ruser") or None,
            "remote_host": fields.get("rhost") or None,
        },
        raw=line.rstrip("\n"),
    )


def save_cursor(path: Path, cursor: LogCursor) -> None:
    """Persist an authentication-log cursor as JSON."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(asdict(cursor), indent=2, sort_keys=True),
        encoding="utf-8",
    )


def load_cursor(path: Path) -> LogCursor:
    """Load a previously persisted authentication-log cursor."""
    data = json.loads(path.read_text(encoding="utf-8"))
    return LogCursor(**data)


class AuthenticationMonitor:
    """Read only newly appended complete authentication-log lines."""

    def __init__(self, log_path: Path, state_path: Path) -> None:
        self.log_path = log_path
        self.state_path = state_path

    def initialize(self) -> LogCursor:
        """Trust existing records and begin monitoring at end of file."""
        metadata = self.log_path.stat()
        cursor = LogCursor(
            device=metadata.st_dev,
            inode=metadata.st_ino,
            offset=metadata.st_size,
        )
        save_cursor(self.state_path, cursor)
        return cursor

    def scan(self) -> list[Event]:
        """Parse relevant records appended since the previous scan."""
        if not self.state_path.exists():
            raise FileNotFoundError(
                "Authentication-log cursor does not exist. "
                "Initialize the monitor before scanning."
            )

        previous = load_cursor(self.state_path)
        metadata = self.log_path.stat()
        same_file = (
            previous.device == metadata.st_dev
            and previous.inode == metadata.st_ino
        )
        offset = previous.offset

        if not same_file or metadata.st_size < previous.offset:
            offset = 0

        events: list[Event] = []
        new_offset = offset

        with self.log_path.open("rb") as log_file:
            log_file.seek(offset)

            while True:
                line_start = log_file.tell()
                encoded_line = log_file.readline()

                if not encoded_line:
                    new_offset = log_file.tell()
                    break

                if not encoded_line.endswith(b"\n"):
                    new_offset = line_start
                    break

                line = encoded_line.decode("utf-8", errors="replace")
                event = parse_authentication_line(line)

                if event is not None:
                    events.append(event)

                new_offset = log_file.tell()

        save_cursor(
            self.state_path,
            LogCursor(
                device=metadata.st_dev,
                inode=metadata.st_ino,
                offset=new_offset,
            ),
        )
        return events
