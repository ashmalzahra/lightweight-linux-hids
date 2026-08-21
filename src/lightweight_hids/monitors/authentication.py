"""Parse Linux authentication records into normalized Events."""

import re
from datetime import datetime

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
