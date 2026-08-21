"""Unit tests for Linux authentication-log parsing."""

from datetime import timedelta

from lightweight_hids.monitors.authentication import (
    parse_authentication_line,
)


FAILURE_LINE = (
    "2026-08-20T23:50:20.428508+05:00 ashmal-VirtualBox sudo: "
    "pam_unix(sudo:auth): authentication failure; "
    "logname= uid=1000 euid=0 tty=/dev/pts/0 "
    "ruser=ashmal rhost= user=ashmal"
)


def test_parse_sudo_authentication_failure() -> None:
    event = parse_authentication_line(FAILURE_LINE)

    assert event is not None
    assert event.event_type == "authentication_failed"
    assert event.source == "authentication"
    assert event.host == "ashmal-VirtualBox"
    assert event.timestamp.utcoffset() == timedelta(hours=5)
    assert event.data == {
        "service": "sudo",
        "user": "ashmal",
        "uid": 1000,
        "effective_uid": 0,
        "terminal": "/dev/pts/0",
        "requesting_user": "ashmal",
        "remote_host": None,
    }
    assert event.raw == FAILURE_LINE


def test_ignore_cron_session_record() -> None:
    line = (
        "2026-08-20T23:45:01.487126+05:00 "
        "ashmal-VirtualBox CRON[8235]: "
        "pam_unix(cron:session): session opened for user root"
    )

    assert parse_authentication_line(line) is None


def test_ignore_successful_sudo_session_record() -> None:
    line = (
        "2026-08-20T23:50:39.364597+05:00 "
        "ashmal-VirtualBox sudo: "
        "pam_unix(sudo:session): session opened for user root(uid=0)"
    )

    assert parse_authentication_line(line) is None


def test_ignore_malformed_log_line() -> None:
    assert parse_authentication_line("not a valid auth log line") is None
