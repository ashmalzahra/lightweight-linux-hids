"""Unit tests for Linux authentication-log parsing."""

from datetime import timedelta

from lightweight_hids.monitors.authentication import (
    AuthenticationMonitor,
    load_cursor,
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


def test_monitor_reads_new_failure_once(tmp_path) -> None:
    log_path = tmp_path / "auth.log"
    state_path = tmp_path / "state" / "authentication_cursor.json"
    log_path.write_text(
        "an existing historical record\n",
        encoding="utf-8",
    )
    monitor = AuthenticationMonitor(log_path, state_path)

    initial_cursor = monitor.initialize()

    assert initial_cursor.offset == log_path.stat().st_size
    assert monitor.scan() == []

    with log_path.open("a", encoding="utf-8") as log_file:
        log_file.write(f"{FAILURE_LINE}\n")

    first_scan = monitor.scan()
    second_scan = monitor.scan()

    assert len(first_scan) == 1
    assert first_scan[0].event_type == "authentication_failed"
    assert second_scan == []
    assert load_cursor(state_path).offset == log_path.stat().st_size


def test_monitor_waits_for_complete_line(tmp_path) -> None:
    log_path = tmp_path / "auth.log"
    state_path = tmp_path / "authentication_cursor.json"
    log_path.write_text("", encoding="utf-8")
    monitor = AuthenticationMonitor(log_path, state_path)
    monitor.initialize()

    with log_path.open("a", encoding="utf-8") as log_file:
        log_file.write(FAILURE_LINE)

    assert monitor.scan() == []
    assert load_cursor(state_path).offset == 0

    with log_path.open("a", encoding="utf-8") as log_file:
        log_file.write("\n")

    events = monitor.scan()

    assert len(events) == 1
    assert events[0].event_type == "authentication_failed"
