"""Unit tests for concise command-line scan reporting."""

from lightweight_hids.cli import report_scan
from lightweight_hids.models import Alert, Event


def test_report_scan_shows_process_details_and_alert(capsys) -> None:
    event = Event(
        event_type="process_started",
        source="processes",
        host="test-host",
        data={
            "name": "hids-lab-agent",
            "pid": 1234,
            "username": "ashmal",
        },
        event_id="event-123",
    )
    alert = Alert(
        rule_id="PROC-001",
        title="Controlled laboratory process started",
        description="A controlled test process was observed.",
        severity="medium",
        event_ids=[event.event_id],
        evidence=event.data,
    )

    report_scan([event], [alert])

    output = capsys.readouterr().out
    assert "EVENT  processes  process_started" in output
    assert "name=hids-lab-agent pid=1234 user=ashmal" in output
    assert "ALERT  PROC-001  severity=medium" in output
    assert "Controlled laboratory process started" in output
    assert "Summary: 1 event(s), 1 alert(s)." in output


def test_report_scan_shows_source_specific_event_details(capsys) -> None:
    file_event = Event(
        event_type="file_modified",
        source="file_integrity",
        host="test-host",
        data={"path": "var/lab/monitored/example.txt"},
    )
    authentication_event = Event(
        event_type="authentication_failed",
        source="authentication",
        host="test-host",
        data={
            "service": "sudo",
            "user": "ashmal",
            "terminal": "/dev/pts/0",
        },
    )

    report_scan([file_event, authentication_event], [])

    output = capsys.readouterr().out
    assert "path=var/lab/monitored/example.txt" in output
    assert "service=sudo user=ashmal terminal=/dev/pts/0" in output
    assert "Summary: 2 event(s), 0 alert(s)." in output


def test_report_scan_prints_nothing_when_scan_is_empty(capsys) -> None:
    report_scan([], [])

    assert capsys.readouterr().out == ""
