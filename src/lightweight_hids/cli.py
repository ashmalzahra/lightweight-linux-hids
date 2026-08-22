"""Command-line interface for the lightweight HIDS."""

import argparse
import json
from pathlib import Path
from typing import Any, Sequence

from lightweight_hids.application import create_application
from lightweight_hids.models import Alert, Event
from lightweight_hids.runtime import run_polling


def format_event(event: Event) -> str:
    """Return a concise, human-readable description of one event."""
    heading = f"EVENT  {event.source}  {event.event_type}"

    if event.source == "processes":
        details = (
            f"name={event.data.get('name') or 'unknown'} "
            f"pid={event.data.get('pid', 'unknown')} "
            f"user={event.data.get('username') or 'unknown'}"
        )
    elif event.source == "file_integrity":
        details = f"path={event.data.get('path', 'unknown')}"
    elif event.source == "authentication":
        details = (
            f"service={event.data.get('service') or 'unknown'} "
            f"user={event.data.get('user') or 'unknown'} "
            f"terminal={event.data.get('terminal') or 'unknown'}"
        )
    else:
        details = f"event_id={event.event_id}"

    return f"{heading}\n       {details}"


def format_alert(alert: Alert) -> str:
    """Return a concise, human-readable description of one alert."""
    return (
        f"ALERT  {alert.rule_id}  severity={alert.severity}\n"
        f"       {alert.title}"
    )


def report_scan(events: list[Event], alerts: list[Alert]) -> None:
    """Print new event and alert details followed by a scan summary."""
    if not events and not alerts:
        return

    for event in events:
        print(format_event(event))

    for alert in alerts:
        print(format_alert(alert))

    print(
        f"Summary: {len(events)} event(s), {len(alerts)} alert(s)."
    )


def positive_integer(value: str) -> int:
    """Parse a command-line value that must be at least one."""
    parsed = int(value)

    if parsed < 1:
        raise argparse.ArgumentTypeError("value must be at least 1")

    return parsed


def print_records(records: list[dict[str, Any]]) -> None:
    """Print stored JSON records in a readable form."""
    if not records:
        print("No matching records found.")
        return

    for index, record in enumerate(records):
        if index:
            print()

        print(json.dumps(record, indent=2, sort_keys=True))


def build_parser() -> argparse.ArgumentParser:
    """Create the command-line argument parser."""
    parser = argparse.ArgumentParser(
        prog="lightweight-hids",
        description="Initialize or scan the lightweight Linux HIDS.",
    )
    parser.add_argument(
        "--config",
        default="config/default.yaml",
        help="path to the main YAML configuration file",
    )
    parser.add_argument(
        "--rules",
        default="config/rules.yaml",
        help="path to the YAML detection-rules file",
    )
    parser.add_argument(
        "--base-directory",
        default=Path.cwd(),
        help="directory used to resolve relative configured paths",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser(
        "initialize",
        help="create or deliberately replace the trusted baseline",
    )
    subparsers.add_parser(
        "scan",
        help="run one scan with every enabled monitor",
    )
    subparsers.add_parser(
        "run",
        help="continuously poll until interrupted",
    )
    events_parser = subparsers.add_parser(
        "show-events",
        help="show recent stored events",
    )
    events_parser.add_argument(
        "--limit",
        type=positive_integer,
        default=5,
        help="maximum number of matching events to show",
    )
    events_parser.add_argument(
        "--source",
        help="show only events from this monitor source",
    )
    events_parser.add_argument(
        "--event-type",
        help="show only this event type",
    )
    alerts_parser = subparsers.add_parser(
        "show-alerts",
        help="show recent stored alerts",
    )
    alerts_parser.add_argument(
        "--limit",
        type=positive_integer,
        default=5,
        help="maximum number of matching alerts to show",
    )
    alerts_parser.add_argument(
        "--rule-id",
        help="show only alerts produced by this rule",
    )

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run the command-line interface and return a process exit code."""
    args = build_parser().parse_args(argv)
    application = create_application(
        config_path=args.config,
        rules_path=args.rules,
        base_directory=args.base_directory,
    )

    if args.command == "initialize":
        application.initialize_monitors()
        print(f"Initialized {len(application.monitors)} monitor(s).")
        return 0

    if args.command == "scan":
        events, alerts = application.scan_once()
        report_scan(events, alerts)

        if not events and not alerts:
            print("Summary: 0 event(s), 0 alert(s).")

        return 0

    if args.command == "show-events":
        records = application.event_store.read_all()

        if args.source:
            records = [
                record
                for record in records
                if record.get("source") == args.source
            ]

        if args.event_type:
            records = [
                record
                for record in records
                if record.get("event_type") == args.event_type
            ]

        print_records(records[-args.limit:])
        return 0

    if args.command == "show-alerts":
        records = application.alert_store.read_all()

        if args.rule_id:
            records = [
                record
                for record in records
                if record.get("rule_id") == args.rule_id
            ]

        print_records(records[-args.limit:])
        return 0

    print(
        f"Monitoring every {application.poll_interval_seconds:g} "
        f"second(s). Press Ctrl+C to stop."
    )

    try:
        run_polling(application, report=report_scan)
    except KeyboardInterrupt:
        print("Monitoring stopped.")

    return 0
