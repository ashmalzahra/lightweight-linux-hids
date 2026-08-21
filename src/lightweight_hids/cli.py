"""Command-line interface for the lightweight HIDS."""

import argparse
from pathlib import Path
from typing import Sequence

from lightweight_hids.application import create_application


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

    events, alerts = application.scan_once()
    print(
        f"Detected {len(events)} event(s); "
        f"generated {len(alerts)} alert(s)."
    )
    return 0
