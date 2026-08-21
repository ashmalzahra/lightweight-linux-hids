"""Continuous polling runtime for the HIDS application."""

import time
from collections.abc import Callable
from typing import Protocol

from lightweight_hids.models import Alert, Event


ScanReporter = Callable[[list[Event], list[Alert]], None]


class PollingApplication(Protocol):
    """Application behavior required by the polling runtime."""

    poll_interval_seconds: float

    def scan_once(self) -> tuple[list[Event], list[Alert]]:
        """Run one scan and return its events and alerts."""
        ...


def run_polling(
    application: PollingApplication,
    report: ScanReporter | None = None,
    *,
    max_scans: int | None = None,
    sleep: Callable[[float], None] = time.sleep,
    monotonic: Callable[[], float] = time.monotonic,
) -> None:
    """Scan repeatedly at the configured start-to-start interval."""
    scans_completed = 0

    while max_scans is None or scans_completed < max_scans:
        scan_started = monotonic()
        events, alerts = application.scan_once()
        scans_completed += 1

        if report is not None:
            report(events, alerts)

        if max_scans is not None and scans_completed >= max_scans:
            return

        scan_duration = monotonic() - scan_started
        remaining_delay = max(
            0.0,
            application.poll_interval_seconds - scan_duration,
        )
        sleep(remaining_delay)
