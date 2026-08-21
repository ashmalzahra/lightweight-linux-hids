"""Unit tests for continuous HIDS polling."""

from lightweight_hids.runtime import run_polling


class FakeApplication:
    """Minimal application substitute with predictable scan results."""

    poll_interval_seconds = 5.0

    def __init__(self) -> None:
        self.scan_count = 0

    def scan_once(self):
        self.scan_count += 1
        return [], []


def test_polling_compensates_for_scan_duration() -> None:
    application = FakeApplication()
    clock_values = iter((10.0, 11.5, 15.0))
    sleep_calls = []
    reported_results = []

    run_polling(
        application,
        report=lambda events, alerts: reported_results.append(
            (events, alerts)
        ),
        max_scans=2,
        sleep=sleep_calls.append,
        monotonic=lambda: next(clock_values),
    )

    assert application.scan_count == 2
    assert reported_results == [([], []), ([], [])]
    assert sleep_calls == [3.5]


def test_polling_does_not_sleep_negative_duration() -> None:
    application = FakeApplication()
    clock_values = iter((10.0, 16.0, 16.0))
    sleep_calls = []

    run_polling(
        application,
        max_scans=2,
        sleep=sleep_calls.append,
        monotonic=lambda: next(clock_values),
    )

    assert sleep_calls == [0.0]
