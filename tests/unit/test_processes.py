"""Unit tests for polling-based process monitoring."""

import psutil

from lightweight_hids.monitors.processes import (
    ProcessMonitor,
    ProcessState,
    collect_process_snapshot,
    load_process_snapshot,
)


def make_process(
    pid: int,
    create_time: float,
    name: str,
) -> ProcessState:
    return ProcessState(
        pid=pid,
        create_time=create_time,
        parent_pid=1,
        name=name,
        executable=f"/usr/bin/{name}",
        command_line=[name],
        username="test-user",
    )


class FakePsutilProcess:
    def __init__(self, information):
        self.info = information


class InaccessiblePsutilProcess:
    @property
    def info(self):
        raise psutil.AccessDenied(pid=99)


def test_collect_process_snapshot_normalizes_process_information() -> None:
    information = {
        "pid": 42,
        "create_time": 1000.5,
        "ppid": 1,
        "name": "python3",
        "exe": "/usr/bin/python3",
        "cmdline": ["python3", "example.py"],
        "username": "ashmal",
    }

    def provider(**_kwargs):
        return [FakePsutilProcess(information)]

    snapshot = collect_process_snapshot(provider)
    state = snapshot["42:1000.5"]

    assert state.pid == 42
    assert state.name == "python3"
    assert state.command_line == ["python3", "example.py"]
    assert state.username == "ashmal"


def test_collect_process_snapshot_skips_inaccessible_process() -> None:
    accessible = FakePsutilProcess(
        {
            "pid": 42,
            "create_time": 1000.5,
            "ppid": 1,
            "name": "python3",
            "exe": "/usr/bin/python3",
            "cmdline": ["python3"],
            "username": "ashmal",
        }
    )

    def provider(**_kwargs):
        return [InaccessiblePsutilProcess(), accessible]

    snapshot = collect_process_snapshot(provider)

    assert list(snapshot) == ["42:1000.5"]


def test_monitor_detects_started_and_stopped_processes(tmp_path) -> None:
    first = make_process(10, 1000.0, "first")
    second = make_process(20, 1010.0, "second")
    snapshots = iter(
        (
            {first.identity: first},
            {first.identity: first, second.identity: second},
            {second.identity: second},
        )
    )
    monitor = ProcessMonitor(
        state_path=tmp_path / "state" / "processes.json",
        host="test-host",
        collector=lambda: next(snapshots),
    )

    monitor.initialize()
    started_events = monitor.scan()
    stopped_events = monitor.scan()

    assert len(started_events) == 1
    assert started_events[0].event_type == "process_started"
    assert started_events[0].data["pid"] == 20
    assert len(stopped_events) == 1
    assert stopped_events[0].event_type == "process_stopped"
    assert stopped_events[0].data["pid"] == 10


def test_process_identity_distinguishes_reused_pid(tmp_path) -> None:
    old_process = make_process(42, 1000.0, "old-program")
    new_process = make_process(42, 2000.0, "new-program")
    snapshots = iter(
        (
            {old_process.identity: old_process},
            {new_process.identity: new_process},
        )
    )
    monitor = ProcessMonitor(
        state_path=tmp_path / "processes.json",
        host="test-host",
        collector=lambda: next(snapshots),
    )

    monitor.initialize()
    events = monitor.scan()

    assert [event.event_type for event in events] == [
        "process_started",
        "process_stopped",
    ]
    assert events[0].data["name"] == "new-program"
    assert events[1].data["name"] == "old-program"
    saved = load_process_snapshot(monitor.state_path)
    assert list(saved) == [new_process.identity]
