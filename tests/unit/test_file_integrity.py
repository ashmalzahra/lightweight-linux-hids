from lightweight_hids.monitors.file_integrity import (
    FileIntegrityMonitor,
    build_snapshot,
    calculate_sha256,
    compare_snapshots,
    inspect_file,
    load_baseline,
    save_baseline,
)



def test_calculate_sha256_changes_when_content_changes(tmp_path):
    file_path = tmp_path / "example.txt"
    file_path.write_text("version one", encoding="utf-8")
    first_hash = calculate_sha256(file_path)

    file_path.write_text("version two", encoding="utf-8")
    second_hash = calculate_sha256(file_path)

    assert first_hash != second_hash


def test_inspect_file_records_file_information(tmp_path):
    file_path = tmp_path / "example.txt"
    file_path.write_text("hello", encoding="utf-8")

    state = inspect_file(file_path)

    assert state.path == str(file_path)
    assert state.size == 5
    assert len(state.sha256) == 64
    assert state.modified_time_ns > 0

def test_build_snapshot_inspects_nested_files(tmp_path):
    monitored_directory = tmp_path / "monitored"
    nested_directory = monitored_directory / "nested"
    nested_directory.mkdir(parents=True)

    first_file = monitored_directory / "first.txt"
    second_file = nested_directory / "second.txt"

    first_file.write_text("first", encoding="utf-8")
    second_file.write_text("second", encoding="utf-8")

    snapshot = build_snapshot([monitored_directory])

    assert str(first_file.resolve()) in snapshot
    assert str(second_file.resolve()) in snapshot
    assert len(snapshot) == 2


def test_saved_baseline_can_be_loaded(tmp_path):
    monitored_file = tmp_path / "example.txt"
    baseline_path = tmp_path / "state" / "baseline.json"
    monitored_file.write_text("trusted content", encoding="utf-8")

    original_snapshot = build_snapshot([monitored_file])
    save_baseline(baseline_path, original_snapshot)
    loaded_snapshot = load_baseline(baseline_path)

    assert baseline_path.exists()
    assert loaded_snapshot == original_snapshot

def test_compare_snapshots_detects_added_file(tmp_path):
    monitored_directory = tmp_path / "monitored"
    monitored_directory.mkdir()

    baseline = build_snapshot([monitored_directory])

    added_file = monitored_directory / "added.txt"
    added_file.write_text("new file", encoding="utf-8")
    current = build_snapshot([monitored_directory])

    events = compare_snapshots(baseline, current, host="test-host")

    assert len(events) == 1
    assert events[0].event_type == "file_added"
    assert events[0].data["path"] == str(added_file.resolve())


def test_compare_snapshots_detects_deleted_file(tmp_path):
    monitored_file = tmp_path / "deleted.txt"
    monitored_file.write_text("original", encoding="utf-8")
    baseline = build_snapshot([monitored_file])

    monitored_file.unlink()
    current = build_snapshot([monitored_file])

    events = compare_snapshots(baseline, current, host="test-host")

    assert len(events) == 1
    assert events[0].event_type == "file_deleted"


def test_compare_snapshots_detects_modified_content(tmp_path):
    monitored_file = tmp_path / "example.txt"
    monitored_file.write_text("version one", encoding="utf-8")
    baseline = build_snapshot([monitored_file])

    monitored_file.write_text("version two", encoding="utf-8")
    current = build_snapshot([monitored_file])

    events = compare_snapshots(baseline, current, host="test-host")

    assert [event.event_type for event in events] == ["file_modified"]


def test_compare_snapshots_detects_permission_change(tmp_path):
    monitored_file = tmp_path / "example.txt"
    monitored_file.write_text("unchanged content", encoding="utf-8")
    monitored_file.chmod(0o644)
    baseline = build_snapshot([monitored_file])

    monitored_file.chmod(0o600)
    current = build_snapshot([monitored_file])

    events = compare_snapshots(baseline, current, host="test-host")

    assert [event.event_type for event in events] == [
        "file_metadata_changed"
    ]
    assert events[0].data["changed_fields"] == ["mode"]

def test_monitor_requires_baseline_before_scan(tmp_path):
    monitor = FileIntegrityMonitor(
        paths=[tmp_path / "monitored"],
        baseline_path=tmp_path / "baseline.json",
        host="test-host",
    )

    try:
        monitor.scan()
        assert False, "Expected FileNotFoundError"
    except FileNotFoundError:
        pass


def test_monitor_detects_change_after_initialization(tmp_path):
    monitored_directory = tmp_path / "monitored"
    monitored_directory.mkdir()

    monitored_file = monitored_directory / "example.txt"
    monitored_file.write_text("trusted content", encoding="utf-8")

    baseline_path = tmp_path / "state" / "baseline.json"

    monitor = FileIntegrityMonitor(
        paths=[monitored_directory],
        baseline_path=baseline_path,
        host="test-host",
    )

    monitor.initialize()
    monitored_file.write_text("changed content", encoding="utf-8")

    events = monitor.scan()

    assert baseline_path.exists()
    assert len(events) == 1
    assert events[0].event_type == "file_modified"
    assert events[0].host == "test-host"


def test_scan_does_not_replace_trusted_baseline(tmp_path):
    monitored_file = tmp_path / "example.txt"
    monitored_file.write_text("trusted content", encoding="utf-8")

    monitor = FileIntegrityMonitor(
        paths=[monitored_file],
        baseline_path=tmp_path / "baseline.json",
        host="test-host",
    )

    monitor.initialize()
    monitored_file.write_text("changed content", encoding="utf-8")

    first_events = monitor.scan()
    second_events = monitor.scan()

    assert first_events[0].event_type == "file_modified"
    assert second_events[0].event_type == "file_modified"