from train import extract_features
from schemas import Event, FileRef, NetworkRef, ProcessRef


def _event(event_type, **refs):
    return Event(
        event_id="e1",
        device_id="test",
        event_type=event_type,
        timestamp="2026-09-11T00:00:00Z",
        **refs,
    )


def test_extract_features_all_zero_for_no_events():
    assert extract_features([]) == [0, 0, 0, 0]


def test_extract_features_child_process():
    events = [_event("process_spawn", process_ref=ProcessRef(pid=1, name="sh", parent_pid=0))]
    assert extract_features(events) == [1, 0, 0, 0]


def test_extract_features_sensitive_write():
    events = [_event("file_write", file_ref=FileRef(path="/etc/passwd", action="write"))]
    assert extract_features(events) == [0, 1, 0, 0]


def test_extract_features_non_sensitive_write_is_not_flagged():
    events = [_event("file_write", file_ref=FileRef(path="/tmp/readme.txt", action="write"))]
    assert extract_features(events) == [0, 0, 0, 0]


def test_extract_features_odd_port():
    events = [_event("network_connect", network_ref=NetworkRef(dst_ip="127.0.0.1", dst_port=31337))]
    assert extract_features(events) == [0, 0, 1, 0]


def test_extract_features_standard_port_is_not_flagged():
    events = [_event("network_connect", network_ref=NetworkRef(dst_ip="127.0.0.1", dst_port=443))]
    assert extract_features(events) == [0, 0, 0, 0]


def test_extract_features_rapid_file_changes():
    events = [
        _event("file_write", file_ref=FileRef(path=f"/tmp/f{i}", action="write")) for i in range(6)
    ]
    assert extract_features(events) == [0, 0, 0, 1]


def test_extract_features_five_file_changes_is_not_rapid():
    events = [
        _event("file_write", file_ref=FileRef(path=f"/tmp/f{i}", action="write")) for i in range(5)
    ]
    assert extract_features(events) == [0, 0, 0, 0]
