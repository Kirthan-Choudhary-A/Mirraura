from differ import diff_snapshots, parse_ps_output, parse_ss_output


def test_parse_ps_output_skips_header():
    text = "  PID COMMAND\n    1 init\n   42 touch\n"
    assert parse_ps_output(text) == {"1": "init", "42": "touch"}


def test_parse_ss_output_only_established():
    text = (
        "State  Recv-Q Send-Q Local Address:Port  Peer Address:Port\n"
        "ESTAB  0      0      10.0.0.5:41234       93.184.216.34:80\n"
        "LISTEN 0      128    0.0.0.0:22            0.0.0.0:*\n"
    )
    assert parse_ss_output(text) == {
        "93.184.216.34:80": {"dst_ip": "93.184.216.34", "dst_port": 80, "protocol": "tcp"}
    }


def test_no_new_processes_or_connections():
    snap = {"processes": {"1": "init"}, "connections": {}, "files": []}
    assert diff_snapshots(snap, snap) == []


def test_empty_snapshots_produce_no_events():
    empty = {"processes": {}, "connections": {}, "files": []}
    assert diff_snapshots(empty, empty) == []


def test_new_process_detected():
    prev = {"processes": {"1": "init"}, "connections": {}}
    curr = {"processes": {"1": "init", "42": "touch"}, "connections": {}}
    events = diff_snapshots(prev, curr)
    assert events == [
        {
            "event_type": "process_spawn",
            "process_ref": {"pid": 42, "name": "touch", "parent_pid": 0},
        }
    ]


def test_new_connection_detected():
    prev = {"processes": {}, "connections": {}}
    curr = {
        "processes": {},
        "connections": {
            "93.184.216.34:80": {"dst_ip": "93.184.216.34", "dst_port": 80, "protocol": "tcp"}
        },
    }
    events = diff_snapshots(prev, curr)
    assert events == [
        {
            "event_type": "network_connect",
            "network_ref": {"dst_ip": "93.184.216.34", "dst_port": 80, "protocol": "tcp"},
        }
    ]


def test_new_file_in_etc_detected():
    prev = {"processes": {}, "connections": {}, "files": ["hostname"]}
    curr = {"processes": {}, "connections": {}, "files": ["hostname", "mirraura-test-marker"]}
    events = diff_snapshots(prev, curr)
    assert events == [
        {
            "event_type": "file_write",
            "file_ref": {"path": "/etc/mirraura-test-marker", "action": "write"},
        }
    ]


def test_no_new_files_produces_no_file_events():
    snap = {"processes": {}, "connections": {}, "files": ["hostname"]}
    assert diff_snapshots(snap, snap) == []


def test_pollers_own_processes_excluded_from_diff():
    prev = {"processes": {}, "connections": {}, "files": []}
    curr = {
        "processes": {"10": "python3", "11": "ps", "12": "ss", "13": "touch"},
        "connections": {},
        "files": [],
    }
    events = diff_snapshots(prev, curr)
    assert events == [
        {
            "event_type": "process_spawn",
            "process_ref": {"pid": 13, "name": "touch", "parent_pid": 0},
        }
    ]
