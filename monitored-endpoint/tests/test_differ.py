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
    snap = {"processes": {"1": "init"}, "connections": {}}
    assert diff_snapshots(snap, snap) == []


def test_empty_snapshots_produce_no_events():
    empty = {"processes": {}, "connections": {}}
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
