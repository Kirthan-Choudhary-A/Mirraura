from parser import parse_trace_log

TRACE_SAMPLE = """
12345 execve("/usr/bin/touch", ["touch", "/etc/mirraura-test-marker"], 0x7fff /* 20 vars */) = 0
12345 openat(AT_FDCWD, "/etc/mirraura-test-marker", O_WRONLY|O_CREAT|O_TRUNC, 0666) = 3
12346 connect(3, {sa_family=AF_INET, sin_port=htons(31337), sin_addr=inet_addr("127.0.0.1")}, 16) = -1 ECONNREFUSED
12346 openat(AT_FDCWD, "/tmp/readme.txt", O_RDONLY) = 4
"""


def test_parses_process_spawn():
    events = parse_trace_log(TRACE_SAMPLE)
    spawns = [e for e in events if e["event_type"] == "process_spawn"]
    assert len(spawns) == 1
    assert spawns[0]["process_ref"]["name"] == "touch"
    assert spawns[0]["process_ref"]["pid"] == 12345


def test_parses_file_write_but_not_read_only():
    events = parse_trace_log(TRACE_SAMPLE)
    writes = [e for e in events if e["event_type"] == "file_write"]
    assert len(writes) == 1
    assert writes[0]["file_ref"]["path"] == "/etc/mirraura-test-marker"


def test_parses_network_connect():
    events = parse_trace_log(TRACE_SAMPLE)
    conns = [e for e in events if e["event_type"] == "network_connect"]
    assert len(conns) == 1
    assert conns[0]["network_ref"]["dst_port"] == 31337
    assert conns[0]["network_ref"]["dst_ip"] == "127.0.0.1"


def test_empty_log_gives_no_events():
    assert parse_trace_log("") == []
