import re
from typing import Dict, List

EXECVE_RE = re.compile(r'^(\d+)\s+execve\("([^"]+)"')
OPENAT_RE = re.compile(r'^(\d+)\s+openat\([^,]+,\s*"([^"]+)",\s*([A-Z_|]+)')
CONNECT_RE = re.compile(
    r'^(\d+)\s+connect\(\d+,\s*\{sa_family=AF_INET,\s*'
    r'sin_port=htons\((\d+)\),\s*sin_addr=inet_addr\("([^"]+)"\)'
)
WRITE_FLAGS = ("O_WRONLY", "O_RDWR", "O_CREAT")


def parse_trace_log(log_text: str) -> List[Dict]:
    events: List[Dict] = []
    for line in log_text.splitlines():
        line = line.strip()
        if not line:
            continue

        m = EXECVE_RE.match(line)
        if m:
            pid, path = m.groups()
            events.append(
                {
                    "event_type": "process_spawn",
                    "process_ref": {
                        "pid": int(pid),
                        "name": path.rsplit("/", 1)[-1],
                        "parent_pid": 0,
                    },
                }
            )
            continue

        m = OPENAT_RE.match(line)
        if m:
            _, path, flags = m.groups()
            if any(flag in flags for flag in WRITE_FLAGS):
                events.append(
                    {
                        "event_type": "file_write",
                        "file_ref": {"path": path, "action": "write"},
                    }
                )
            continue

        m = CONNECT_RE.match(line)
        if m:
            _, port, ip = m.groups()
            events.append(
                {
                    "event_type": "network_connect",
                    "network_ref": {
                        "dst_ip": ip,
                        "dst_port": int(port),
                        "protocol": "tcp",
                    },
                }
            )
            continue

    return events
