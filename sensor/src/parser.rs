use regex::Regex;
use serde_json::{json, Value};

const WRITE_FLAGS: [&str; 3] = ["O_WRONLY", "O_RDWR", "O_CREAT"];

pub fn parse_trace_log(log_text: &str) -> Vec<Value> {
    let execve_re = Regex::new(r#"^(\d+)\s+execve\("([^"]+)""#).unwrap();
    let openat_re = Regex::new(r#"^(\d+)\s+openat\([^,]+,\s*"([^"]+)",\s*([A-Z_|]+)"#).unwrap();
    // Statically-linked busybox binaries (e.g. the shadow image's `touch`)
    // call the legacy `open` syscall directly instead of `openat`.
    let open_re = Regex::new(r#"^(\d+)\s+open\("([^"]+)",\s*([A-Z_|]+)"#).unwrap();
    let connect_re = Regex::new(
        r#"^(\d+)\s+connect\(\d+,\s*\{sa_family=AF_INET,\s*sin_port=htons\((\d+)\),\s*sin_addr=inet_addr\("([^"]+)"\)"#,
    )
    .unwrap();

    let mut events = Vec::new();

    for raw_line in log_text.lines() {
        let line = raw_line.trim();
        if line.is_empty() {
            continue;
        }

        if let Some(caps) = execve_re.captures(line) {
            let pid: u32 = caps[1].parse().unwrap_or(0);
            let path = &caps[2];
            let name = path.rsplit('/').next().unwrap_or(path);
            events.push(json!({
                "event_type": "process_spawn",
                "process_ref": {"pid": pid, "name": name, "parent_pid": 0}
            }));
            continue;
        }

        if let Some(caps) = openat_re.captures(line) {
            let path = &caps[2];
            let flags = &caps[3];
            if WRITE_FLAGS.iter().any(|f| flags.contains(f)) {
                events.push(json!({
                    "event_type": "file_write",
                    "file_ref": {"path": path, "action": "write"}
                }));
            }
            continue;
        }

        if let Some(caps) = open_re.captures(line) {
            let path = &caps[2];
            let flags = &caps[3];
            if WRITE_FLAGS.iter().any(|f| flags.contains(f)) {
                events.push(json!({
                    "event_type": "file_write",
                    "file_ref": {"path": path, "action": "write"}
                }));
            }
            continue;
        }

        if let Some(caps) = connect_re.captures(line) {
            let port: u16 = caps[2].parse().unwrap_or(0);
            let ip = &caps[3];
            events.push(json!({
                "event_type": "network_connect",
                "network_ref": {"dst_ip": ip, "dst_port": port, "protocol": "tcp"}
            }));
            continue;
        }
    }

    events
}

#[cfg(test)]
mod tests {
    use super::*;

    const TRACE_SAMPLE: &str = r#"
12345 execve("/usr/bin/touch", ["touch", "/etc/mirraura-test-marker"], 0x7fff /* 20 vars */) = 0
12345 openat(AT_FDCWD, "/etc/mirraura-test-marker", O_WRONLY|O_CREAT|O_TRUNC, 0666) = 3
12346 connect(3, {sa_family=AF_INET, sin_port=htons(31337), sin_addr=inet_addr("127.0.0.1")}, 16) = -1 ECONNREFUSED
12346 openat(AT_FDCWD, "/tmp/readme.txt", O_RDONLY) = 4
"#;

    #[test]
    fn test_parses_process_spawn() {
        let events = parse_trace_log(TRACE_SAMPLE);
        let spawns: Vec<&Value> = events
            .iter()
            .filter(|e| e["event_type"] == "process_spawn")
            .collect();
        assert_eq!(spawns.len(), 1);
        assert_eq!(spawns[0]["process_ref"]["name"], "touch");
        assert_eq!(spawns[0]["process_ref"]["pid"], 12345);
    }

    #[test]
    fn test_parses_file_write_but_not_read_only() {
        let events = parse_trace_log(TRACE_SAMPLE);
        let writes: Vec<&Value> = events
            .iter()
            .filter(|e| e["event_type"] == "file_write")
            .collect();
        assert_eq!(writes.len(), 1);
        assert_eq!(writes[0]["file_ref"]["path"], "/etc/mirraura-test-marker");
    }

    #[test]
    fn test_parses_network_connect() {
        let events = parse_trace_log(TRACE_SAMPLE);
        let conns: Vec<&Value> = events
            .iter()
            .filter(|e| e["event_type"] == "network_connect")
            .collect();
        assert_eq!(conns.len(), 1);
        assert_eq!(conns[0]["network_ref"]["dst_port"], 31337);
        assert_eq!(conns[0]["network_ref"]["dst_ip"], "127.0.0.1");
    }

    #[test]
    fn test_empty_log_gives_no_events() {
        let events: Vec<Value> = parse_trace_log("");
        assert!(events.is_empty());
    }

    #[test]
    fn test_parses_legacy_open_but_not_read_only() {
        // busybox touch (statically linked) calls the raw `open` syscall
        // instead of `openat` — regression check for that case.
        let log = r#"
9 open("/etc/mirraura-test-marker", O_RDWR|O_CREAT|O_LARGEFILE, 0666) = 3
9 open("/etc/hostname", O_RDONLY) = 4
"#;
        let events = parse_trace_log(log);
        let writes: Vec<&Value> = events
            .iter()
            .filter(|e| e["event_type"] == "file_write")
            .collect();
        assert_eq!(writes.len(), 1);
        assert_eq!(writes[0]["file_ref"]["path"], "/etc/mirraura-test-marker");
    }
}
