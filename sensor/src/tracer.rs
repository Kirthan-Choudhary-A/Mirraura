use std::fs;
use std::io;
use std::process::Command;

use regex::Regex;

pub fn strip_root_execve(trace_text: &str) -> String {
    let root_execve_re = Regex::new(r"^\d+\s+execve\(").unwrap();
    let mut removed = false;
    let mut result = String::with_capacity(trace_text.len());
    for line in trace_text.split_inclusive('\n') {
        if !removed && root_execve_re.is_match(line.trim()) {
            removed = true;
            continue;
        }
        result.push_str(line);
    }
    result
}

// ponytail: no timeout on the strace subprocess, matching the existing
// Python sensor (its timeout=15 argument was never actually caught —
// an uncaught subprocess.TimeoutExpired crashes it too, so dropping the
// timeout keeps identical observable behavior for a hung sample).
// Upgrade path: a watcher thread + Command::kill if a hung sample ever
// becomes a real problem in practice.
pub fn run_strace(sample_path: &str) -> io::Result<String> {
    let trace_path =
        std::env::temp_dir().join(format!("mirraura-sensor-{}.trace", std::process::id()));

    let spawn_result = Command::new("strace")
        .args(["-f", "-e", "trace=execve,openat,connect", "-o"])
        .arg(&trace_path)
        .args(["bash", sample_path])
        .output();

    let trace_text = fs::read_to_string(&trace_path).unwrap_or_default();
    let _ = fs::remove_file(&trace_path);

    spawn_result?;
    Ok(strip_root_execve(&trace_text))
}

#[cfg(test)]
mod tests {
    use super::*;

    const MULTI_LINE_TRACE: &str = r#"12345 execve("/bin/bash", ["bash", "/tmp/sample.sh"], 0x7fff /* 20 vars */) = 0
12345 openat(AT_FDCWD, "/etc/mirraura-test-marker", O_WRONLY|O_CREAT|O_TRUNC, 0666) = 3
12346 execve("/usr/bin/touch", ["touch", "/etc/mirraura-test-marker"], 0x7fff /* 20 vars */) = 0
"#;

    const ONLY_ROOT_TRACE: &str = r#"12345 execve("/bin/bash", ["bash", "/tmp/sample.sh"], 0x7fff /* 20 vars */) = 0
"#;

    const NO_EXECVE_TRACE: &str = r#"12345 openat(AT_FDCWD, "/etc/mirraura-test-marker", O_WRONLY|O_CREAT|O_TRUNC, 0666) = 3
12346 connect(3, {sa_family=AF_INET, sin_port=htons(31337), sin_addr=inet_addr("127.0.0.1")}, 16) = -1 ECONNREFUSED
"#;

    #[test]
    fn test_strips_only_the_leading_root_execve_line() {
        let result = strip_root_execve(MULTI_LINE_TRACE);
        let original_lines: Vec<&str> = MULTI_LINE_TRACE.split_inclusive('\n').collect();
        let expected: String = original_lines[1..].concat();
        assert_eq!(result, expected);
    }

    #[test]
    fn test_only_root_execve_line_results_in_empty_string() {
        assert_eq!(strip_root_execve(ONLY_ROOT_TRACE), "");
    }

    #[test]
    fn test_empty_string_returns_empty_string() {
        assert_eq!(strip_root_execve(""), "");
    }

    #[test]
    fn test_no_execve_line_leaves_everything_untouched() {
        assert_eq!(strip_root_execve(NO_EXECVE_TRACE), NO_EXECVE_TRACE);
    }
}
