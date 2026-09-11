use std::fs;
use std::io;
use std::process::{Child, Command};
use std::time::{Duration, Instant};

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

pub fn run_strace(sample_path: &str) -> io::Result<String> {
    run_strace_with_timeout(sample_path, Duration::from_secs(15))
}

fn run_strace_with_timeout(sample_path: &str, timeout: Duration) -> io::Result<String> {
    let trace_path =
        std::env::temp_dir().join(format!("mirraura-sensor-{}.trace", std::process::id()));

    // ponytail: `open` is traced alongside `openat` because statically-linked
    // busybox binaries (the shadow image's touch, etc.) issue the legacy
    // `open` syscall directly instead of glibc/musl's usual `openat` wrapper.
    let spawn_result = (|| -> io::Result<()> {
        let mut child = Command::new("strace")
            .args(["-f", "-e", "trace=execve,open,openat,connect", "-o"])
            .arg(&trace_path)
            .args(["bash", sample_path])
            .spawn()?;
        wait_with_deadline(&mut child, timeout)
    })();

    let trace_text = match fs::read_to_string(&trace_path) {
        Ok(text) => text,
        Err(e) => {
            eprintln!("warning: failed to read strace trace file: {e}");
            String::new()
        }
    };
    let _ = fs::remove_file(&trace_path);

    spawn_result?;
    Ok(strip_root_execve(&trace_text))
}

/// Waits for `child` to exit on its own, polling every 100ms; if it's still
/// running once `timeout` has elapsed, kills it and reaps it instead of
/// blocking forever. Matches the old Python sensor's de facto behavior:
/// `subprocess.run(..., timeout=15)` kills the child at the OS level once
/// the timeout elapses, regardless of whether the caller catches the
/// resulting `TimeoutExpired`.
fn wait_with_deadline(child: &mut Child, timeout: Duration) -> io::Result<()> {
    let deadline = Instant::now() + timeout;
    loop {
        if child.try_wait()?.is_some() {
            return Ok(());
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(100));
    }
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

    #[test]
    fn test_wait_with_deadline_kills_a_hung_child_and_returns() {
        // "sleep 5" would outlive a naive `.output()`/`.wait()` call; a 500ms
        // deadline proves the kill path fires instead of blocking for 5s.
        let mut child = Command::new("sh")
            .args(["-c", "sleep 5"])
            .spawn()
            .expect("failed to spawn sh -c 'sleep 5'");

        let start = Instant::now();
        wait_with_deadline(&mut child, Duration::from_millis(500)).unwrap();
        let elapsed = start.elapsed();

        assert!(
            elapsed < Duration::from_secs(3),
            "wait_with_deadline should return shortly after its deadline, took {elapsed:?}"
        );
        // The child must actually be gone (killed + reaped), not just abandoned.
        assert!(
            child.try_wait().unwrap().is_some(),
            "child should have been killed and reaped by the deadline"
        );
    }
}
