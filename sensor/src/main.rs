mod parser;
mod tracer;

use std::env;
use std::io::{self, Write};
use std::process;
use std::thread;
use std::time::Duration;

use chrono::{SecondsFormat, Utc};
use serde_json::{json, Value};
use uuid::Uuid;

const DEVICE_ID: &str = "shadow-node";

fn wrap_event(raw: Value) -> Value {
    let mut event = json!({
        "event_id": Uuid::new_v4().to_string(),
        "device_id": DEVICE_ID,
        "timestamp": Utc::now().to_rfc3339_opts(SecondsFormat::Micros, false),
        "baseline_deviation_score": 0.0,
    });
    if let (Value::Object(event_map), Value::Object(raw_map)) = (&mut event, raw) {
        event_map.extend(raw_map);
    }
    event
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("usage: sensor <path-to-sample>");
        process::exit(1);
    }
    let sample_path = &args[1];

    let log_text = match tracer::run_strace(sample_path) {
        Ok(text) => text,
        Err(e) => {
            eprintln!("strace failed: {e}");
            process::exit(1);
        }
    };

    let raw_events = parser::parse_trace_log(&log_text);
    let stdout = io::stdout();

    for raw in raw_events {
        let event = wrap_event(raw);
        println!("{event}");
        stdout.lock().flush().ok();
        thread::sleep(Duration::from_millis(300));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wrap_event_merges_envelope_and_raw_fields() {
        let raw = json!({
            "event_type": "process_spawn",
            "process_ref": {"pid": 1, "name": "sh", "parent_pid": 0}
        });
        let event = wrap_event(raw);
        assert_eq!(event["device_id"], DEVICE_ID);
        assert_eq!(event["baseline_deviation_score"], 0.0);
        assert_eq!(event["event_type"], "process_spawn");
        assert_eq!(event["process_ref"]["name"], "sh");
        assert!(event["event_id"].is_string());
        assert!(event["timestamp"].is_string());
    }

    #[test]
    fn test_wrap_event_generates_unique_ids() {
        let raw1 = json!({
            "event_type": "process_spawn",
            "process_ref": {"pid": 1, "name": "sh", "parent_pid": 0}
        });
        let raw2 = raw1.clone();
        let e1 = wrap_event(raw1);
        let e2 = wrap_event(raw2);
        assert_ne!(e1["event_id"], e2["event_id"]);
    }
}
