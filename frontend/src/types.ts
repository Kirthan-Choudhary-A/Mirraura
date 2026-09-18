export interface ProcessRef {
  pid: number;
  name: string;
  parent_pid: number;
}

export interface NetworkRef {
  dst_ip: string;
  dst_port: number;
  protocol: string;
}

export interface FileRef {
  path: string;
  action: string;
}

export interface MirraEvent {
  event_id: string;
  device_id: string;
  event_type: "process_spawn" | "file_write" | "file_delete" | "network_connect";
  process_ref?: ProcessRef;
  network_ref?: NetworkRef;
  file_ref?: FileRef;
  timestamp: string;
  baseline_deviation_score: number;
}

export interface Verdict {
  verdict_id: string;
  sample_hash: string;
  sample_filename: string;
  verdict: "Normal" | "Suspicious" | "Compromised" | "Inconclusive";
  confidence: number;
  causal_chain: string[];
  timestamp: string;
  prev_log_hash: string;
}
