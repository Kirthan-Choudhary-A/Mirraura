package main

type ProcessRef struct {
	PID       int    `json:"pid"`
	Name      string `json:"name"`
	ParentPID int    `json:"parent_pid"`
}

type NetworkRef struct {
	DstIP    string `json:"dst_ip"`
	DstPort  int    `json:"dst_port"`
	Protocol string `json:"protocol"`
}

type FileRef struct {
	Path   string `json:"path"`
	Action string `json:"action"`
}

type Verdict struct {
	VerdictID      string   `json:"verdict_id"`
	SampleHash     string   `json:"sample_hash"`
	SampleFilename string   `json:"sample_filename"`
	Verdict        string   `json:"verdict"`
	Confidence     float64  `json:"confidence"`
	CausalChain    []string `json:"causal_chain"`
	Timestamp      string   `json:"timestamp"`
	PrevLogHash    string   `json:"prev_log_hash"`
	// Passed through from the verdict engine so the dashboard can show how
	// the verdict was reached (known_bad_hash, static_triage, dynamic).
	DetectionMethod string `json:"detection_method"`
	// "sample" (upload/intercept) or "monitor" (continuous-monitoring batch).
	Source string `json:"source"`
}

type Broadcaster interface {
	Broadcast(msg any)
}
