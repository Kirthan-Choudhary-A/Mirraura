package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

const shadowImage = "mirraura-shadow:latest"

// sensorTimeout bounds a single detonation run; if the sensor hasn't
// finished by then, execAndStream force-closes its exec stream (see
// dockermanager.go) and the run is scored as Inconclusive instead of
// hanging the HTTP request.
const sensorTimeout = 30 * time.Second

// httpClient is shared by scoreWithVerdictEngine and logAction so a hung
// verdict-engine call can't block Tick (and therefore the ticker) forever.
var httpClient = &http.Client{Timeout: 15 * time.Second}

func randomID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func samplesHandler(dm *DockerManager, verdictEngineURL string, hub Broadcaster) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 64<<20) // 64MB, matches nginx's client_max_body_size
		file, header, err := r.FormFile("sample")
		if err != nil {
			http.Error(w, "missing 'sample' file field", http.StatusBadRequest)
			return
		}
		defer file.Close()
		safeFilename := filepath.Base(header.Filename)

		data, err := io.ReadAll(file)
		if err != nil {
			http.Error(w, "failed to read upload", http.StatusInternalServerError)
			return
		}

		actor, _ := sessionFromContext(r.Context())
		verdict, err := detonateAndScore(r.Context(), dm, verdictEngineURL, hub, data, safeFilename, "sample", actor.Username)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(verdict)
	}
}

// detonateAndScore runs data (a sample's raw bytes) through a fresh shadow
// container and scores the resulting events. Shared by the human-triggered
// upload path (samplesHandler) and the automatic interceptor path
// (interceptHandler) -- both produce a verdict the exact same way, the only
// difference is where the bytes and the actor name come from.
func detonateAndScore(reqCtx context.Context, dm *DockerManager, verdictEngineURL string, hub Broadcaster, data []byte, filename, source, actor string) (*Verdict, error) {
	sum := sha256.Sum256(data)
	sampleHash := hex.EncodeToString(sum[:])

	staticMatches, err := staticTriage(verdictEngineURL, data)
	if err != nil {
		// Fails open to detonation, not open to a verdict: a triage-call
		// failure (network blip, verdict-engine briefly down) must never
		// skip scoring entirely, only skip the "detonation" optimization.
		log.Printf("static triage failed, falling back to detonation: %v", err)
	} else if len(staticMatches) > 0 {
		verdict, err := scoreWithVerdictEngine(verdictEngineURL, sampleHash, filename, source, actor, false, []json.RawMessage{}, staticMatches)
		if err != nil {
			return nil, fmt.Errorf("scoring failed: %w", err)
		}
		hub.Broadcast(map[string]any{"type": "verdict", "source": source, "data": verdict})
		return verdict, nil
	}

	tmpPath := filepath.Join(os.TempDir(), filename)
	if err := os.WriteFile(tmpPath, data, 0644); err != nil {
		return nil, fmt.Errorf("failed to stage upload: %w", err)
	}
	defer os.Remove(tmpPath)

	ctx, cancel := context.WithTimeout(reqCtx, 60*time.Second)
	defer cancel()

	runID := randomID()
	networkID, err := dm.CreateShadowNetwork(ctx, "mirraura-net-"+runID)
	if err != nil {
		return nil, fmt.Errorf("network create failed: %w", err)
	}
	var containerID string
	defer func() { dm.Teardown(context.Background(), containerID, networkID) }()

	containerID, err = dm.StartShadowContainer(ctx, shadowImage, networkID, "mirraura-shadow-"+runID)
	if err != nil {
		return nil, fmt.Errorf("container start failed: %w", err)
	}

	if err := dm.CopyFileIntoContainer(ctx, containerID, tmpPath, "/samples/"); err != nil {
		return nil, fmt.Errorf("copy into container failed: %w", err)
	}

	sensorCtx, sensorCancel := context.WithTimeout(ctx, sensorTimeout)
	defer sensorCancel()

	lines, err := dm.RunSensor(sensorCtx, containerID, "/samples/"+filename)
	if err != nil {
		return nil, fmt.Errorf("sensor run failed: %w", err)
	}

	events := []json.RawMessage{}
	for line := range lines {
		if !json.Valid([]byte(line)) {
			log.Printf("sensor: non-JSON line ignored: %s", line)
			continue
		}
		raw := json.RawMessage(line)
		hub.Broadcast(map[string]any{"type": "event", "source": source, "data": raw})
		events = append(events, raw)
	}
	timedOut := sensorCtx.Err() != nil

	verdict, err := scoreWithVerdictEngine(verdictEngineURL, sampleHash, filename, source, actor, timedOut, events, nil)
	if err != nil {
		return nil, fmt.Errorf("scoring failed: %w", err)
	}
	hub.Broadcast(map[string]any{"type": "verdict", "source": source, "data": verdict})
	return verdict, nil
}

// staticTriage posts data to the verdict engine's /triage endpoint and
// returns the (possibly empty) list of static match reasons, without
// touching Docker. Called before detonation so a decisive match can skip
// it entirely.
func staticTriage(baseURL string, data []byte) ([]string, error) {
	body, err := json.Marshal(map[string]any{
		"sample_content_b64": base64.StdEncoding.EncodeToString(data),
	})
	if err != nil {
		return nil, err
	}
	resp, err := httpClient.Post(baseURL+"/triage", "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("verdict-engine returned %d: %s", resp.StatusCode, string(b))
	}
	var out struct {
		Matches []string `json:"matches"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	return out.Matches, nil
}

func scoreWithVerdictEngine(baseURL, sampleHash, sampleFilename, source, actor string, timedOut bool, events []json.RawMessage, staticMatches []string) (*Verdict, error) {
	// A nil Go slice marshals to JSON null, which Pydantic's
	// static_matches: List[str] rejects outright (422) -- every caller
	// that has nothing to report passes nil here, so normalize it rather
	// than pushing a []string{} literal onto every call site.
	if staticMatches == nil {
		staticMatches = []string{}
	}
	body, err := json.Marshal(map[string]any{
		"sample_hash":     sampleHash,
		"sample_filename": sampleFilename,
		"timed_out":       timedOut,
		"events":          events,
		"source":          source,
		"actor":           actor,
		"static_matches":  staticMatches,
	})
	if err != nil {
		return nil, err
	}
	resp, err := httpClient.Post(baseURL+"/score", "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("verdict-engine returned %d: %s", resp.StatusCode, string(b))
	}
	var v Verdict
	if err := json.NewDecoder(resp.Body).Decode(&v); err != nil {
		return nil, err
	}
	return &v, nil
}
