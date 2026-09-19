package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
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
		sum := sha256.Sum256(data)
		sampleHash := hex.EncodeToString(sum[:])

		tmpPath := filepath.Join(os.TempDir(), safeFilename)
		if err := os.WriteFile(tmpPath, data, 0644); err != nil {
			http.Error(w, "failed to stage upload", http.StatusInternalServerError)
			return
		}
		defer os.Remove(tmpPath)

		ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
		defer cancel()

		runID := randomID()
		networkID, err := dm.CreateShadowNetwork(ctx, "mirraura-net-"+runID)
		if err != nil {
			http.Error(w, fmt.Sprintf("network create failed: %v", err), http.StatusInternalServerError)
			return
		}
		var containerID string
		defer func() { dm.Teardown(context.Background(), containerID, networkID) }()

		containerID, err = dm.StartShadowContainer(ctx, shadowImage, networkID, "mirraura-shadow-"+runID)
		if err != nil {
			http.Error(w, fmt.Sprintf("container start failed: %v", err), http.StatusInternalServerError)
			return
		}

		if err := dm.CopyFileIntoContainer(ctx, containerID, tmpPath, "/samples/"); err != nil {
			http.Error(w, fmt.Sprintf("copy into container failed: %v", err), http.StatusInternalServerError)
			return
		}

		sensorCtx, sensorCancel := context.WithTimeout(ctx, sensorTimeout)
		defer sensorCancel()

		lines, err := dm.RunSensor(sensorCtx, containerID, "/samples/"+safeFilename)
		if err != nil {
			http.Error(w, fmt.Sprintf("sensor run failed: %v", err), http.StatusInternalServerError)
			return
		}

		events := []json.RawMessage{}
		for line := range lines {
			if !json.Valid([]byte(line)) {
				log.Printf("sensor: non-JSON line ignored: %s", line)
				continue
			}
			raw := json.RawMessage(line)
			hub.Broadcast(map[string]any{"type": "event", "source": "sample", "data": raw})
			events = append(events, raw)
		}
		timedOut := sensorCtx.Err() != nil

		actor, _ := sessionFromContext(r.Context())
		verdict, err := scoreWithVerdictEngine(verdictEngineURL, sampleHash, safeFilename, "sample", actor.Username, timedOut, events)
		if err != nil {
			http.Error(w, fmt.Sprintf("scoring failed: %v", err), http.StatusInternalServerError)
			return
		}
		hub.Broadcast(map[string]any{"type": "verdict", "source": "sample", "data": verdict})

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(verdict)
	}
}

func scoreWithVerdictEngine(baseURL, sampleHash, sampleFilename, source, actor string, timedOut bool, events []json.RawMessage) (*Verdict, error) {
	body, err := json.Marshal(map[string]any{
		"sample_hash":     sampleHash,
		"sample_filename": sampleFilename,
		"timed_out":       timedOut,
		"events":          events,
		"source":          source,
		"actor":           actor,
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
