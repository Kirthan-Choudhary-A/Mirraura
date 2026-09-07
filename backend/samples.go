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
	"net/http"
	"os"
	"path/filepath"
	"time"
)

const shadowImage = "mirraura-shadow:latest"

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
		file, header, err := r.FormFile("sample")
		if err != nil {
			http.Error(w, "missing 'sample' file field", http.StatusBadRequest)
			return
		}
		defer file.Close()

		data, err := io.ReadAll(file)
		if err != nil {
			http.Error(w, "failed to read upload", http.StatusInternalServerError)
			return
		}
		sum := sha256.Sum256(data)
		sampleHash := hex.EncodeToString(sum[:])

		tmpPath := filepath.Join(os.TempDir(), header.Filename)
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
		containerID, err := dm.StartShadowContainer(ctx, shadowImage, networkID, "mirraura-shadow-"+runID)
		if err != nil {
			http.Error(w, fmt.Sprintf("container start failed: %v", err), http.StatusInternalServerError)
			return
		}
		defer dm.Teardown(context.Background(), containerID, networkID)

		if err := dm.CopyFileIntoContainer(ctx, containerID, tmpPath, "/samples/"); err != nil {
			http.Error(w, fmt.Sprintf("copy into container failed: %v", err), http.StatusInternalServerError)
			return
		}

		lines, err := dm.RunSensor(ctx, containerID, "/samples/"+header.Filename)
		if err != nil {
			http.Error(w, fmt.Sprintf("sensor run failed: %v", err), http.StatusInternalServerError)
			return
		}

		var events []json.RawMessage
		for line := range lines {
			raw := json.RawMessage(line)
			hub.Broadcast(map[string]any{"type": "event", "data": raw})
			events = append(events, raw)
		}

		verdict, err := scoreWithVerdictEngine(verdictEngineURL, sampleHash, events)
		if err != nil {
			http.Error(w, fmt.Sprintf("scoring failed: %v", err), http.StatusInternalServerError)
			return
		}
		hub.Broadcast(map[string]any{"type": "verdict", "data": verdict})

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(verdict)
	}
}

func scoreWithVerdictEngine(baseURL, sampleHash string, events []json.RawMessage) (*Verdict, error) {
	body, err := json.Marshal(map[string]any{"sample_hash": sampleHash, "events": events})
	if err != nil {
		return nil, err
	}
	resp, err := http.Post(baseURL+"/score", "application/json", bytes.NewReader(body))
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
