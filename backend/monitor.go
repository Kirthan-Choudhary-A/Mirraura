package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"sync"
)

const (
	monitorContainerName = "mirraura-monitored-endpoint"
	monitorNetworkName   = "mirraura-monitor-net"
	monitorDeviceID      = "monitored-endpoint"
)

var errNotIsolated = errors.New("monitor is not currently isolated")

type monitorDocker interface {
	RunPoller(ctx context.Context, containerID string) (<-chan string, error)
	IsolateContainer(ctx context.Context, networkName, containerName string) error
	ReconnectContainer(ctx context.Context, networkName, containerName string) error
	IsContainerIsolated(ctx context.Context, networkName, containerName string) (bool, error)
}

type Monitor struct {
	dm               monitorDocker
	verdictEngineURL string
	hub              Broadcaster

	mu       sync.Mutex
	isolated bool
}

func NewMonitor(dm monitorDocker, verdictEngineURL string, hub Broadcaster) *Monitor {
	return &Monitor{dm: dm, verdictEngineURL: verdictEngineURL, hub: hub}
}

func (mon *Monitor) IsIsolated() bool {
	mon.mu.Lock()
	defer mon.mu.Unlock()
	return mon.isolated
}

// InitIsolatedState recovers the isolated flag from Docker's actual network
// attachment state, so a backend restart doesn't forget that the monitored
// container is genuinely disconnected. Falls back to isolated=false (logging
// the error) if the inspect call fails, e.g. the container doesn't exist yet.
func (mon *Monitor) InitIsolatedState(ctx context.Context) {
	isolated, err := mon.dm.IsContainerIsolated(ctx, monitorNetworkName, monitorContainerName)
	if err != nil {
		log.Printf("monitor: failed to inspect container isolation state at startup, defaulting to not isolated: %v", err)
		return
	}
	mon.mu.Lock()
	mon.isolated = isolated
	mon.mu.Unlock()
}

func (mon *Monitor) Tick(ctx context.Context) error {
	lines, err := mon.dm.RunPoller(ctx, monitorContainerName)
	if err != nil {
		return fmt.Errorf("poll failed: %w", err)
	}

	events := []json.RawMessage{}
	for line := range lines {
		if !json.Valid([]byte(line)) {
			log.Printf("monitor: non-JSON line ignored: %s", line)
			continue
		}
		events = append(events, json.RawMessage(line))
	}

	if len(events) == 0 {
		return nil
	}

	for _, e := range events {
		mon.hub.Broadcast(map[string]any{"type": "event", "data": e})
	}

	batch, err := json.Marshal(events)
	if err != nil {
		return fmt.Errorf("marshal events failed: %w", err)
	}
	sum := sha256.Sum256(batch)
	batchHash := hex.EncodeToString(sum[:])

	verdict, err := scoreWithVerdictEngine(mon.verdictEngineURL, batchHash, events)
	if err != nil {
		return fmt.Errorf("scoring failed: %w", err)
	}
	mon.hub.Broadcast(map[string]any{"type": "verdict", "data": verdict})

	if verdict.Verdict != "Compromised" {
		return nil
	}

	mon.mu.Lock()
	if mon.isolated {
		mon.mu.Unlock()
		return nil
	}
	if err := mon.dm.IsolateContainer(ctx, monitorNetworkName, monitorContainerName); err != nil {
		mon.mu.Unlock()
		return fmt.Errorf("isolate failed: %w", err)
	}
	mon.isolated = true
	mon.mu.Unlock()
	mon.hub.Broadcast(map[string]any{"type": "isolated"})
	if err := logAction(mon.verdictEngineURL, "isolated", monitorDeviceID); err != nil {
		log.Printf("monitor: failed to audit-log isolate action: %v", err)
	}
	return nil
}

func (mon *Monitor) Reconnect(ctx context.Context) error {
	mon.mu.Lock()
	if !mon.isolated {
		mon.mu.Unlock()
		return errNotIsolated
	}
	mon.mu.Unlock()

	if err := mon.dm.ReconnectContainer(ctx, monitorNetworkName, monitorContainerName); err != nil {
		return err
	}
	mon.mu.Lock()
	mon.isolated = false
	mon.mu.Unlock()
	mon.hub.Broadcast(map[string]any{"type": "reconnected"})
	if err := logAction(mon.verdictEngineURL, "reconnected", monitorDeviceID); err != nil {
		log.Printf("monitor: failed to audit-log reconnect action: %v", err)
	}
	return nil
}

func logAction(baseURL, action, deviceID string) error {
	body, err := json.Marshal(map[string]string{"action": action, "device_id": deviceID})
	if err != nil {
		return err
	}
	resp, err := httpClient.Post(baseURL+"/audit/action", "application/json", bytes.NewReader(body))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("verdict-engine returned %d: %s", resp.StatusCode, string(b))
	}
	return nil
}
