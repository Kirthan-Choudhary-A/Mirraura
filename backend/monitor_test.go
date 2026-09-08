package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

type fakeMonitorDocker struct {
	pollLines      []string
	pollErr        error
	isolateCalls   int
	reconnectCalls int
	isolateErr     error
	reconnectErr   error
}

func (f *fakeMonitorDocker) RunPoller(ctx context.Context, containerID string) (<-chan string, error) {
	if f.pollErr != nil {
		return nil, f.pollErr
	}
	ch := make(chan string, len(f.pollLines))
	for _, l := range f.pollLines {
		ch <- l
	}
	close(ch)
	return ch, nil
}

func (f *fakeMonitorDocker) IsolateContainer(ctx context.Context, networkName, containerName string) error {
	f.isolateCalls++
	return f.isolateErr
}

func (f *fakeMonitorDocker) ReconnectContainer(ctx context.Context, networkName, containerName string) error {
	f.reconnectCalls++
	return f.reconnectErr
}

func fakeVerdictEngine(t *testing.T, verdictLabel string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(Verdict{VerdictID: "v1", Verdict: verdictLabel, Confidence: 1.0})
	}))
}

func TestTickSkipsScoringWhenNoEvents(t *testing.T) {
	fd := &fakeMonitorDocker{pollLines: nil}
	engine := fakeVerdictEngine(t, "Normal")
	defer engine.Close()

	mon := NewMonitor(fd, engine.URL, &fakeBroadcaster{})
	if err := mon.Tick(context.Background()); err != nil {
		t.Fatalf("Tick: %v", err)
	}
	if fd.isolateCalls != 0 {
		t.Fatalf("expected no isolate calls, got %d", fd.isolateCalls)
	}
}

func TestTickIsolatesOnCompromisedVerdict(t *testing.T) {
	fd := &fakeMonitorDocker{pollLines: []string{`{"event_type":"process_spawn"}`}}
	engine := fakeVerdictEngine(t, "Compromised")
	defer engine.Close()

	mon := NewMonitor(fd, engine.URL, &fakeBroadcaster{})
	if err := mon.Tick(context.Background()); err != nil {
		t.Fatalf("Tick: %v", err)
	}
	if fd.isolateCalls != 1 {
		t.Fatalf("expected 1 isolate call, got %d", fd.isolateCalls)
	}
	if !mon.IsIsolated() {
		t.Fatal("expected monitor to be marked isolated")
	}
}

func TestTickDoesNotReIsolateWhenAlreadyIsolated(t *testing.T) {
	fd := &fakeMonitorDocker{pollLines: []string{`{"event_type":"process_spawn"}`}}
	engine := fakeVerdictEngine(t, "Compromised")
	defer engine.Close()

	mon := NewMonitor(fd, engine.URL, &fakeBroadcaster{})
	if err := mon.Tick(context.Background()); err != nil {
		t.Fatalf("first Tick: %v", err)
	}
	if err := mon.Tick(context.Background()); err != nil {
		t.Fatalf("second Tick: %v", err)
	}
	if fd.isolateCalls != 1 {
		t.Fatalf("expected isolate called exactly once across two Compromised ticks, got %d", fd.isolateCalls)
	}
}

func TestReconnectFailsWhenNotIsolated(t *testing.T) {
	fd := &fakeMonitorDocker{}
	mon := NewMonitor(fd, "http://unused", &fakeBroadcaster{})
	if err := mon.Reconnect(context.Background()); err != errNotIsolated {
		t.Fatalf("expected errNotIsolated, got %v", err)
	}
}

func TestReconnectClearsIsolatedFlag(t *testing.T) {
	fd := &fakeMonitorDocker{pollLines: []string{`{"event_type":"process_spawn"}`}}
	engine := fakeVerdictEngine(t, "Compromised")
	defer engine.Close()

	mon := NewMonitor(fd, engine.URL, &fakeBroadcaster{})
	if err := mon.Tick(context.Background()); err != nil {
		t.Fatalf("Tick: %v", err)
	}
	if err := mon.Reconnect(context.Background()); err != nil {
		t.Fatalf("Reconnect: %v", err)
	}
	if mon.IsIsolated() {
		t.Fatal("expected monitor to no longer be isolated")
	}
	if fd.reconnectCalls != 1 {
		t.Fatalf("expected 1 reconnect call, got %d", fd.reconnectCalls)
	}
}
