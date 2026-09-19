package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

func TestHubBroadcastsToConnectedClient(t *testing.T) {
	hub := NewHub()
	server := httptest.NewServer(nil)
	server.Config.Handler = nil
	mux := newTestMux(hub)
	server.Config.Handler = mux
	defer server.Close()

	wsURL := "ws" + server.URL[len("http"):] + "/api/live"
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	time.Sleep(50 * time.Millisecond)
	hub.Broadcast(map[string]string{"type": "test"})

	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, msg, err := conn.ReadMessage()
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(msg) == "" {
		t.Fatal("expected non-empty broadcast message")
	}
}

func TestHubRejectsCrossOriginUpgrade(t *testing.T) {
	hub := NewHub()
	server := httptest.NewServer(newTestMux(hub))
	defer server.Close()

	wsURL := "ws" + server.URL[len("http"):] + "/api/live"
	headers := http.Header{"Origin": []string{"http://evil.example"}}
	_, resp, err := websocket.DefaultDialer.Dial(wsURL, headers)
	if err == nil {
		t.Fatal("expected dial to fail for a cross-origin request")
	}
	if resp == nil || resp.StatusCode != http.StatusForbidden {
		status := "no response"
		if resp != nil {
			status = resp.Status
		}
		t.Fatalf("expected 403 Forbidden, got %s", status)
	}
}

func TestHubAllowsSameOriginUpgrade(t *testing.T) {
	hub := NewHub()
	server := httptest.NewServer(newTestMux(hub))
	defer server.Close()

	wsURL := "ws" + server.URL[len("http"):] + "/api/live"
	headers := http.Header{"Origin": []string{server.URL}}
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, headers)
	if err != nil {
		t.Fatalf("expected same-origin dial to succeed, got: %v", err)
	}
	conn.Close()
}
