package main

import (
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
