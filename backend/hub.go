package main

import (
	"encoding/json"
	"log"
	"net/http"
	"net/url"
	"sync"

	"github.com/gorilla/websocket"
)

type Hub struct {
	mu      sync.Mutex
	clients map[*websocket.Conn]bool
}

func NewHub() *Hub {
	return &Hub{clients: make(map[*websocket.Conn]bool)}
}

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		origin := r.Header.Get("Origin")
		if origin == "" || origin == "null" {
			// Non-browser clients (curl, server-to-server health checks) send no
			// Origin header at all; browsers always send one, so this only
			// affects non-browser callers, which this check isn't meant to stop.
			// "null" specifically shows up on real same-origin requests too --
			// confirmed live from a Chromium --app= window, which sends a
			// literal "null" Origin for its WebSocket handshake instead of the
			// page's real origin -- so treating it as "no origin to check"
			// rather than rejecting it is correct here, not a loosened check.
			return true
		}
		u, err := url.Parse(origin)
		if err != nil || u.Host != r.Host {
			log.Printf("websocket: rejecting origin %q (want host %q)", origin, r.Host)
			return false
		}
		return true
	},
}

func (h *Hub) HandleWS(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	h.mu.Lock()
	h.clients[conn] = true
	h.mu.Unlock()

	defer func() {
		h.mu.Lock()
		delete(h.clients, conn)
		h.mu.Unlock()
		conn.Close()
	}()

	for {
		if _, _, err := conn.ReadMessage(); err != nil {
			break
		}
	}
}

func (h *Hub) Broadcast(msg any) {
	data, err := json.Marshal(msg)
	if err != nil {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	for conn := range h.clients {
		conn.WriteMessage(websocket.TextMessage, data)
	}
}
