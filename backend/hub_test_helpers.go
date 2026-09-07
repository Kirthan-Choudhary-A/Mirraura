package main

import "net/http"

func newTestMux(hub *Hub) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/live", hub.HandleWS)
	return mux
}
