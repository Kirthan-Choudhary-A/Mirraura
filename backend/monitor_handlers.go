package main

import (
	"encoding/json"
	"net/http"
)

func monitorStatusHandler(mon *Monitor) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]bool{"isolated": mon.IsIsolated()})
	}
}

func monitorReconnectHandler(mon *Monitor) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		actor, _ := sessionFromContext(r.Context())
		if err := mon.Reconnect(r.Context(), actor.Username); err != nil {
			if err == errNotIsolated {
				http.Error(w, "not currently isolated", http.StatusBadRequest)
				return
			}
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]bool{"isolated": false})
	}
}
