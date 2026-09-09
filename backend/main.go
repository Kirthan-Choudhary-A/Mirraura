package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"time"
)

func main() {
	verdictEngineURL := os.Getenv("VERDICT_ENGINE_URL")
	if verdictEngineURL == "" {
		verdictEngineURL = "http://localhost:8000"
	}
	dm, err := NewDockerManager()
	if err != nil {
		log.Fatal(err)
	}
	hub := NewHub()
	mon := NewMonitor(dm, verdictEngineURL, hub)
	initCtx, initCancel := context.WithTimeout(context.Background(), 10*time.Second)
	mon.InitIsolatedState(initCtx)
	initCancel()

	mux := http.NewServeMux()
	mux.HandleFunc("/api/health", healthHandler)
	mux.HandleFunc("/api/samples", samplesHandler(dm, verdictEngineURL, hub))
	mux.HandleFunc("/api/verdicts", verdictsListHandler(verdictEngineURL))
	mux.HandleFunc("/api/verdicts/", verdictDetailHandler(verdictEngineURL))
	mux.HandleFunc("/api/live", hub.HandleWS)
	mux.HandleFunc("/api/monitor/status", monitorStatusHandler(mon))
	mux.HandleFunc("/api/monitor/reconnect", monitorReconnectHandler(mon))
	mux.HandleFunc("/api/hashes", hashesHandler(verdictEngineURL))
	mux.HandleFunc("/api/hashes/", hashDecisionHandler(verdictEngineURL))

	go func() {
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			if err := mon.Tick(ctx); err != nil {
				log.Printf("monitor tick failed: %v", err)
			}
			cancel()
		}
	}()

	port := os.Getenv("BACKEND_PORT")
	if port == "" {
		port = "8080"
	}
	log.Printf("backend listening on :%s", port)
	if err := http.ListenAndServe(":"+port, withCORS(mux)); err != nil {
		log.Fatal(err)
	}
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func withCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}
