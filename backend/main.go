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
	if len(os.Getenv("MIRRAURA_ADMIN_PASSWORD")) < 12 {
		log.Fatal("MIRRAURA_ADMIN_PASSWORD must be set and at least 12 characters")
	}
	users, err := loadUsers()
	if err != nil {
		log.Fatalf("loadUsers: %v", err)
	}

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

	store := NewSessionStore()
	limiter := NewLoginLimiter()
	mux := newMux(dm, verdictEngineURL, hub, mon, store, users, limiter)

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
	if err := http.ListenAndServe(":"+port, mux); err != nil {
		log.Fatal(err)
	}
}

func newMux(dm *DockerManager, verdictEngineURL string, hub *Hub, mon *Monitor, store *SessionStore, users map[string]User, limiter *LoginLimiter) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/health", healthHandler)
	mux.HandleFunc("/api/login", loginHandler(store, users, limiter))
	mux.Handle("/api/logout", requireAuth(store)(logoutHandler(store)))
	mux.Handle("/api/me", requireAuth(store)(meHandler()))
	mux.Handle("/api/samples", requireAuth(store)(samplesHandler(dm, verdictEngineURL, hub)))
	mux.Handle("/api/verdicts", requireAuth(store)(verdictsListHandler(verdictEngineURL)))
	mux.Handle("/api/verdicts/", requireAuth(store)(verdictDetailHandler(verdictEngineURL)))
	mux.Handle("/api/audit/verify", requireAuth(store)(chainVerifyHandler(verdictEngineURL)))
	mux.Handle("/api/live", requireAuth(store)(http.HandlerFunc(hub.HandleWS)))
	mux.Handle("/api/monitor/status", requireAuth(store)(monitorStatusHandler(mon)))
	mux.Handle("/api/monitor/reconnect", requireAuth(store)(requireRole("admin")(monitorReconnectHandler(mon))))
	mux.Handle("/api/hashes", requireAuth(store)(hashesHandler(verdictEngineURL)))
	mux.Handle("/api/hashes/", requireAuth(store)(requireRole("admin")(hashDecisionHandler(verdictEngineURL))))
	return mux
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}
