package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

func main() {
	ctx := context.Background()

	backendDBURL := os.Getenv("BACKEND_DATABASE_URL")
	backendMigrationsURL := os.Getenv("BACKEND_MIGRATIONS_DATABASE_URL")
	if backendDBURL == "" || backendMigrationsURL == "" {
		log.Fatal("BACKEND_DATABASE_URL and BACKEND_MIGRATIONS_DATABASE_URL must both be set")
	}
	if err := RunMigrations(ctx, backendMigrationsURL, backendDBURL, "migrations"); err != nil {
		log.Fatalf("RunMigrations: %v", err)
	}
	pool, err := NewPool(ctx, backendDBURL)
	if err != nil {
		log.Fatalf("NewPool: %v", err)
	}

	if err := SeedUsers(ctx, pool); err != nil {
		log.Fatalf("SeedUsers: %v", err)
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
	initCtx, initCancel := context.WithTimeout(ctx, 10*time.Second)
	mon.InitIsolatedState(initCtx)
	initCancel()

	store := NewSessionStore(pool)
	limiter := NewLoginLimiter()
	mux := newMux(dm, verdictEngineURL, hub, mon, store, pool, limiter)

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

	go func() {
		ticker := time.NewTicker(1 * time.Hour)
		defer ticker.Stop()
		for range ticker.C {
			cleanupCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			if err := store.CleanupExpired(cleanupCtx); err != nil {
				log.Printf("session cleanup failed: %v", err)
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

func newMux(dm *DockerManager, verdictEngineURL string, hub *Hub, mon *Monitor, store *SessionStore, pool *pgxpool.Pool, limiter *LoginLimiter) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/health", healthHandler)
	mux.HandleFunc("/api/login", loginHandler(store, pool, limiter))
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
	mux.Handle("/api/users", requireAuth(store)(requireRole("admin")(dispatchByMethod(map[string]http.HandlerFunc{
		http.MethodGet:  listUsersHandler(pool),
		http.MethodPost: createUserHandler(pool),
	}))))
	mux.Handle("/api/users/{username}", requireAuth(store)(requireRole("admin")(dispatchByMethod(map[string]http.HandlerFunc{
		http.MethodDelete: deleteUserHandler(store, pool),
	}))))
	mux.Handle("/api/users/{username}/role", requireAuth(store)(requireRole("admin")(dispatchByMethod(map[string]http.HandlerFunc{
		http.MethodPatch: updateUserRoleHandler(store, pool),
	}))))
	return mux
}

// dispatchByMethod routes to the handler registered for r.Method, or 405.
func dispatchByMethod(byMethod map[string]http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		h, ok := byMethod[r.Method]
		if !ok {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		h(w, r)
	}
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}
