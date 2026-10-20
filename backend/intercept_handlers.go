package main

import (
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"strconv"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type interceptResponse struct {
	Verdict      *Verdict `json:"verdict"`
	Decision     string   `json:"decision"`
	QuarantineID *int64   `json:"quarantine_id,omitempty"`
}

// decisionForVerdict maps a verdict label to what the interceptor daemon
// should do with the file it's holding: Normal is safe to release
// immediately, Compromised stays blocked, and anything else (Suspicious or
// Inconclusive -- not confidently clean, but not confidently bad either)
// holds for a human decision rather than guessing either direction.
func decisionForVerdict(label string) string {
	switch label {
	case "Normal":
		return "release"
	case "Compromised":
		return "block"
	default:
		return "hold"
	}
}

// interceptHandler is the interceptor daemon's submission endpoint: a file
// it already moved into its own host-side quarantine directory gets
// detonated exactly like a human upload would, and the verdict maps to a
// decision the daemon acts on (release the file, hold it for a human, or
// leave it blocked).
func interceptHandler(dm *DockerManager, verdictEngineURL string, hub Broadcaster, pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 64<<20)
		file, header, err := r.FormFile("sample")
		if err != nil {
			http.Error(w, "missing 'sample' file field", http.StatusBadRequest)
			return
		}
		defer file.Close()
		originalPath := r.FormValue("original_path")
		if originalPath == "" {
			http.Error(w, "missing 'original_path' field", http.StatusBadRequest)
			return
		}

		data, err := io.ReadAll(file)
		if err != nil {
			http.Error(w, "failed to read upload", http.StatusInternalServerError)
			return
		}
		filename := header.Filename

		verdict, err := detonateAndScore(r.Context(), dm, verdictEngineURL, hub, data, filename, "interceptor", "interceptor")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		resp := interceptResponse{Verdict: verdict, Decision: decisionForVerdict(verdict.Verdict)}
		if resp.Decision == "hold" {
			id, err := insertQuarantine(r.Context(), pool, verdict.SampleHash, filename, originalPath, verdict.Verdict, verdict.Confidence)
			if err != nil {
				http.Error(w, "failed to record quarantine", http.StatusInternalServerError)
				return
			}
			resp.QuarantineID = &id
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}
}

func quarantinePendingHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		entries, err := listPendingQuarantine(r.Context(), pool)
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(entries)
	}
}

// quarantineDecisionHandler is registered once for "approve" and once for
// "reject" (decision is baked in via closure, same pattern as
// requireRole), so each route is its own fixed-method, fixed-outcome
// handler rather than parsing the decision back out of the URL.
func quarantineDecisionHandler(pool *pgxpool.Pool, verdictEngineURL, decision string) http.HandlerFunc {
	dbStatus := map[string]string{"approve": "approved", "reject": "rejected"}[decision]
	auditAction := map[string]string{"approve": "quarantine_approved", "reject": "quarantine_rejected"}[decision]
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
		if err != nil {
			http.Error(w, "invalid id", http.StatusBadRequest)
			return
		}
		q, err := decideQuarantine(r.Context(), pool, id, dbStatus)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				http.Error(w, "not found or already decided", http.StatusNotFound)
				return
			}
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		actor, _ := sessionFromContext(r.Context())
		if err := logAction(verdictEngineURL, auditAction, q.Filename, actor.Username); err != nil {
			log.Printf("%s: failed to audit-log quarantine decision for %s: %v", auditAction, q.Filename, err)
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

// quarantineStatusHandler is the interceptor daemon's poll endpoint for a
// file it's holding pending a human decision.
func quarantineStatusHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
		if err != nil {
			http.Error(w, "invalid id", http.StatusBadRequest)
			return
		}
		status, err := getQuarantineStatus(r.Context(), pool, id)
		if err != nil {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": status})
	}
}
