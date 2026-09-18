package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHashesHandlerProxiesGet(t *testing.T) {
	fakeEngine := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/hashes" || r.Method != http.MethodGet {
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`[{"hash":"a","status":"pending"}]`))
	}))
	defer fakeEngine.Close()

	req := httptest.NewRequest(http.MethodGet, "/api/hashes", nil)
	rec := httptest.NewRecorder()
	hashesHandler(fakeEngine.URL)(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), `"hash":"a"`) {
		t.Fatalf("expected proxied body, got %s", rec.Body.String())
	}
}

func TestHashesHandlerProxiesPost(t *testing.T) {
	fakeEngine := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/hashes" || r.Method != http.MethodPost {
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		w.WriteHeader(http.StatusConflict)
		w.Write([]byte(`{"detail":"hash already exists"}`))
	}))
	defer fakeEngine.Close()

	req := httptest.NewRequest(http.MethodPost, "/api/hashes", strings.NewReader(`{"hash":"a","label":"b"}`))
	rec := httptest.NewRecorder()
	hashesHandler(fakeEngine.URL)(rec, req)

	if rec.Code != http.StatusConflict {
		t.Fatalf("expected 409, got %d", rec.Code)
	}
}

func TestHashesHandlerRejectsOtherMethods(t *testing.T) {
	req := httptest.NewRequest(http.MethodDelete, "/api/hashes", nil)
	rec := httptest.NewRecorder()
	hashesHandler("http://unused")(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", rec.Code)
	}
}

func TestHashDecisionHandlerProxiesApproveWithActor(t *testing.T) {
	var gotBody map[string]any
	fakeEngine := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/hashes/abc123/approve" || r.Method != http.MethodPost {
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		json.NewDecoder(r.Body).Decode(&gotBody)
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"hash":"abc123","status":"approved"}`))
	}))
	defer fakeEngine.Close()

	req := httptest.NewRequest(http.MethodPost, "/api/hashes/abc123/approve", nil)
	ctx := context.WithValue(req.Context(), sessionCtxKey, Session{Username: "alice", Role: "admin"})
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()
	hashDecisionHandler(fakeEngine.URL)(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if gotBody["actor"] != "alice" {
		t.Fatalf("expected actor=alice forwarded to verdict-engine, got %v", gotBody["actor"])
	}
}

func TestHashDecisionHandlerRejectsBadPath(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/api/hashes/abc123/frobnicate", nil)
	rec := httptest.NewRecorder()
	hashDecisionHandler("http://unused")(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", rec.Code)
	}
}

// Routes through a real ServeMux rather than calling the handlers directly, so
// the exact-match-before-prefix registration ("/api/hashes" vs "/api/hashes/")
// is itself under test — that routing decision is the Go/frontend seam.
func TestHashRoutesRegisteredCorrectlyOnRealMux(t *testing.T) {
	var gotPaths []string
	fakeEngine := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPaths = append(gotPaths, r.Method+" "+r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{}`))
	}))
	defer fakeEngine.Close()

	mux := http.NewServeMux()
	mux.HandleFunc("/api/hashes", hashesHandler(fakeEngine.URL))
	mux.HandleFunc("/api/hashes/", hashDecisionHandler(fakeEngine.URL))

	cases := []struct {
		method, path, wantUpstream string
	}{
		{http.MethodGet, "/api/hashes", "GET /hashes"},
		{http.MethodPost, "/api/hashes", "POST /hashes"},
		{http.MethodPost, "/api/hashes/abc123/approve", "POST /hashes/abc123/approve"},
		{http.MethodPost, "/api/hashes/abc123/reject", "POST /hashes/abc123/reject"},
	}

	for _, c := range cases {
		gotPaths = nil
		req := httptest.NewRequest(c.method, c.path, nil)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if len(gotPaths) != 1 || gotPaths[0] != c.wantUpstream {
			t.Errorf("%s %s: expected upstream call %q, got %v", c.method, c.path, c.wantUpstream, gotPaths)
		}
	}
}
