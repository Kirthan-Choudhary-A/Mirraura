package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCorpusHandlerProxiesGet(t *testing.T) {
	fakeEngine := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/corpus" || r.Method != http.MethodGet {
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`[{"content_hash":"a","status":"pending"}]`))
	}))
	defer fakeEngine.Close()

	req := httptest.NewRequest(http.MethodGet, "/api/corpus", nil)
	rec := httptest.NewRecorder()
	corpusHandler(fakeEngine.URL)(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), `"content_hash":"a"`) {
		t.Fatalf("expected proxied body, got %s", rec.Body.String())
	}
}

func TestCorpusHandlerProxiesPost(t *testing.T) {
	fakeEngine := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/corpus" || r.Method != http.MethodPost {
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		w.WriteHeader(http.StatusConflict)
		w.Write([]byte(`{"detail":"sample already exists"}`))
	}))
	defer fakeEngine.Close()

	req := httptest.NewRequest(http.MethodPost, "/api/corpus", strings.NewReader(`{"content_b64":"YQ==","label":"b"}`))
	rec := httptest.NewRecorder()
	corpusHandler(fakeEngine.URL)(rec, req)

	if rec.Code != http.StatusConflict {
		t.Fatalf("expected 409, got %d", rec.Code)
	}
}

func TestCorpusHandlerRejectsOtherMethods(t *testing.T) {
	req := httptest.NewRequest(http.MethodDelete, "/api/corpus", nil)
	rec := httptest.NewRecorder()
	corpusHandler("http://unused")(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", rec.Code)
	}
}

func TestCorpusDecisionHandlerProxiesApproveWithActor(t *testing.T) {
	var gotBody map[string]any
	fakeEngine := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/corpus/abc123/approve" || r.Method != http.MethodPost {
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		json.NewDecoder(r.Body).Decode(&gotBody)
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"content_hash":"abc123","status":"approved"}`))
	}))
	defer fakeEngine.Close()

	req := httptest.NewRequest(http.MethodPost, "/api/corpus/abc123/approve", nil)
	ctx := context.WithValue(req.Context(), sessionCtxKey, Session{Username: "alice", Role: "admin"})
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()
	corpusDecisionHandler(fakeEngine.URL)(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if gotBody["actor"] != "alice" {
		t.Fatalf("expected actor=alice forwarded to verdict-engine, got %v", gotBody["actor"])
	}
}

func TestCorpusDecisionHandlerRejectsBadPath(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/api/corpus/abc123/frobnicate", nil)
	rec := httptest.NewRecorder()
	corpusDecisionHandler("http://unused")(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", rec.Code)
	}
}

// Routes through a real ServeMux rather than calling the handlers directly, so
// the exact-match-before-prefix registration ("/api/corpus" vs "/api/corpus/")
// is itself under test — that routing decision is the Go/frontend seam.
func TestCorpusRoutesRegisteredCorrectlyOnRealMux(t *testing.T) {
	var gotPaths []string
	fakeEngine := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPaths = append(gotPaths, r.Method+" "+r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{}`))
	}))
	defer fakeEngine.Close()

	mux := http.NewServeMux()
	mux.HandleFunc("/api/corpus", corpusHandler(fakeEngine.URL))
	mux.HandleFunc("/api/corpus/", corpusDecisionHandler(fakeEngine.URL))

	cases := []struct {
		method, path, wantUpstream string
	}{
		{http.MethodGet, "/api/corpus", "GET /corpus"},
		{http.MethodPost, "/api/corpus", "POST /corpus"},
		{http.MethodPost, "/api/corpus/abc123/approve", "POST /corpus/abc123/approve"},
		{http.MethodPost, "/api/corpus/abc123/reject", "POST /corpus/abc123/reject"},
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
