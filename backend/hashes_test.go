package main

import (
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

func TestHashDecisionHandlerProxiesApprove(t *testing.T) {
	fakeEngine := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/hashes/abc123/approve" || r.Method != http.MethodPost {
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"hash":"abc123","status":"approved"}`))
	}))
	defer fakeEngine.Close()

	req := httptest.NewRequest(http.MethodPost, "/api/hashes/abc123/approve", nil)
	rec := httptest.NewRecorder()
	hashDecisionHandler(fakeEngine.URL)(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), `"status":"approved"`) {
		t.Fatalf("expected proxied body, got %s", rec.Body.String())
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
