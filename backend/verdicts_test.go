package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestChainVerifyHandlerProxiesGet(t *testing.T) {
	fakeEngine := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/verify" || r.Method != http.MethodGet {
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"intact":true,"entries":2,"broken_at":null}`))
	}))
	defer fakeEngine.Close()

	req := httptest.NewRequest(http.MethodGet, "/api/audit/verify", nil)
	rec := httptest.NewRecorder()
	chainVerifyHandler(fakeEngine.URL)(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), `"intact":true`) {
		t.Fatalf("expected proxied body, got %s", rec.Body.String())
	}
}

func TestChainVerifyHandlerReportsBrokenChain(t *testing.T) {
	fakeEngine := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/verify" || r.Method != http.MethodGet {
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"intact":false,"entries":3,"broken_at":2}`))
	}))
	defer fakeEngine.Close()

	req := httptest.NewRequest(http.MethodGet, "/api/audit/verify", nil)
	rec := httptest.NewRecorder()
	chainVerifyHandler(fakeEngine.URL)(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), `"broken_at":2`) {
		t.Fatalf("expected broken_at in body, got %s", rec.Body.String())
	}
}
