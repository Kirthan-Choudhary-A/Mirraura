package main

import (
	"bytes"
	"context"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

func TestDecisionForVerdict(t *testing.T) {
	cases := map[string]string{
		"Normal":       "release",
		"Compromised":  "block",
		"Suspicious":   "hold",
		"Inconclusive": "hold",
	}
	for label, want := range cases {
		if got := decisionForVerdict(label); got != want {
			t.Errorf("decisionForVerdict(%q) = %q, want %q", label, got, want)
		}
	}
}

func newInterceptMultipartRequest(t *testing.T, fileName string, content []byte, originalPath string) *http.Request {
	t.Helper()
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	if fileName != "" {
		part, err := w.CreateFormFile("sample", fileName)
		if err != nil {
			t.Fatal(err)
		}
		part.Write(content)
	}
	if originalPath != "" {
		w.WriteField("original_path", originalPath)
	}
	w.Close()

	req := httptest.NewRequest(http.MethodPost, "/api/intercept", &buf)
	req.Header.Set("Content-Type", w.FormDataContentType())
	return req
}

func TestInterceptHandlerRejectsMissingFile(t *testing.T) {
	req := newInterceptMultipartRequest(t, "", nil, "/home/user/Downloads/x.sh")
	rec := httptest.NewRecorder()

	interceptHandler(nil, "http://unused", &fakeBroadcaster{}, nil)(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}
}

func TestInterceptHandlerRejectsMissingOriginalPath(t *testing.T) {
	req := newInterceptMultipartRequest(t, "x.sh", []byte("echo hi"), "")
	rec := httptest.NewRecorder()

	interceptHandler(nil, "http://unused", &fakeBroadcaster{}, nil)(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}
}

func TestInterceptHandlerRejectsWrongMethod(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/intercept", nil)
	rec := httptest.NewRecorder()

	interceptHandler(nil, "http://unused", &fakeBroadcaster{}, nil)(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", rec.Code)
	}
}

func TestRequireTokenRejectsMissingHeader(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/intercept", nil)
	called := false
	h := requireToken("secret")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true }))
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized || called {
		t.Fatalf("expected 401 and handler not called, got %d called=%v", rec.Code, called)
	}
}

func TestRequireTokenRejectsWrongToken(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/intercept", nil)
	req.Header.Set("Authorization", "Bearer wrong")
	h := requireToken("secret")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
}

func TestRequireTokenFailsClosedWhenUnconfigured(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/intercept", nil)
	req.Header.Set("Authorization", "Bearer anything")
	h := requireToken("")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 when no token is configured, got %d", rec.Code)
	}
}

func TestRequireTokenAcceptsCorrectToken(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/intercept", nil)
	req.Header.Set("Authorization", "Bearer secret")
	called := false
	h := requireToken("secret")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true }))
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !called {
		t.Fatalf("expected 200 and handler called, got %d called=%v", rec.Code, called)
	}
}

// TestQuarantinePendingHandlerReturnsEmptyArrayNotNull guards against
// encoding/json marshaling a nil slice as the JSON literal "null" -- the
// frontend calls .length/.map() on this response unconditionally, which
// throws on null the moment the queue is empty.
func TestQuarantinePendingHandlerReturnsEmptyArrayNotNull(t *testing.T) {
	pool := newTestQuarantinePool(t)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/intercept/pending", nil)
	quarantinePendingHandler(pool)(rec, req)

	if got := rec.Body.String(); strings.TrimSpace(got) != "[]" {
		t.Fatalf("expected literal JSON [], got %q", got)
	}
}

func TestQuarantinePendingAndDecisionHandlers(t *testing.T) {
	pool := newTestQuarantinePool(t)
	ctx := context.Background()
	fakeEngine := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer fakeEngine.Close()

	id, err := insertQuarantine(ctx, pool, "abc123", "payload.sh", "/home/user/Downloads/payload.sh", "Suspicious", 0.45)
	if err != nil {
		t.Fatalf("insertQuarantine: %v", err)
	}

	// GET /api/intercept/pending
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/intercept/pending", nil)
	quarantinePendingHandler(pool)(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	var entries []QuarantinedFile
	if err := json.Unmarshal(rec.Body.Bytes(), &entries); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(entries) != 1 || entries[0].ID != id {
		t.Fatalf("unexpected pending list: %+v", entries)
	}

	// POST /api/intercept/{id}/approve
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/api/intercept/x/approve", nil).WithContext(adminSessionContext())
	req.SetPathValue("id", intToStr(id))
	quarantineDecisionHandler(pool, fakeEngine.URL, "approve")(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d: %s", rec.Code, rec.Body.String())
	}

	status, err := getQuarantineStatus(ctx, pool, id)
	if err != nil {
		t.Fatalf("getQuarantineStatus: %v", err)
	}
	if status != "approved" {
		t.Fatalf("expected approved, got %s", status)
	}

	// Deciding again must 404 (already decided).
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/api/intercept/x/reject", nil).WithContext(adminSessionContext())
	req.SetPathValue("id", intToStr(id))
	quarantineDecisionHandler(pool, fakeEngine.URL, "reject")(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404 re-deciding an already-decided entry, got %d", rec.Code)
	}
}

func TestQuarantineStatusHandler(t *testing.T) {
	pool := newTestQuarantinePool(t)
	ctx := context.Background()
	id, err := insertQuarantine(ctx, pool, "abc123", "payload.sh", "/home/user/Downloads/payload.sh", "Suspicious", 0.45)
	if err != nil {
		t.Fatalf("insertQuarantine: %v", err)
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/intercept/x/status", nil)
	req.SetPathValue("id", intToStr(id))
	quarantineStatusHandler(pool)(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	var body map[string]string
	json.Unmarshal(rec.Body.Bytes(), &body)
	if body["status"] != "pending" {
		t.Fatalf("expected pending, got %v", body)
	}

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/api/intercept/x/status", nil)
	req.SetPathValue("id", "999999")
	quarantineStatusHandler(pool)(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for a nonexistent id, got %d", rec.Code)
	}
}

func intToStr(n int64) string {
	return strconv.FormatInt(n, 10)
}
