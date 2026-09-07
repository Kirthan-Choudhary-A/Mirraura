package main

import (
	"bytes"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"testing"
)

type fakeBroadcaster struct{ messages []any }

func (f *fakeBroadcaster) Broadcast(msg any) { f.messages = append(f.messages, msg) }

func TestSamplesHandlerRejectsMissingFile(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/api/samples", nil)
	rec := httptest.NewRecorder()

	handler := samplesHandler(nil, "http://unused", &fakeBroadcaster{})
	handler(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}
}

func TestScoreWithVerdictEngine(t *testing.T) {
	fakeEngine := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(Verdict{VerdictID: "v1", Verdict: "Normal", Confidence: 0})
	}))
	defer fakeEngine.Close()

	v, err := scoreWithVerdictEngine(fakeEngine.URL, "somehash", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if v.VerdictID != "v1" {
		t.Fatalf("expected verdict id v1, got %s", v.VerdictID)
	}
}

func newMultipartRequest(t *testing.T, fieldName, fileName string, content []byte) *http.Request {
	t.Helper()
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	part, err := w.CreateFormFile(fieldName, fileName)
	if err != nil {
		t.Fatal(err)
	}
	part.Write(content)
	w.Close()

	req := httptest.NewRequest(http.MethodPost, "/api/samples", &buf)
	req.Header.Set("Content-Type", w.FormDataContentType())
	return req
}
