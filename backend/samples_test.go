package main

import (
	"bytes"
	"context"
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

	v, err := scoreWithVerdictEngine(fakeEngine.URL, "somehash", "file.bin", "sample", "", false, nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if v.VerdictID != "v1" {
		t.Fatalf("expected verdict id v1, got %s", v.VerdictID)
	}
}

func TestScoreWithVerdictEngineSendsTimedOutFlag(t *testing.T) {
	var gotBody map[string]any
	fakeEngine := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&gotBody)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(Verdict{VerdictID: "v1", Verdict: "Inconclusive"})
	}))
	defer fakeEngine.Close()

	_, err := scoreWithVerdictEngine(fakeEngine.URL, "somehash", "file.bin", "sample", "", true, nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gotBody["timed_out"] != true {
		t.Fatalf("expected timed_out=true in request body, got %v", gotBody["timed_out"])
	}
}

func TestScoreWithVerdictEngineSendsActor(t *testing.T) {
	var gotBody map[string]any
	fakeEngine := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&gotBody)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(Verdict{VerdictID: "v1", Verdict: "Normal"})
	}))
	defer fakeEngine.Close()

	_, err := scoreWithVerdictEngine(fakeEngine.URL, "somehash", "file.bin", "sample", "alice", false, nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gotBody["actor"] != "alice" {
		t.Fatalf("expected actor=alice in request body, got %v", gotBody["actor"])
	}
}

func TestStaticTriageParsesMatches(t *testing.T) {
	var gotBody map[string]any
	fakeEngine := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&gotBody)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"matches": []string{"YARA rule 'X' matched"}})
	}))
	defer fakeEngine.Close()

	matches, err := staticTriage(fakeEngine.URL, []byte("hello"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(matches) != 1 || matches[0] != "YARA rule 'X' matched" {
		t.Fatalf("unexpected matches: %v", matches)
	}
	if _, ok := gotBody["sample_content_b64"]; !ok {
		t.Fatalf("expected sample_content_b64 in request body, got %v", gotBody)
	}
}

func TestDetonateAndScoreSkipsDetonationOnStaticMatch(t *testing.T) {
	fakeEngine := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/triage":
			json.NewEncoder(w).Encode(map[string]any{"matches": []string{"YARA rule 'EICAR_Test_String' matched"}})
		case "/score":
			var body map[string]any
			json.NewDecoder(r.Body).Decode(&body)
			if body["static_matches"] == nil {
				t.Errorf("expected static_matches to be forwarded to /score")
			}
			json.NewEncoder(w).Encode(Verdict{VerdictID: "v1", Verdict: "Compromised", Confidence: 1.0})
		default:
			t.Fatalf("unexpected call to %s -- detonation should have been skipped", r.URL.Path)
		}
	}))
	defer fakeEngine.Close()

	// dm is nil: if detonation were attempted, this would panic -- proof
	// the static match actually short-circuited before touching Docker.
	v, err := detonateAndScore(context.Background(), nil, fakeEngine.URL, &fakeBroadcaster{}, []byte("sample content"), "x.sh", "sample", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if v.Verdict != "Compromised" {
		t.Fatalf("expected Compromised, got %s", v.Verdict)
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
