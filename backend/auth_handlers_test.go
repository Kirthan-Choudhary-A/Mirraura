package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/gorilla/websocket"
	"golang.org/x/crypto/bcrypt"
)

func testUsers(t *testing.T) map[string]User {
	t.Helper()
	adminHash, err := bcrypt.GenerateFromPassword([]byte("adminpassword123"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("GenerateFromPassword: %v", err)
	}
	analystHash, err := bcrypt.GenerateFromPassword([]byte("analystpassword123"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("GenerateFromPassword: %v", err)
	}
	return map[string]User{
		"admin":   {Username: "admin", PasswordHash: string(adminHash), Role: "admin"},
		"analyst": {Username: "analyst", PasswordHash: string(analystHash), Role: "analyst"},
	}
}

func testMux(t *testing.T) *http.ServeMux {
	t.Helper()
	hub := NewHub()
	mon := NewMonitor(&fakeMonitorDocker{}, "http://unused", hub)
	return newMux(nil, "http://unused", hub, mon, NewSessionStore(), testUsers(t), NewLoginLimiter())
}

func TestLoginSucceedsAndSetsCookie(t *testing.T) {
	mux := testMux(t)
	body, _ := json.Marshal(map[string]string{"username": "admin", "password": "adminpassword123"})
	req := httptest.NewRequest(http.MethodPost, "/api/login", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var got map[string]string
	json.Unmarshal(rec.Body.Bytes(), &got)
	if got["username"] != "admin" || got["role"] != "admin" {
		t.Fatalf("unexpected body: %v", got)
	}
	found := false
	for _, c := range rec.Result().Cookies() {
		if c.Name == "mirraura_session" && c.HttpOnly && c.SameSite == http.SameSiteStrictMode {
			found = true
		}
	}
	if !found {
		t.Fatal("expected an HttpOnly, SameSite=Strict mirraura_session cookie")
	}
}

func TestLoginFailureGenericMessage(t *testing.T) {
	mux := testMux(t)

	cases := []map[string]string{
		{"username": "admin", "password": "wrongpassword"},
		{"username": "nosuchuser", "password": "whatever12345"},
	}
	for _, c := range cases {
		body, _ := json.Marshal(c)
		req := httptest.NewRequest(http.MethodPost, "/api/login", bytes.NewReader(body))
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401, got %d", rec.Code)
		}
		if !strings.Contains(rec.Body.String(), "Invalid username or password") {
			t.Fatalf("expected the generic error message, got: %s", rec.Body.String())
		}
	}
}

func TestLoginRateLimitedAfterFiveFailures(t *testing.T) {
	mux := testMux(t)
	body, _ := json.Marshal(map[string]string{"username": "admin", "password": "wrongpassword"})

	for i := 0; i < 5; i++ {
		req := httptest.NewRequest(http.MethodPost, "/api/login", bytes.NewReader(body))
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: expected 401, got %d", i+1, rec.Code)
		}
	}
	req := httptest.NewRequest(http.MethodPost, "/api/login", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429 on the 6th attempt, got %d", rec.Code)
	}
}

func TestMiddlewareBlocksUnauthenticatedRequest(t *testing.T) {
	mux := testMux(t)
	req := httptest.NewRequest(http.MethodGet, "/api/verdicts", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for an unauthenticated request, got %d", rec.Code)
	}
}

func TestHealthAndLoginAreReachableWithoutAuth(t *testing.T) {
	mux := testMux(t)
	for _, path := range []string{"/api/health"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: expected 200, got %d", path, rec.Code)
		}
	}
}

// login performs a real login against server and returns a Cookie header
// value usable both for further http.Client calls (via jar) and for a raw
// websocket.Dialer, which doesn't take a cookie jar.
func login(t *testing.T, server *httptest.Server, username, password string) (*http.Client, string) {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar.New: %v", err)
	}
	client := &http.Client{Jar: jar}
	body, _ := json.Marshal(map[string]string{"username": username, "password": password})
	resp, err := client.Post(server.URL+"/api/login", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("login POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("login: expected 200, got %d", resp.StatusCode)
	}
	u, _ := url.Parse(server.URL)
	var cookieHeader string
	for _, c := range jar.Cookies(u) {
		if c.Name == "mirraura_session" {
			cookieHeader = c.Name + "=" + c.Value
		}
	}
	if cookieHeader == "" {
		t.Fatal("expected a mirraura_session cookie after login")
	}
	return client, cookieHeader
}

func TestAnalystGets403OnHashApprove(t *testing.T) {
	fakeEngine := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"hash":"abc","status":"approved"}`))
	}))
	defer fakeEngine.Close()

	hub := NewHub()
	mon := NewMonitor(&fakeMonitorDocker{}, fakeEngine.URL, hub)
	mux := newMux(nil, fakeEngine.URL, hub, mon, NewSessionStore(), testUsers(t), NewLoginLimiter())
	server := httptest.NewServer(mux)
	defer server.Close()

	client, _ := login(t, server, "analyst", "analystpassword123")
	resp, err := client.Post(server.URL+"/api/hashes/abc/approve", "application/json", nil)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 for an analyst approving a hash, got %d", resp.StatusCode)
	}
}

func TestAdminCanApproveHash(t *testing.T) {
	fakeEngine := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"hash":"abc","status":"approved"}`))
	}))
	defer fakeEngine.Close()

	hub := NewHub()
	mon := NewMonitor(&fakeMonitorDocker{}, fakeEngine.URL, hub)
	mux := newMux(nil, fakeEngine.URL, hub, mon, NewSessionStore(), testUsers(t), NewLoginLimiter())
	server := httptest.NewServer(mux)
	defer server.Close()

	client, _ := login(t, server, "admin", "adminpassword123")
	resp, err := client.Post(server.URL+"/api/hashes/abc/approve", "application/json", nil)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 for an admin approving a hash, got %d", resp.StatusCode)
	}
}

func TestWebSocketRejectedWithoutCookie(t *testing.T) {
	hub := NewHub()
	mon := NewMonitor(&fakeMonitorDocker{}, "http://unused", hub)
	mux := newMux(nil, "http://unused", hub, mon, NewSessionStore(), testUsers(t), NewLoginLimiter())
	server := httptest.NewServer(mux)
	defer server.Close()

	wsURL := "ws" + server.URL[len("http"):] + "/api/live"
	_, resp, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err == nil {
		t.Fatal("expected the dial to fail without a session cookie")
	}
	if resp == nil || resp.StatusCode != http.StatusUnauthorized {
		status := "no response"
		if resp != nil {
			status = resp.Status
		}
		t.Fatalf("expected 401 Unauthorized, got %s", status)
	}
}

func TestWebSocketAcceptedWithValidCookie(t *testing.T) {
	hub := NewHub()
	mon := NewMonitor(&fakeMonitorDocker{}, "http://unused", hub)
	mux := newMux(nil, "http://unused", hub, mon, NewSessionStore(), testUsers(t), NewLoginLimiter())
	server := httptest.NewServer(mux)
	defer server.Close()

	_, cookieHeader := login(t, server, "admin", "adminpassword123")
	wsURL := "ws" + server.URL[len("http"):] + "/api/live"
	headers := http.Header{"Cookie": []string{cookieHeader}}
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, headers)
	if err != nil {
		t.Fatalf("expected the dial to succeed with a valid session cookie, got: %v", err)
	}
	conn.Close()
}
