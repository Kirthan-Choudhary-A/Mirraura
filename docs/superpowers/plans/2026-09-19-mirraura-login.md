# Mirraura User Login (Part 2) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Put a login page in front of the whole app (no public sign-up, two
roles: admin/analyst), serve the frontend and API from one origin via
nginx, and record who did every consequential action in the audit log.

**Architecture:** Session-cookie auth in the Go backend (bcrypt-checked
passwords, random-token sessions held in memory, one middleware wrapping
every `/api/*` route except `/api/login` and `/api/health`). An nginx
reverse proxy replaces the frontend's `serve` and same-origin-proxies
`/api/` to the backend, which is what actually fixes the `VITE_BACKEND_URL`
bug (Part 1 deferred it here on purpose). The frontend adds one `user |
null` state switch — no router.

**Tech Stack:** Go stdlib `net/http`, `golang.org/x/crypto/bcrypt`
(new dependency), `crypto/rand` for tokens; nginx (`nginx:alpine`); React +
TypeScript (no new frontend dependency).

**Spec:** `docs/superpowers/specs/2026-09-18-mirraura-auth-redesign-design.md`
(Part 2 — User login)

## Global Constraints

- No "prototype"/"Day N" framing in code, comments, docs, or commit messages.
- Minimum code that works; follow this codebase's existing patterns — small
  single-purpose files (see `backend/hub.go`, `backend/hashes.go`), proxy
  handlers that pass a body straight through to the verdict engine, the
  `known_bad_label`-style short-circuit branch shape in `verdict-engine/app.py`.
- New dependency `golang.org/x/crypto/bcrypt` is explicitly authorized by
  the spec — this is the only new dependency this plan introduces. No new
  frontend npm dependency, no router library, no CSS/component framework
  (the spec's split-screen/wordmark login design belongs to **Part 3**, not
  this plan — Task 9 below builds a plain functional login form using the
  *existing* design tokens and classes in `frontend/src/index.css`, e.g.
  `.panel`, `.error-text`, `.run-button`, the bare `button`/`input`
  selectors. Do not attempt the Part 3 visual design here.).
- Cookie name is `mirraura_session` everywhere (backend sets it, tests
  assert it, docs reference it) — never a different name in different files.
- Session TTL is 8 hours, sliding on activity (each valid `Get` extends the
  expiry), not a fixed absolute expiry.
- Login rate limit is exactly 5 failed attempts per IP per 15 minutes → 429.
- The generic auth-failure message is exactly `"Invalid username or password"`
  for both an unknown username and a correct username with the wrong
  password — never anything that reveals which case occurred.
- Every new language/library/tool gets an entry in `docs/concepts.md` in
  the same change that introduces it — Task 10 covers `bcrypt`, the session
  model, nginx same-origin serving, and the sandbox/CORS items already
  documented in Part 1.
- This plan builds directly on top of Part 1's branch (`mirraura-bugfixes`,
  currently an open, unmerged PR) — every file this plan touches already
  reflects Part 1's changes (e.g. `backend/samples.go`'s `timedOut`
  parameter, `frontend/src/api.ts`'s `applyLiveEvent`/`connectLive`). Do not
  re-derive those changes or assume the pre-Part-1 file shapes.

---

### Task 1: User accounts (env-seeded admin + optional `users.json`) and a password-hashing helper

**Files:**
- Create: `backend/users.go`
- Create: `backend/users_test.go`
- Create: `backend/cmd/hashpw/main.go`
- Modify: `backend/go.mod`, `backend/go.sum` (via `go get`)

**Interfaces:**
- Produces:
  - `type User struct { Username string; PasswordHash string; Role string }`
  - `func loadUsers() (map[string]User, error)` — reads
    `MIRRAURA_ADMIN_USER`/`MIRRAURA_ADMIN_PASSWORD` from the environment
    (returns an error if either is empty, or if the password is shorter
    than 12 characters — defense in depth; `setup.sh`/Task 3's main.go
    check are the first line of defense, this is the second), bcrypt-hashes
    the password, and seeds the returned map with that one admin user.
    Then, if `MIRRAURA_USERS_PATH` is set AND the file at that path exists,
    parses it as a JSON array of `{"username": "...", "bcrypt_hash": "...",
    "role": "admin" | "analyst"}` and merges each entry in — a duplicate
    username (colliding with the env-seeded admin or another entry in the
    file) is an error. A `MIRRAURA_USERS_PATH` that is unset, or set but
    pointing at a file that doesn't exist, is not an error — the feature is
    optional, per its own name.

- [ ] **Step 1: Add the bcrypt dependency**

Run: `cd backend && go get golang.org/x/crypto/bcrypt && go mod tidy`
Expected: `go.mod` gains `golang.org/x/crypto` as a direct dependency;
`go.sum` updated accordingly.

- [ ] **Step 2: Write the failing tests**

Create `backend/users_test.go`:

```go
package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

func withEnv(t *testing.T, key, value string) {
	t.Helper()
	old, had := os.LookupEnv(key)
	os.Setenv(key, value)
	t.Cleanup(func() {
		if had {
			os.Setenv(key, old)
		} else {
			os.Unsetenv(key)
		}
	})
}

func TestLoadUsersSeedsAdminFromEnv(t *testing.T) {
	withEnv(t, "MIRRAURA_ADMIN_USER", "admin")
	withEnv(t, "MIRRAURA_ADMIN_PASSWORD", "correcthorsebatterystaple")
	withEnv(t, "MIRRAURA_USERS_PATH", "")

	users, err := loadUsers()
	if err != nil {
		t.Fatalf("loadUsers: %v", err)
	}
	admin, ok := users["admin"]
	if !ok {
		t.Fatal("expected admin user to be seeded")
	}
	if admin.Role != "admin" {
		t.Fatalf("expected role admin, got %q", admin.Role)
	}
	if err := bcrypt.CompareHashAndPassword([]byte(admin.PasswordHash), []byte("correcthorsebatterystaple")); err != nil {
		t.Fatalf("expected password hash to verify, got: %v", err)
	}
}

func TestLoadUsersRejectsShortPassword(t *testing.T) {
	withEnv(t, "MIRRAURA_ADMIN_USER", "admin")
	withEnv(t, "MIRRAURA_ADMIN_PASSWORD", "short")
	withEnv(t, "MIRRAURA_USERS_PATH", "")

	if _, err := loadUsers(); err == nil {
		t.Fatal("expected an error for a password shorter than 12 characters")
	}
}

func TestLoadUsersRejectsMissingAdminEnv(t *testing.T) {
	withEnv(t, "MIRRAURA_ADMIN_USER", "")
	withEnv(t, "MIRRAURA_ADMIN_PASSWORD", "")
	withEnv(t, "MIRRAURA_USERS_PATH", "")

	if _, err := loadUsers(); err == nil {
		t.Fatal("expected an error when admin env vars are unset")
	}
}

func TestLoadUsersMergesUsersJSON(t *testing.T) {
	withEnv(t, "MIRRAURA_ADMIN_USER", "admin")
	withEnv(t, "MIRRAURA_ADMIN_PASSWORD", "correcthorsebatterystaple")

	dir := t.TempDir()
	path := filepath.Join(dir, "users.json")
	hash, err := bcrypt.GenerateFromPassword([]byte("analystpassword123"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("GenerateFromPassword: %v", err)
	}
	entries := []map[string]string{
		{"username": "alice", "bcrypt_hash": string(hash), "role": "analyst"},
	}
	data, _ := json.Marshal(entries)
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	withEnv(t, "MIRRAURA_USERS_PATH", path)

	users, err := loadUsers()
	if err != nil {
		t.Fatalf("loadUsers: %v", err)
	}
	if len(users) != 2 {
		t.Fatalf("expected 2 users (admin + alice), got %d", len(users))
	}
	alice, ok := users["alice"]
	if !ok || alice.Role != "analyst" {
		t.Fatalf("expected alice with role analyst, got %+v (found=%v)", alice, ok)
	}
}

func TestLoadUsersMissingUsersFileIsNotAnError(t *testing.T) {
	withEnv(t, "MIRRAURA_ADMIN_USER", "admin")
	withEnv(t, "MIRRAURA_ADMIN_PASSWORD", "correcthorsebatterystaple")
	withEnv(t, "MIRRAURA_USERS_PATH", filepath.Join(t.TempDir(), "does-not-exist.json"))

	users, err := loadUsers()
	if err != nil {
		t.Fatalf("expected no error for a missing optional users file, got: %v", err)
	}
	if len(users) != 1 {
		t.Fatalf("expected only the admin user, got %d", len(users))
	}
}

func TestLoadUsersRejectsDuplicateUsername(t *testing.T) {
	withEnv(t, "MIRRAURA_ADMIN_USER", "admin")
	withEnv(t, "MIRRAURA_ADMIN_PASSWORD", "correcthorsebatterystaple")

	dir := t.TempDir()
	path := filepath.Join(dir, "users.json")
	hash, _ := bcrypt.GenerateFromPassword([]byte("whatever12345"), bcrypt.DefaultCost)
	entries := []map[string]string{
		{"username": "admin", "bcrypt_hash": string(hash), "role": "analyst"},
	}
	data, _ := json.Marshal(entries)
	os.WriteFile(path, data, 0644)
	withEnv(t, "MIRRAURA_USERS_PATH", path)

	if _, err := loadUsers(); err == nil {
		t.Fatal("expected an error for a users.json entry colliding with the env-seeded admin username")
	}
}
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `cd backend && go test ./... -run TestLoadUsers -v`
Expected: FAIL to compile — `loadUsers`/`User` don't exist yet.

- [ ] **Step 4: Implement `backend/users.go`**

```go
package main

import (
	"encoding/json"
	"fmt"
	"os"

	"golang.org/x/crypto/bcrypt"
)

type User struct {
	Username     string
	PasswordHash string
	Role         string
}

type userJSONEntry struct {
	Username   string `json:"username"`
	BcryptHash string `json:"bcrypt_hash"`
	Role       string `json:"role"`
}

func loadUsers() (map[string]User, error) {
	adminUser := os.Getenv("MIRRAURA_ADMIN_USER")
	adminPassword := os.Getenv("MIRRAURA_ADMIN_PASSWORD")
	if adminUser == "" || len(adminPassword) < 12 {
		return nil, fmt.Errorf("MIRRAURA_ADMIN_USER and MIRRAURA_ADMIN_PASSWORD (12+ chars) must both be set")
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(adminPassword), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("hash admin password: %w", err)
	}

	users := map[string]User{
		adminUser: {Username: adminUser, PasswordHash: string(hash), Role: "admin"},
	}

	usersPath := os.Getenv("MIRRAURA_USERS_PATH")
	if usersPath == "" {
		return users, nil
	}
	data, err := os.ReadFile(usersPath)
	if os.IsNotExist(err) {
		return users, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", usersPath, err)
	}
	var entries []userJSONEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		return nil, fmt.Errorf("parse %s: %w", usersPath, err)
	}
	for _, e := range entries {
		if e.Role != "admin" && e.Role != "analyst" {
			return nil, fmt.Errorf("%s: user %q has invalid role %q (must be admin or analyst)", usersPath, e.Username, e.Role)
		}
		if _, exists := users[e.Username]; exists {
			return nil, fmt.Errorf("%s: duplicate username %q", usersPath, e.Username)
		}
		users[e.Username] = User{Username: e.Username, PasswordHash: e.BcryptHash, Role: e.Role}
	}
	return users, nil
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd backend && go test ./... -run TestLoadUsers -v`
Expected: PASS.

- [ ] **Step 6: Add the `cmd/hashpw` helper**

Create `backend/cmd/hashpw/main.go`:

```go
// hashpw prints a bcrypt hash for a password, for use in a users.json entry.
//
// Usage: go run ./cmd/hashpw <password>
// or, to avoid the password appearing in shell history:
//
//	echo -n 'the password' | go run ./cmd/hashpw
package main

import (
	"bufio"
	"fmt"
	"os"

	"golang.org/x/crypto/bcrypt"
)

func main() {
	var password string
	if len(os.Args) > 1 {
		password = os.Args[1]
	} else {
		scanner := bufio.NewScanner(os.Stdin)
		if !scanner.Scan() {
			fmt.Fprintln(os.Stderr, "usage: go run ./cmd/hashpw <password>  (or pipe the password on stdin)")
			os.Exit(1)
		}
		password = scanner.Text()
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		fmt.Fprintln(os.Stderr, "hash:", err)
		os.Exit(1)
	}
	fmt.Println(string(hash))
}
```

- [ ] **Step 7: Verify it builds and run the full backend suite**

Run: `cd backend && go build ./... && go vet ./... && go test ./...`
Expected: PASS. Manually sanity-check the helper:
`cd backend && go run ./cmd/hashpw testpassword123` prints a `$2a$...` hash.

- [ ] **Step 8: Commit**

```bash
git add backend/users.go backend/users_test.go backend/cmd/hashpw/main.go backend/go.mod backend/go.sum
git commit -m "feat: seed admin user from env, optional users.json, hashpw helper"
```

---

### Task 2: Session store and login rate limiter

**Files:**
- Create: `backend/session.go`
- Create: `backend/session_test.go`
- Create: `backend/ratelimit.go`
- Create: `backend/ratelimit_test.go`

**Interfaces:**
- Consumes: nothing from Task 1.
- Produces:
  - `type Session struct { Username string; Role string }`
  - `func NewSessionStore() *SessionStore`
  - `func (s *SessionStore) Create(username, role string) string` — returns
    a 32-byte, hex-encoded, `crypto/rand`-sourced token.
  - `func (s *SessionStore) Get(token string) (Session, bool)` — sliding
    8-hour expiry: a hit extends the session's expiry from now; an expired
    or unknown token returns `(Session{}, false)` and evicts the entry.
  - `func (s *SessionStore) Delete(token string)`
  - `func NewLoginLimiter() *LoginLimiter`
  - `func (l *LoginLimiter) Allow(ip string) bool` — false once 5 failures
    for that IP have landed within the last 15 minutes.
  - `func (l *LoginLimiter) RecordFailure(ip string)`

- [ ] **Step 1: Write the failing session-store tests**

Create `backend/session_test.go`:

```go
package main

import (
	"testing"
	"time"
)

func TestSessionStoreCreateAndGet(t *testing.T) {
	store := NewSessionStore()
	token := store.Create("alice", "analyst")
	if token == "" {
		t.Fatal("expected a non-empty token")
	}
	sess, ok := store.Get(token)
	if !ok {
		t.Fatal("expected the created session to be found")
	}
	if sess.Username != "alice" || sess.Role != "analyst" {
		t.Fatalf("unexpected session: %+v", sess)
	}
}

func TestSessionStoreGetUnknownTokenFails(t *testing.T) {
	store := NewSessionStore()
	if _, ok := store.Get("does-not-exist"); ok {
		t.Fatal("expected an unknown token to not be found")
	}
}

func TestSessionStoreDelete(t *testing.T) {
	store := NewSessionStore()
	token := store.Create("alice", "analyst")
	store.Delete(token)
	if _, ok := store.Get(token); ok {
		t.Fatal("expected the deleted session to no longer be found")
	}
}

func TestSessionStoreExpiresAfterTTL(t *testing.T) {
	store := NewSessionStore()
	token := store.Create("alice", "analyst")
	// Reach into the store to simulate 8+ hours of inactivity, rather than
	// sleeping in the test.
	store.mu.Lock()
	entry := store.sessions[token]
	entry.expiresAt = time.Now().Add(-time.Second)
	store.sessions[token] = entry
	store.mu.Unlock()

	if _, ok := store.Get(token); ok {
		t.Fatal("expected an expired session to not be found")
	}
}

func TestSessionStoreSlidesExpiryOnGet(t *testing.T) {
	store := NewSessionStore()
	token := store.Create("alice", "analyst")
	store.mu.Lock()
	entry := store.sessions[token]
	nearExpiry := time.Now().Add(time.Second)
	entry.expiresAt = nearExpiry
	store.sessions[token] = entry
	store.mu.Unlock()

	if _, ok := store.Get(token); !ok {
		t.Fatal("expected the session to still be valid just before its near-term expiry")
	}
	store.mu.Lock()
	slid := store.sessions[token].expiresAt
	store.mu.Unlock()
	if !slid.After(nearExpiry) {
		t.Fatal("expected Get to slide the expiry forward")
	}
}

func TestSessionStoreTokensAreUnique(t *testing.T) {
	store := NewSessionStore()
	a := store.Create("alice", "analyst")
	b := store.Create("alice", "analyst")
	if a == b {
		t.Fatal("expected two calls to Create to produce different tokens")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd backend && go test ./... -run TestSessionStore -v`
Expected: FAIL to compile — `SessionStore` doesn't exist yet.

- [ ] **Step 3: Implement `backend/session.go`**

```go
package main

import (
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"
)

type Session struct {
	Username string
	Role     string
}

type sessionEntry struct {
	Session
	expiresAt time.Time
}

const sessionTTL = 8 * time.Hour

// SessionStore is an in-memory session table: sessions are lost on backend
// restart. That's an accepted tradeoff for a single-instance deployment.
// ponytail: move to a shared store (e.g. Redis) if the backend ever runs
// as more than one instance.
type SessionStore struct {
	mu       sync.Mutex
	sessions map[string]sessionEntry
}

func NewSessionStore() *SessionStore {
	return &SessionStore{sessions: make(map[string]sessionEntry)}
}

func (s *SessionStore) Create(username, role string) string {
	b := make([]byte, 32)
	rand.Read(b)
	token := hex.EncodeToString(b)

	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[token] = sessionEntry{
		Session:   Session{Username: username, Role: role},
		expiresAt: time.Now().Add(sessionTTL),
	}
	return token
}

func (s *SessionStore) Get(token string) (Session, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, ok := s.sessions[token]
	if !ok {
		return Session{}, false
	}
	if time.Now().After(entry.expiresAt) {
		delete(s.sessions, token)
		return Session{}, false
	}
	entry.expiresAt = time.Now().Add(sessionTTL)
	s.sessions[token] = entry
	return entry.Session, true
}

func (s *SessionStore) Delete(token string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, token)
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd backend && go test ./... -run TestSessionStore -v`
Expected: PASS.

- [ ] **Step 5: Write the failing rate-limiter tests**

Create `backend/ratelimit_test.go`:

```go
package main

import "testing"

func TestLoginLimiterAllowsUnderThreshold(t *testing.T) {
	l := NewLoginLimiter()
	for i := 0; i < 4; i++ {
		if !l.Allow("1.2.3.4") {
			t.Fatalf("expected Allow to be true on attempt %d", i+1)
		}
		l.RecordFailure("1.2.3.4")
	}
}

func TestLoginLimiterBlocksAfterFiveFailures(t *testing.T) {
	l := NewLoginLimiter()
	for i := 0; i < 5; i++ {
		l.RecordFailure("1.2.3.4")
	}
	if l.Allow("1.2.3.4") {
		t.Fatal("expected Allow to be false after 5 failures")
	}
}

func TestLoginLimiterIsPerIP(t *testing.T) {
	l := NewLoginLimiter()
	for i := 0; i < 5; i++ {
		l.RecordFailure("1.2.3.4")
	}
	if !l.Allow("5.6.7.8") {
		t.Fatal("expected a different IP to be unaffected by another IP's failures")
	}
}
```

- [ ] **Step 6: Run tests to verify they fail**

Run: `cd backend && go test ./... -run TestLoginLimiter -v`
Expected: FAIL to compile — `LoginLimiter` doesn't exist yet.

- [ ] **Step 7: Implement `backend/ratelimit.go`**

```go
package main

import (
	"sync"
	"time"
)

const (
	loginMaxFailures = 5
	loginWindow      = 15 * time.Minute
)

// LoginLimiter tracks failed login attempts per IP in memory. ponytail:
// like SessionStore, this resets on restart and doesn't share state across
// instances — fine for a single-instance deployment.
type LoginLimiter struct {
	mu       sync.Mutex
	failures map[string][]time.Time
}

func NewLoginLimiter() *LoginLimiter {
	return &LoginLimiter{failures: make(map[string][]time.Time)}
}

func (l *LoginLimiter) Allow(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.recentFailuresLocked(ip)) < loginMaxFailures
}

func (l *LoginLimiter) RecordFailure(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	recent := l.recentFailuresLocked(ip)
	l.failures[ip] = append(recent, time.Now())
}

// recentFailuresLocked prunes and returns failures within the window for
// ip. Caller must hold l.mu.
func (l *LoginLimiter) recentFailuresLocked(ip string) []time.Time {
	cutoff := time.Now().Add(-loginWindow)
	var kept []time.Time
	for _, t := range l.failures[ip] {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	l.failures[ip] = kept
	return kept
}
```

- [ ] **Step 8: Run tests to verify they pass**

Run: `cd backend && go test ./... -run TestLoginLimiter -v`
Expected: PASS.

- [ ] **Step 9: Run the full backend suite**

Run: `cd backend && go build ./... && go vet ./... && go test ./...`
Expected: PASS.

- [ ] **Step 10: Commit**

```bash
git add backend/session.go backend/session_test.go backend/ratelimit.go backend/ratelimit_test.go
git commit -m "feat: in-memory session store and login rate limiter"
```

---

### Task 3: Auth middleware, login/logout/me handlers, and wiring into `main.go`

**Files:**
- Create: `backend/auth_handlers.go`
- Create: `backend/auth_handlers_test.go`
- Modify: `backend/main.go` (extract `newMux`, add startup validation, wire auth)
- Modify: `backend/main_test.go` (exercise `newMux` for the auth-specific cases the spec requires)

**Interfaces:**
- Consumes: `User`, `loadUsers()` (Task 1); `Session`, `SessionStore`,
  `LoginLimiter` (Task 2).
- Produces:
  - `func requireAuth(store *SessionStore) func(http.Handler) http.Handler`
  - `func requireRole(role string) func(http.Handler) http.Handler` — must
    run downstream of `requireAuth` (reads the session `requireAuth` put in
    context); 403 if the session's role doesn't match.
  - `func sessionFromContext(ctx context.Context) (Session, bool)`
  - `func loginHandler(store *SessionStore, users map[string]User, limiter *LoginLimiter) http.HandlerFunc`
  - `func logoutHandler(store *SessionStore) http.HandlerFunc`
  - `func meHandler() http.HandlerFunc`
  - `func clientIP(r *http.Request) string` — checks `X-Forwarded-For`
    first (set by Task 7's nginx proxy), falls back to `r.RemoteAddr`'s host.
  - `func newMux(dm *DockerManager, verdictEngineURL string, hub *Hub, mon *Monitor, store *SessionStore, users map[string]User, limiter *LoginLimiter) *http.ServeMux`
    — extracted from `main()` so it's directly testable; `main()` becomes a
    thin wrapper that builds the dependencies and calls this.

- [ ] **Step 1: Write the failing tests**

Create `backend/auth_handlers_test.go`:

```go
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

	"golang.org/x/crypto/bcrypt"
	"github.com/gorilla/websocket"
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd backend && go test ./... -run 'TestLogin|TestMiddleware|TestHealthAndLogin|TestAnalyst|TestAdminCan|TestWebSocket' -v`
Expected: FAIL to compile — `newMux`, `loginHandler`, etc. don't exist yet.

- [ ] **Step 3: Implement `backend/auth_handlers.go`**

```go
package main

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

type ctxKey int

const sessionCtxKey ctxKey = 0

const sessionCookieName = "mirraura_session"

func sessionFromContext(ctx context.Context) (Session, bool) {
	sess, ok := ctx.Value(sessionCtxKey).(Session)
	return sess, ok
}

func clientIP(r *http.Request) string {
	if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
		parts := strings.Split(fwd, ",")
		return strings.TrimSpace(parts[0])
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func requireAuth(store *SessionStore) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			cookie, err := r.Cookie(sessionCookieName)
			if err != nil {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			sess, ok := store.Get(cookie.Value)
			if !ok {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			ctx := context.WithValue(r.Context(), sessionCtxKey, sess)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func requireRole(role string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			sess, ok := sessionFromContext(r.Context())
			if !ok || sess.Role != role {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func loginHandler(store *SessionStore, users map[string]User, limiter *LoginLimiter) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		ip := clientIP(r)
		if !limiter.Allow(ip) {
			http.Error(w, "too many failed login attempts, try again later", http.StatusTooManyRequests)
			return
		}

		var req loginRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return
		}

		user, ok := users[req.Username]
		if !ok || bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password)) != nil {
			limiter.RecordFailure(ip)
			http.Error(w, "Invalid username or password", http.StatusUnauthorized)
			return
		}

		token := store.Create(user.Username, user.Role)
		http.SetCookie(w, &http.Cookie{
			Name:     sessionCookieName,
			Value:    token,
			Path:     "/",
			HttpOnly: true,
			SameSite: http.SameSiteStrictMode,
			Secure:   r.TLS != nil,
		})
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"username": user.Username, "role": user.Role})
	}
}

func logoutHandler(store *SessionStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if cookie, err := r.Cookie(sessionCookieName); err == nil {
			store.Delete(cookie.Value)
		}
		http.SetCookie(w, &http.Cookie{
			Name:     sessionCookieName,
			Value:    "",
			Path:     "/",
			HttpOnly: true,
			SameSite: http.SameSiteStrictMode,
			Secure:   r.TLS != nil,
			MaxAge:   -1,
		})
		w.WriteHeader(http.StatusNoContent)
	}
}

func meHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess, _ := sessionFromContext(r.Context())
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"username": sess.Username, "role": sess.Role})
	}
}
```

- [ ] **Step 4: Extract `newMux` and wire auth into `backend/main.go`**

Replace the body of `main.go` from the `mux := http.NewServeMux()` line
through the `mux.HandleFunc("/api/hashes/", ...)` line with a call to a new
`newMux` function, and add startup validation. The full new `main.go`:

```go
package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"time"
)

func main() {
	if len(os.Getenv("MIRRAURA_ADMIN_PASSWORD")) < 12 {
		log.Fatal("MIRRAURA_ADMIN_PASSWORD must be set and at least 12 characters")
	}
	users, err := loadUsers()
	if err != nil {
		log.Fatalf("loadUsers: %v", err)
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
	initCtx, initCancel := context.WithTimeout(context.Background(), 10*time.Second)
	mon.InitIsolatedState(initCtx)
	initCancel()

	store := NewSessionStore()
	limiter := NewLoginLimiter()
	mux := newMux(dm, verdictEngineURL, hub, mon, store, users, limiter)

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

	port := os.Getenv("BACKEND_PORT")
	if port == "" {
		port = "8080"
	}
	log.Printf("backend listening on :%s", port)
	if err := http.ListenAndServe(":"+port, mux); err != nil {
		log.Fatal(err)
	}
}

func newMux(dm *DockerManager, verdictEngineURL string, hub *Hub, mon *Monitor, store *SessionStore, users map[string]User, limiter *LoginLimiter) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/health", healthHandler)
	mux.HandleFunc("/api/login", loginHandler(store, users, limiter))
	mux.Handle("/api/logout", requireAuth(store)(logoutHandler(store)))
	mux.Handle("/api/me", requireAuth(store)(meHandler()))
	mux.Handle("/api/samples", requireAuth(store)(samplesHandler(dm, verdictEngineURL, hub)))
	mux.Handle("/api/verdicts", requireAuth(store)(verdictsListHandler(verdictEngineURL)))
	mux.Handle("/api/verdicts/", requireAuth(store)(verdictDetailHandler(verdictEngineURL)))
	mux.Handle("/api/live", requireAuth(store)(http.HandlerFunc(hub.HandleWS)))
	mux.Handle("/api/monitor/status", requireAuth(store)(monitorStatusHandler(mon)))
	mux.Handle("/api/monitor/reconnect", requireAuth(store)(requireRole("admin")(monitorReconnectHandler(mon))))
	mux.Handle("/api/hashes", requireAuth(store)(hashesHandler(verdictEngineURL)))
	mux.Handle("/api/hashes/", requireAuth(store)(requireRole("admin")(hashDecisionHandler(verdictEngineURL))))
	return mux
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}
```

Note `dm *DockerManager` in `newMux`'s signature: `samplesHandler` takes a
concrete `*DockerManager`, so tests that build a `newMux` without a real
Docker daemon (all the ones in Step 1 above) pass `nil` for `dm` — that's
fine, since none of those tests exercise `/api/samples`, and Go allows a
nil pointer receiver to be passed around freely as long as it's never
dereferenced.

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd backend && go test ./... -v 2>&1 | tail -80`
Expected: PASS — all of Step 1's new tests, plus every pre-existing test
(`healthHandler` is still directly testable exactly as
`backend/main_test.go` already does, since it's an ordinary
`http.HandlerFunc` unchanged by this task).

- [ ] **Step 6: Run the full backend suite**

Run: `cd backend && go build ./... && go vet ./... && go test ./...`
Expected: PASS (aside from the two pre-existing Docker-daemon-dependent
tests if no daemon is available in this environment).

- [ ] **Step 7: Commit**

```bash
git add backend/auth_handlers.go backend/auth_handlers_test.go backend/main.go
git commit -m "feat: session-cookie auth middleware, login/logout/me routes, role gating"
```

---

### Task 4: Record who uploaded a sample

**Files:**
- Modify: `backend/samples.go`
- Modify: `backend/samples_test.go`
- Modify: `backend/monitor.go` (the one other `scoreWithVerdictEngine` call site)
- Modify: `verdict-engine/app.py`
- Modify: `verdict-engine/tests/test_app.py`

**Interfaces:**
- Consumes: `sessionFromContext` (Task 3), the current
  `scoreWithVerdictEngine(baseURL, sampleHash, sampleFilename, source
  string, timedOut bool, events []json.RawMessage) (*Verdict, error)`.
- Produces: `scoreWithVerdictEngine(baseURL, sampleHash, sampleFilename,
  source, actor string, timedOut bool, events []json.RawMessage) (*Verdict,
  error)` — `actor` inserted as the 5th parameter (Go groups the leading
  string params together: `baseURL, sampleHash, sampleFilename, source,
  actor string`). Every call site must move to this new signature.

- [ ] **Step 1: Write the failing test**

In `backend/samples_test.go`, add:

```go
func TestScoreWithVerdictEngineSendsActor(t *testing.T) {
	var gotBody map[string]any
	fakeEngine := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&gotBody)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(Verdict{VerdictID: "v1", Verdict: "Normal"})
	}))
	defer fakeEngine.Close()

	_, err := scoreWithVerdictEngine(fakeEngine.URL, "somehash", "file.bin", "sample", "alice", false, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gotBody["actor"] != "alice" {
		t.Fatalf("expected actor=alice in request body, got %v", gotBody["actor"])
	}
}
```

Update the two existing calls in the same file to match the new signature
(insert `"file.bin"`'s neighbor — the actor arg — right after `source`):

```go
	v, err := scoreWithVerdictEngine(fakeEngine.URL, "somehash", "file.bin", "sample", "", false, nil)
```

and

```go
	_, err := scoreWithVerdictEngine(fakeEngine.URL, "somehash", "file.bin", "sample", "", true, nil)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd backend && go test ./... -run TestScoreWithVerdictEngine -v`
Expected: FAIL to compile.

- [ ] **Step 3: Update `scoreWithVerdictEngine` and its callers**

In `backend/samples.go`, change:

```go
func scoreWithVerdictEngine(baseURL, sampleHash, sampleFilename, source string, timedOut bool, events []json.RawMessage) (*Verdict, error) {
	body, err := json.Marshal(map[string]any{
		"sample_hash":     sampleHash,
		"sample_filename": sampleFilename,
		"timed_out":       timedOut,
		"events":          events,
		"source":          source,
	})
```

to:

```go
func scoreWithVerdictEngine(baseURL, sampleHash, sampleFilename, source, actor string, timedOut bool, events []json.RawMessage) (*Verdict, error) {
	body, err := json.Marshal(map[string]any{
		"sample_hash":     sampleHash,
		"sample_filename": sampleFilename,
		"timed_out":       timedOut,
		"events":          events,
		"source":          source,
		"actor":           actor,
	})
```

In `samplesHandler`, read the actor from the request's session and pass it
through. Change:

```go
		verdict, err := scoreWithVerdictEngine(verdictEngineURL, sampleHash, safeFilename, "sample", timedOut, events)
```

to:

```go
		actor, _ := sessionFromContext(r.Context())
		verdict, err := scoreWithVerdictEngine(verdictEngineURL, sampleHash, safeFilename, "sample", actor.Username, timedOut, events)
```

In `backend/monitor.go`, the continuous-monitoring path has no human actor.
Change:

```go
	verdict, err := scoreWithVerdictEngine(mon.verdictEngineURL, batchHash, "", "monitor", false, events)
```

to:

```go
	verdict, err := scoreWithVerdictEngine(mon.verdictEngineURL, batchHash, "", "monitor", "", false, events)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd backend && go test ./... -run TestScoreWithVerdictEngine -v`
Expected: PASS.

- [ ] **Step 5: Thread `actor` through the verdict engine**

In `verdict-engine/app.py`, add `actor: str = ""` to `ScoreRequest`:

```python
class ScoreRequest(BaseModel):
    sample_hash: str
    sample_filename: str = ""
    timed_out: bool = False
    actor: str = ""
    events: List[Event] = []
    source: str = "sample"
```

Add `"actor": req.actor,` to the `record` dict built in `score()`:

```python
    record = {
        "verdict_id": verdict_id,
        "sample_hash": req.sample_hash,
        "sample_filename": req.sample_filename,
        "actor": req.actor,
        "verdict": verdict,
        "confidence": confidence,
        "causal_chain": chain,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
```

- [ ] **Step 6: Write and run the pytest test**

Add to `verdict-engine/tests/test_app.py`:

```python
def test_score_records_actor_in_audit_log():
    resp = client.post(
        "/score",
        json={"sample_hash": "9" * 64, "events": [], "actor": "alice"},
    )
    assert resp.status_code == 200
    assert resp.json()["actor"] == "alice"
```

Run: `cd verdict-engine && python -m pytest tests/test_app.py -k actor -v`
Expected: PASS.

- [ ] **Step 7: Run both full suites**

Run: `cd backend && go build ./... && go test ./...`
Run: `cd verdict-engine && python -m pytest tests/ -q`
Expected: PASS.

- [ ] **Step 8: Commit**

```bash
git add backend/samples.go backend/samples_test.go backend/monitor.go verdict-engine/app.py verdict-engine/tests/test_app.py
git commit -m "feat: record the uploading user as actor on every sample verdict"
```

---

### Task 5: Record who approved or rejected a hash

**Files:**
- Modify: `backend/hashes.go`
- Modify: `backend/hashes_test.go`
- Modify: `verdict-engine/app.py`
- Modify: `verdict-engine/tests/test_app.py`

**Interfaces:**
- Consumes: `sessionFromContext` (Task 3). `hashDecisionHandler`'s existing
  signature `func(verdictEngineURL string) http.HandlerFunc` is unchanged —
  it reads the actor from the request it already receives, no new
  parameter needed.
- Produces: the backend now POSTs a JSON body `{"actor": "..."}` to
  `/hashes/{hash}/approve` and `/hashes/{hash}/reject` instead of a nil
  body; `verdict-engine`'s `ActionRequest`-style handling for these two
  routes gains an `actor` field recorded in the `hash_approved`/
  `hash_rejected` audit entries.

- [ ] **Step 1: Write the failing Go test**

In `backend/hashes_test.go`, replace `TestHashDecisionHandlerProxiesApprove`
with a version that asserts the actor is forwarded, and add a context to
the request the same way `requireAuth` would:

```go
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
```

Add `"context"` and `"encoding/json"` to the file's imports if not already
present (check the existing import block first — `"encoding/json"` is
likely new to this file, `"context"` definitely is).

- [ ] **Step 2: Run test to verify it fails**

Run: `cd backend && go test ./... -run TestHashDecisionHandlerProxiesApproveWithActor -v`
Expected: FAIL — the current handler sends a nil body, so `gotBody["actor"]`
is nil, not `"alice"`.

- [ ] **Step 3: Implement in `backend/hashes.go`**

Change `hashDecisionHandler`:

```go
func hashDecisionHandler(verdictEngineURL string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		path := strings.TrimPrefix(r.URL.Path, "/api/hashes/")
		parts := strings.Split(path, "/")
		if len(parts) != 2 || (parts[1] != "approve" && parts[1] != "reject") {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		hash, decision := parts[0], parts[1]
		actor, _ := sessionFromContext(r.Context())
		body, err := json.Marshal(map[string]string{"actor": actor.Username})
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		resp, err := httpClient.Post(verdictEngineURL+"/hashes/"+hash+"/"+decision, "application/json", bytes.NewReader(body))
		if err != nil {
			http.Error(w, "verdict-engine unreachable", http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(resp.StatusCode)
		io.Copy(w, resp.Body)
	}
}
```

Add `"bytes"` and `"encoding/json"` to `backend/hashes.go`'s import block
(currently just `"io"`, `"net/http"`, `"strings"`).

Note `TestHashDecisionHandlerRejectsBadPath` (existing test, unchanged)
still calls `hashDecisionHandler("http://unused")(rec, req)` with a plain
`httptest.NewRequest` carrying no session in its context — `sessionFromContext`
returns `(Session{}, false)` in that case, `actor.Username` is `""`, which
is fine since that test only exercises the bad-path 404 branch before actor
is even used.

- [ ] **Step 4: Run test to verify it passes**

Run: `cd backend && go test ./... -run TestHashDecisionHandler -v`
Expected: PASS.

- [ ] **Step 5: Thread `actor` through the verdict engine's approve/reject routes**

In `verdict-engine/app.py`, add a small request model and use it on both
routes:

```python
class HashDecisionRequest(BaseModel):
    actor: str = ""
```

Change:

```python
@app.post("/hashes/{hash}/approve")
def approve_hash_route(hash: str):
    try:
        entry = approve_hash(hash)
    except HashNotFoundError:
        raise HTTPException(status_code=404, detail="hash not found")
    except HashNotPendingError:
        raise HTTPException(status_code=409, detail="hash is not pending")
    audit_log.append(
        {
            "record_id": str(uuid.uuid4()),
            "action": "hash_approved",
            "hash": entry["hash"],
            "label": entry["label"],
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
    )
    return entry
```

to:

```python
@app.post("/hashes/{hash}/approve")
def approve_hash_route(hash: str, req: HashDecisionRequest):
    try:
        entry = approve_hash(hash)
    except HashNotFoundError:
        raise HTTPException(status_code=404, detail="hash not found")
    except HashNotPendingError:
        raise HTTPException(status_code=409, detail="hash is not pending")
    audit_log.append(
        {
            "record_id": str(uuid.uuid4()),
            "action": "hash_approved",
            "hash": entry["hash"],
            "label": entry["label"],
            "actor": req.actor,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
    )
    return entry
```

Apply the identical pattern (`req: HashDecisionRequest` parameter,
`"actor": req.actor` in the audit entry) to `reject_hash_route`, changing
`"action": "hash_rejected"`'s block the same way.

- [ ] **Step 6: Update the existing pytest tests that call these routes**

`verdict-engine/tests/test_app.py` has tests posting to
`/hashes/{hash}/approve` and `/hashes/{hash}/reject` with no body (e.g.
around the existing `test_approve_hash_...`/`test_reject_hash_...` tests —
search for `f"/hashes/{sample_hash}/approve"` and the reject equivalent).
FastAPI will now require a JSON body for these routes since
`HashDecisionRequest` has no fields without a default that would make the
body itself optional — but since `actor: str = ""` has a default, an
**empty JSON object `{}`** body is enough to satisfy validation; a
genuinely absent body is not. Update each such `client.post(...)` call to
include `json={}"` (or `json={"actor": "..."}` where you want to assert the
actor is recorded — see the new test below) so existing tests keep passing.

Add one new test modeled on the existing approve/reject tests:

```python
def test_approve_hash_records_actor():
    sample_hash = "e" * 64
    client.post("/hashes", json={"hash": sample_hash, "label": "actor-test"})
    resp = client.post(f"/hashes/{sample_hash}/approve", json={"actor": "alice"})
    assert resp.status_code == 200
    listed = client.get("/verdicts").json()
    match = next(r for r in listed if r.get("action") == "hash_approved" and r.get("hash") == sample_hash)
    assert match["actor"] == "alice"
```

- [ ] **Step 7: Run the full verdict-engine suite**

Run: `cd verdict-engine && python -m pytest tests/ -q`
Expected: PASS.

- [ ] **Step 8: Run the full backend suite**

Run: `cd backend && go build ./... && go test ./...`
Expected: PASS.

- [ ] **Step 9: Commit**

```bash
git add backend/hashes.go backend/hashes_test.go verdict-engine/app.py verdict-engine/tests/test_app.py
git commit -m "feat: record who approved or rejected a hash"
```

---

### Task 6: Record who reconnected an isolated endpoint; restrict reconnect to admins

**Files:**
- Modify: `backend/monitor.go`
- Modify: `backend/monitor_test.go`
- Modify: `backend/monitor_handlers.go`
- Modify: `verdict-engine/app.py`
- Modify: `verdict-engine/tests/test_app.py`

**Interfaces:**
- Consumes: `sessionFromContext` (Task 3).
- Produces: `func (mon *Monitor) Reconnect(ctx context.Context, actor
  string) error` — `actor` added as a new parameter; `func logAction(baseURL,
  action, deviceID, actor string) error` — same.

- [ ] **Step 1: Update the failing Go tests**

`backend/monitor_test.go` has three tests calling `mon.Reconnect(...)`:
`TestReconnectFailsWhenNotIsolated`, `TestReconnectClearsIsolatedFlag`, and
implicitly nothing else. Update both call sites to pass an actor:

```go
	if err := mon.Reconnect(context.Background(), "alice"); err != errNotIsolated {
```

and

```go
	if err := mon.Reconnect(context.Background(), "alice"); err != nil {
		t.Fatalf("Reconnect: %v", err)
	}
```

Add a new test asserting the actor reaches the verdict engine:

```go
func TestReconnectSendsActorToAuditLog(t *testing.T) {
	fd := &fakeMonitorDocker{pollLines: []string{`{"event_type":"process_spawn"}`}}
	var gotActor string
	engine := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/audit/action" {
			var body map[string]string
			json.NewDecoder(r.Body).Decode(&body)
			gotActor = body["actor"]
			w.Write([]byte(`{}`))
			return
		}
		json.NewEncoder(w).Encode(Verdict{VerdictID: "v1", Verdict: "Compromised", Confidence: 1.0})
	}))
	defer engine.Close()

	mon := NewMonitor(fd, engine.URL, &fakeBroadcaster{})
	if err := mon.Tick(context.Background()); err != nil {
		t.Fatalf("Tick: %v", err)
	}
	if err := mon.Reconnect(context.Background(), "alice"); err != nil {
		t.Fatalf("Reconnect: %v", err)
	}
	if gotActor != "alice" {
		t.Fatalf("expected actor=alice recorded on reconnect, got %q", gotActor)
	}
}
```

Add `"net/http"` and `"net/http/httptest"` to the file's imports if not
already present (check first — `httptest` is likely already imported for
`fakeVerdictEngine`).

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd backend && go test ./... -run TestReconnect -v`
Expected: FAIL to compile.

- [ ] **Step 3: Implement in `backend/monitor.go`**

Change:

```go
func (mon *Monitor) Reconnect(ctx context.Context) error {
	mon.mu.Lock()
	if !mon.isolated {
		mon.mu.Unlock()
		return errNotIsolated
	}
	mon.mu.Unlock()

	if err := mon.dm.ReconnectContainer(ctx, monitorNetworkName, monitorContainerName); err != nil {
		return err
	}
	mon.mu.Lock()
	mon.isolated = false
	mon.mu.Unlock()
	mon.hub.Broadcast(map[string]any{"type": "reconnected"})
	if err := logAction(mon.verdictEngineURL, "reconnected", monitorDeviceID); err != nil {
		log.Printf("monitor: failed to audit-log reconnect action: %v", err)
	}
	return nil
}

func logAction(baseURL, action, deviceID string) error {
	body, err := json.Marshal(map[string]string{"action": action, "device_id": deviceID})
```

to:

```go
func (mon *Monitor) Reconnect(ctx context.Context, actor string) error {
	mon.mu.Lock()
	if !mon.isolated {
		mon.mu.Unlock()
		return errNotIsolated
	}
	mon.mu.Unlock()

	if err := mon.dm.ReconnectContainer(ctx, monitorNetworkName, monitorContainerName); err != nil {
		return err
	}
	mon.mu.Lock()
	mon.isolated = false
	mon.mu.Unlock()
	mon.hub.Broadcast(map[string]any{"type": "reconnected"})
	if err := logAction(mon.verdictEngineURL, "reconnected", monitorDeviceID, actor); err != nil {
		log.Printf("monitor: failed to audit-log reconnect action: %v", err)
	}
	return nil
}

func logAction(baseURL, action, deviceID, actor string) error {
	body, err := json.Marshal(map[string]string{"action": action, "device_id": deviceID, "actor": actor})
```

The other `logAction` call site (the auto-isolate branch inside `Tick`) is
system-triggered, not a human action — update it to pass an empty actor:

```go
	if err := logAction(mon.verdictEngineURL, "isolated", monitorDeviceID, ""); err != nil {
```

- [ ] **Step 4: Update `monitor_handlers.go` to require admin and pass the actor**

Read the current `monitorReconnectHandler` in `backend/monitor_handlers.go`
first (Task 3 already wraps its registration with `requireRole("admin")` in
`newMux`, so the role check is already enforced at the routing layer — this
step only needs the handler itself to read the actor and pass it through).
Change:

```go
		if err := mon.Reconnect(r.Context()); err != nil {
```

to:

```go
		actor, _ := sessionFromContext(r.Context())
		if err := mon.Reconnect(r.Context(), actor.Username); err != nil {
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd backend && go test ./... -run TestReconnect -v`
Expected: PASS.

- [ ] **Step 6: Thread `actor` through the verdict engine's `/audit/action`**

In `verdict-engine/app.py`, add `actor: str = ""` to `ActionRequest`:

```python
class ActionRequest(BaseModel):
    action: str
    device_id: str
    actor: str = ""
```

Add `"actor": req.actor,` to the record built in `log_action`:

```python
@app.post("/audit/action")
def log_action(req: ActionRequest):
    record = {
        "record_id": str(uuid.uuid4()),
        "device_id": req.device_id,
        "action": req.action,
        "actor": req.actor,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    return _strip_entry_hash(audit_log.append(record))
```

- [ ] **Step 7: Add a pytest test**

Add to `verdict-engine/tests/test_app.py`:

```python
def test_log_action_records_actor():
    resp = client.post(
        "/audit/action",
        json={"action": "reconnected", "device_id": "monitored-endpoint", "actor": "alice"},
    )
    assert resp.status_code == 200
    assert resp.json()["actor"] == "alice"
```

Run: `cd verdict-engine && python -m pytest tests/test_app.py -k log_action -v`
Expected: PASS.

- [ ] **Step 8: Run both full suites**

Run: `cd backend && go build ./... && go test ./...`
Run: `cd verdict-engine && python -m pytest tests/ -q`
Expected: PASS.

- [ ] **Step 9: Commit**

```bash
git add backend/monitor.go backend/monitor_test.go backend/monitor_handlers.go verdict-engine/app.py verdict-engine/tests/test_app.py
git commit -m "feat: record who reconnected an isolated endpoint"
```

---

### Task 7: Serve frontend and API from one origin via nginx

**Files:**
- Modify: `frontend/Dockerfile`
- Create: `frontend/nginx.conf`
- Modify: `docker-compose.yml`
- Modify: `.env.example`
- Modify: `setup.sh`

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces: nothing new for other tasks to consume — this is the serving
  change that makes Task 8's relative `/api` URLs actually reach the
  backend, and finally resolves the `VITE_BACKEND_URL` bug the whole
  initiative started from.

- [ ] **Step 1: Write `frontend/nginx.conf`**

```nginx
server {
    listen 80;
    server_name _;
    root /usr/share/nginx/html;
    index index.html;

    add_header Content-Security-Policy "default-src 'self'" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Referrer-Policy "no-referrer" always;
    add_header X-Frame-Options "DENY" always;

    location / {
        try_files $uri /index.html;
    }

    location /api/ {
        proxy_pass http://backend:8080;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection $connection_upgrade;
    }
}
```

Since the `Connection` header must be `upgrade` only for WebSocket
requests and left alone otherwise, this needs a `map` directive at the
`http` block level, which lives outside this `server` block. Add a second
file `frontend/nginx-http.conf` is unnecessary — instead, place the `map`
directive in `frontend/nginx.conf` above the `server` block (nginx allows
`map` inside a file included at the `http` context level, which is where
this file will be included — see Step 2):

```nginx
map $http_upgrade $connection_upgrade {
    default upgrade;
    ''      close;
}

server {
    listen 80;
    ...
```

(Fold this `map` block in above the `server { ... }` block already written
above — the final file has both.)

- [ ] **Step 2: Rewrite `frontend/Dockerfile`**

```dockerfile
# frontend/Dockerfile
FROM node:20-alpine AS build
WORKDIR /app
COPY package*.json ./
RUN npm install
COPY . .
RUN npm run build

FROM nginx:alpine
COPY --from=build /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf
EXPOSE 80
```

(`nginx:alpine`'s default `CMD` already runs `nginx -g "daemon off;"` — no
`CMD` override needed. Removing the default `/etc/nginx/conf.d/default.conf`
isn't necessary since `COPY` overwrites it directly at that exact path.)

- [ ] **Step 3: Update `docker-compose.yml`**

Change the `backend` and `verdict-engine` services to stop publishing
ports to the host (keep them reachable to each other and to `frontend` via
Docker's internal service-name DNS, which every service already uses:
`http://backend:8080`, `http://verdict-engine:8000`), pass the new
`MIRRAURA_ADMIN_USER`/`MIRRAURA_ADMIN_PASSWORD`/`MIRRAURA_USERS_PATH` env
vars to `backend`, and change `frontend`'s port mapping and drop
`VITE_BACKEND_URL` entirely:

```yaml
name: mirraura

services:
  backend:
    build: ./backend
    environment:
      - BACKEND_PORT=8080
      - VERDICT_ENGINE_URL=http://verdict-engine:8000
      - MIRRAURA_ADMIN_USER=${MIRRAURA_ADMIN_USER}
      - MIRRAURA_ADMIN_PASSWORD=${MIRRAURA_ADMIN_PASSWORD}
      - MIRRAURA_USERS_PATH=${MIRRAURA_USERS_PATH:-}
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
    depends_on:
      - verdict-engine

  verdict-engine:
    build: ./verdict-engine
    environment:
      - AUDIT_LOG_PATH=/data/audit_log.jsonl
      - KNOWN_BAD_HASHES_PATH=/data/known_bad_hashes.json
      - EVENT_ARCHIVE_PATH=/data/event_archive.jsonl
    volumes:
      - audit-log-data:/data
      - ./verdict-engine/revalidation_candidates:/app/revalidation_candidates
      - ./verdict-engine/revalidation_reports:/app/revalidation_reports

  frontend:
    build: ./frontend
    ports:
      - "${FRONTEND_PORT:-5173}:80"
    depends_on:
      - backend

  monitored-endpoint:
    build: ./monitored-endpoint
    container_name: mirraura-monitored-endpoint
    networks:
      - monitor-net

volumes:
  audit-log-data:

networks:
  monitor-net:
    name: mirraura-monitor-net
```

Note `VERDICT_ENGINE_PORT` is no longer used anywhere (its only use was the
now-removed `verdict-engine` port mapping) — leave the variable itself in
`.env.example` alone for now (Step 4 handles `.env.example`); removing an
env var nobody references is harmless either way, but this task's job is
the serving change, not an `.env.example` cleanup pass beyond what login
needs.

- [ ] **Step 4: Update `.env.example`**

Change:

```
BACKEND_PORT=8080
VERDICT_ENGINE_PORT=8000
FRONTEND_PORT=5173
AUDIT_LOG_PATH=/data/audit_log.jsonl
```

to:

```
BACKEND_PORT=8080
VERDICT_ENGINE_PORT=8000
FRONTEND_PORT=5173
AUDIT_LOG_PATH=/data/audit_log.jsonl

# Required. No default — setup.sh refuses to start if this is unset or
# shorter than 12 characters.
MIRRAURA_ADMIN_USER=admin
MIRRAURA_ADMIN_PASSWORD=

# Optional: path (inside the backend container) to a JSON file of extra
# users, e.g. {"username": "...", "bcrypt_hash": "...", "role": "analyst"}.
# Generate a hash with: go run ./backend/cmd/hashpw <password>
MIRRAURA_USERS_PATH=
```

- [ ] **Step 5: Add the password-strength check to `setup.sh`**

Change `setup.sh` from:

```bash
#!/bin/bash
# setup.sh — run once after cloning, or after pulling changes to shadow-image/sensor/
set -e
docker build -f shadow-image/Dockerfile -t mirraura-shadow:latest .
docker compose up --build
```

to:

```bash
#!/bin/bash
# setup.sh — run once after cloning, or after pulling changes to shadow-image/sensor/
set -e

if [ -f .env ]; then
  set -a
  source .env
  set +a
fi
if [ -z "$MIRRAURA_ADMIN_PASSWORD" ] || [ "${#MIRRAURA_ADMIN_PASSWORD}" -lt 12 ]; then
  echo "MIRRAURA_ADMIN_PASSWORD must be set in .env and at least 12 characters." >&2
  exit 1
fi

docker build -f shadow-image/Dockerfile -t mirraura-shadow:latest .
docker compose up --build
```

- [ ] **Step 6: Verify the nginx config is syntactically valid**

Run: `docker run --rm -v "$(pwd)/frontend/nginx.conf:/etc/nginx/conf.d/default.conf:ro" nginx:alpine nginx -t`
Expected: `nginx: configuration file /etc/nginx/nginx.conf test is successful`
(Docker daemon required — if unavailable in this environment, read the
config carefully by hand against nginx's `map`/`proxy_pass` documentation
instead, and note in your report that this specific check needs a Docker
daemon to run for real.)

- [ ] **Step 7: Commit**

```bash
git add frontend/Dockerfile frontend/nginx.conf docker-compose.yml .env.example setup.sh
git commit -m "feat: serve frontend and API from one origin via nginx"
```

---

### Task 8: `api.ts` — one `request()` helper, relative URLs, typed errors

**Files:**
- Modify: `frontend/src/api.ts`
- Modify: `frontend/src/api.test.ts`

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces:
  - `class ApiError extends Error { status: number }`
  - `async function request<T>(path: string, init?: RequestInit): Promise<T>`
    — prefixes `path` with nothing (relative URL, e.g. `/api/verdicts`,
    works because of Task 7's same-origin serving), always includes
    `credentials: "same-origin"` (needed so the session cookie is sent even
    if a future change moves the fetch base — same-origin fetches send
    cookies by default in browsers, but being explicit here means this
    still works correctly if `BASE` is ever reintroduced for local dev
    without nginx), checks `res.ok`, and on failure throws `new
    ApiError(await res.text(), res.status)`; on success, parses and returns
    JSON (or `undefined as T` for a `204 No Content` response, since
    `logoutHandler` returns 204 with no body).
  - Every existing exported function in `api.ts` (`uploadSample`,
    `fetchVerdicts`, `fetchMonitorStatus`, `reconnectMonitor`,
    `fetchHashes`, `submitHash`, `approveHash`, `rejectHash`) is
    reimplemented in terms of `request()`, keeping its exact existing
    exported signature. `connectLive` keeps its existing signature too, but
    drops the `BASE` variable it currently reads from
    `import.meta.env.VITE_BACKEND_URL` — the WS URL becomes a relative
    `ws(s)://<current host>/api/live`, computed from `window.location`.
  - New exported functions for the login flow (needed by Task 9):
    `login(username: string, password: string): Promise<{ username:
    string; role: string }>`, `logout(): Promise<void>`, `me(): Promise<{
    username: string; role: string }>`.

- [ ] **Step 1: Write the failing tests**

Add to `frontend/src/api.test.ts` (new, alongside the existing ones):

```ts
import { ApiError, request } from "./api";

describe("request", () => {
  it("returns parsed JSON on a successful response", async () => {
    (fetch as any).mockResolvedValue({ ok: true, status: 200, json: async () => ({ a: 1 }) });
    const result = await request<{ a: number }>("/api/whatever");
    expect(result).toEqual({ a: 1 });
  });

  it("throws an ApiError with the status code on a 401", async () => {
    (fetch as any).mockResolvedValue({ ok: false, status: 401, text: async () => "unauthorized" });
    await expect(request("/api/whatever")).rejects.toMatchObject({ status: 401, message: "unauthorized" });
  });

  it("throws an ApiError with the status code on a 403", async () => {
    (fetch as any).mockResolvedValue({ ok: false, status: 403, text: async () => "forbidden" });
    await expect(request("/api/whatever")).rejects.toMatchObject({ status: 403 });
  });

  it("thrown errors are instances of ApiError", async () => {
    (fetch as any).mockResolvedValue({ ok: false, status: 500, text: async () => "boom" });
    await expect(request("/api/whatever")).rejects.toBeInstanceOf(ApiError);
  });

  it("resolves to undefined on a 204 No Content response with no body", async () => {
    (fetch as any).mockResolvedValue({ ok: true, status: 204 });
    const result = await request("/api/logout", { method: "POST" });
    expect(result).toBeUndefined();
  });

  it("always sends credentials: same-origin", async () => {
    (fetch as any).mockResolvedValue({ ok: true, status: 200, json: async () => ({}) });
    await request("/api/whatever");
    expect(fetch).toHaveBeenCalledWith("/api/whatever", expect.objectContaining({ credentials: "same-origin" }));
  });
});
```

Update the existing tests in the same file that assert on the exact URL
fetched (e.g. `expect(fetch).toHaveBeenCalledWith(expect.stringContaining("/api/verdicts"))`)
— these should keep passing unchanged, since `stringContaining("/api/verdicts")`
still matches a relative `/api/verdicts` URL. Read through the whole file
once before editing to confirm none of the existing assertions hard-code
`http://localhost:8080` or similar — if any do, update them to expect the
relative path instead.

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd frontend && npm test`
Expected: FAIL to compile — `ApiError`/`request` don't exist yet.

- [ ] **Step 3: Implement in `frontend/src/api.ts`**

Read the current full file first (it has grown across Part 1's tasks —
`applyLiveEvent`, `shouldUpdateSampleVerdict`, `ConnectionState`,
`nextBackoffMs`, `connectLive` are all already there and this task must
not disturb their exported signatures). Replace the `BASE` constant and
every function above `connectLive` with:

```ts
export class ApiError extends Error {
  status: number;
  constructor(message: string, status: number) {
    super(message);
    this.status = status;
  }
}

export async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(path, { ...init, credentials: "same-origin" });
  if (!res.ok) {
    throw new ApiError(await res.text(), res.status);
  }
  if (res.status === 204) {
    return undefined as T;
  }
  return res.json();
}

export async function login(username: string, password: string): Promise<{ username: string; role: string }> {
  return request("/api/login", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username, password }),
  });
}

export async function logout(): Promise<void> {
  await request("/api/logout", { method: "POST" });
}

export async function me(): Promise<{ username: string; role: string }> {
  return request("/api/me");
}

export async function uploadSample(file: File): Promise<Verdict> {
  const form = new FormData();
  form.append("sample", file);
  return request("/api/samples", { method: "POST", body: form });
}

export async function fetchVerdicts(): Promise<Verdict[]> {
  return request("/api/verdicts");
}

export async function fetchMonitorStatus(): Promise<{ isolated: boolean }> {
  return request("/api/monitor/status");
}

export async function reconnectMonitor(): Promise<void> {
  await request("/api/monitor/reconnect", { method: "POST" });
}

export async function fetchHashes(): Promise<HashEntry[]> {
  return request("/api/hashes");
}

export async function submitHash(hash: string, label: string): Promise<void> {
  await request("/api/hashes", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ hash, label }),
  });
}

export async function approveHash(hash: string): Promise<void> {
  await request(`/api/hashes/${hash}/approve`, { method: "POST" });
}

export async function rejectHash(hash: string): Promise<void> {
  await request(`/api/hashes/${hash}/reject`, { method: "POST" });
}
```

In `connectLive`, remove the `BASE.replace(/^http/, "ws") + "/api/live"`
line's dependency on `BASE` (delete the `BASE` constant entirely once
nothing else uses it) and compute the WS URL from the current page origin:

```ts
    const wsUrl = (window.location.protocol === "https:" ? "wss://" : "ws://") + window.location.host + "/api/live";
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd frontend && npx tsc --noEmit -p tsconfig.app.json && npm test`
Expected: PASS.

- [ ] **Step 5: Build**

Run: `cd frontend && npm run build`
Expected: clean build. Since `VITE_BACKEND_URL` is no longer referenced
anywhere in `frontend/src`, this also completes the removal Task 7 started
in `docker-compose.yml`/`.env.example`.

- [ ] **Step 6: Commit**

```bash
git add frontend/src/api.ts frontend/src/api.test.ts
git commit -m "feat: one request() helper with typed errors; relative same-origin URLs"
```

---

### Task 9: Login page and session-aware `App.tsx`

**Files:**
- Create: `frontend/src/components/LoginPage.tsx`
- Modify: `frontend/src/App.tsx`
- Modify: `frontend/src/index.css` (a handful of small classes for the login form)

**Interfaces:**
- Consumes: `login`, `logout`, `me`, `ApiError` (Task 8).
- Produces: `LoginPage` component with props `{ onLogin: (user: {
  username: string; role: string }) => void }`. `App.tsx` gains a `user:
  { username: string; role: string } | null` state; renders `LoginPage`
  when `user` is `null`, the existing dashboard when it isn't. This is a
  **plain, functional** login form using existing design tokens — the
  Part 3 spec's split-screen/wordmark treatment is explicitly out of scope
  here (see Global Constraints).

- [ ] **Step 1: Write `LoginPage.tsx`**

```tsx
import { useRef, useState } from "react";
import { login } from "../api";

export function LoginPage({ onLogin }: { onLogin: (user: { username: string; role: string }) => void }) {
  const usernameRef = useRef<HTMLInputElement>(null);
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [capsLockOn, setCapsLockOn] = useState(false);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    const username = usernameRef.current?.value.trim() ?? "";
    if (!username || !password) return;
    setBusy(true);
    setError(null);
    try {
      const user = await login(username, password);
      onLogin(user);
    } catch (e) {
      setError(e instanceof Error ? e.message : "login failed");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="login-page">
      <form className="panel login-form" onSubmit={handleSubmit}>
        <h1>Mirraura</h1>
        <p className="app-header__subtitle">Sign in to continue</p>
        <label htmlFor="username">Username</label>
        <input
          id="username"
          name="username"
          autoComplete="username"
          ref={usernameRef}
          autoFocus
          disabled={busy}
        />
        <label htmlFor="password">Password</label>
        <input
          id="password"
          name="password"
          type="password"
          autoComplete="current-password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          onKeyUp={(e) => setCapsLockOn(e.getModifierState("CapsLock"))}
          disabled={busy}
        />
        {capsLockOn && <p className="login-form__hint">Caps Lock is on</p>}
        <button type="submit" className="run-button" disabled={busy}>
          {busy && <span className="spinner" aria-hidden="true" />}
          {busy ? "Signing in…" : "Sign in"}
        </button>
        {error && <p className="error-text">{error}</p>}
      </form>
    </div>
  );
}
```

- [ ] **Step 2: Add minimal CSS**

Append to `frontend/src/index.css` (reusing existing tokens — no new
colors, fonts, or spacing values):

```css
/* ---------- Login page ---------- */

.login-page {
  min-height: 100svh;
  display: flex;
  align-items: center;
  justify-content: center;
  padding: var(--sp-3);
}

.login-form {
  width: 100%;
  max-width: 360px;
  display: flex;
  flex-direction: column;
  gap: var(--sp-1);
}

.login-form label {
  font-size: 13px;
  color: var(--ink-muted);
  margin-top: var(--sp-1);
}

.login-form__hint {
  font-size: 12px;
  color: var(--sev-suspicious);
  margin: 0;
}
```

- [ ] **Step 3: Wire session state into `App.tsx`**

Read the current full `frontend/src/App.tsx` first — Task 6/7/8/9's prior
edits (Part 1) already added `connState`, `monitorError`, and the
`applyLiveEvent`/`shouldUpdateSampleVerdict`-based WS handler; this task
adds a gate in front of all of it, not a rewrite of it.

Add imports:

```tsx
import { logout, me } from "./api";
import { LoginPage } from "./components/LoginPage";
```

Add state and a load-time `/api/me` check, and a logout handler. Change the
top of the `App` function from:

```tsx
function App() {
  const [events, setEvents] = useState<MirraEvent[]>([]);
  const [verdict, setVerdict] = useState<Verdict | null>(null);
  const [refreshKey, setRefreshKey] = useState(0);
  const [isolated, setIsolated] = useState(false);
  const [connState, setConnState] = useState<ConnectionState>("connecting");
  const [monitorError, setMonitorError] = useState<string | null>(null);

  useEffect(() => {
    fetchMonitorStatus()
```

to:

```tsx
function App() {
  const [user, setUser] = useState<{ username: string; role: string } | null | undefined>(undefined);
  const [sessionExpired, setSessionExpired] = useState(false);
  const [events, setEvents] = useState<MirraEvent[]>([]);
  const [verdict, setVerdict] = useState<Verdict | null>(null);
  const [refreshKey, setRefreshKey] = useState(0);
  const [isolated, setIsolated] = useState(false);
  const [connState, setConnState] = useState<ConnectionState>("connecting");
  const [monitorError, setMonitorError] = useState<string | null>(null);

  useEffect(() => {
    me()
      .then(setUser)
      .catch(() => setUser(null));
  }, []);

  useEffect(() => {
    if (!user) return;
    fetchMonitorStatus()
```

(`user` starts as `undefined` — meaning "haven't checked yet" — distinct
from `null`, "checked and not logged in." The second `useEffect`, which
sets up monitor-status polling and the live WebSocket, now only runs once
`user` is truthy, gated by the `if (!user) return;` guard and `user` added
to that effect's own dependency array — see the closing `}, [])line a few
lines down in the existing code, which becomes `}, [user]);`.)

Find the existing effect's closing line `}, []);` (the one immediately
after `return () => conn.close();`) and change it to `}, [user]);`.

Add a `handleLogout` function and the login gate to the render. Change:

```tsx
  function handleUpload(v: Verdict) {
    setVerdict(v);
    setRefreshKey((k) => k + 1);
  }

  return (
    <div className="app">
```

to:

```tsx
  function handleUpload(v: Verdict) {
    setVerdict(v);
    setRefreshKey((k) => k + 1);
  }

  async function handleLogout() {
    await logout().catch(() => {});
    setUser(null);
  }

  if (user === undefined) {
    return null;
  }

  if (user === null) {
    return (
      <>
        {sessionExpired && <p className="error-text">Your session expired. Please sign in again.</p>}
        <LoginPage
          onLogin={(u) => {
            setSessionExpired(false);
            setUser(u);
          }}
        />
      </>
    );
  }

  return (
    <div className="app">
```

Add a logout button and username/role display to the header. Change:

```tsx
        <p className="app-header__conn-state" data-state={connState}>
          {connState === "live" ? "● Live" : connState === "connecting" ? "○ Connecting…" : "○ Offline — retrying"}
        </p>
      </header>
```

to:

```tsx
        <p className="app-header__conn-state" data-state={connState}>
          {connState === "live" ? "● Live" : connState === "connecting" ? "○ Connecting…" : "○ Offline — retrying"}
        </p>
        <p className="app-header__user">
          {user.username} · {user.role}{" "}
          <button className="app-header__logout" onClick={handleLogout}>
            Sign out
          </button>
        </p>
      </header>
```

- [ ] **Step 4: Handle session expiry on any later 401**

Any API call made after the initial `/api/me` check can start failing with
a 401 if the session expires mid-session (8-hour sliding TTL). The
WebSocket connection itself doesn't go through `request()` (messages
arrive over the socket, not as fetch responses), so it isn't part of this
step — a dropped WS connection after session expiry just shows as
`connState` cycling through `"offline"`/`"connecting"` via the existing
Part 1 reconnect logic, which is an acceptable (if less precise) signal
here; wiring 401-specific detection into the WS upgrade path is out of
scope for this task. The concrete, in-scope case is `UploadPanel`'s
`handleUpload`, since that's the one place a stale session would visibly
surface first, on the next upload attempt. Since `UploadPanel` doesn't
currently know about `user`/`setUser`, add a narrow `onSessionExpired: ()
=> void` prop to it instead of threading full auth state in. In
`frontend/src/components/UploadPanel.tsx`, change the top import line from:

```tsx
import { uploadSample } from "../api";
```

to:

```tsx
import { ApiError, uploadSample } from "../api";
```

Then change the `catch` block of `handleUpload`:

```tsx
    } catch (e) {
      setError(e instanceof Error ? e.message : "upload failed");
    } finally {
```

to:

```tsx
    } catch (e) {
      if (e instanceof ApiError && e.status === 401) {
        onSessionExpired();
        return;
      }
      setError(e instanceof Error ? e.message : "upload failed");
    } finally {
```

Add `onSessionExpired: () => void` to `UploadPanel`'s props destructuring
and its inline props type (the same object literal type currently reading
`{ onVerdict: (v: Verdict) => void; onUploadStart: () => void }` — extend
it with `onSessionExpired: () => void`). In `App.tsx`, pass:

```tsx
          <UploadPanel
            onVerdict={handleUpload}
            onUploadStart={() => setEvents([])}
            onSessionExpired={() => {
              setSessionExpired(true);
              setUser(null);
            }}
          />
```

- [ ] **Step 5: Add a small style for the header user/logout controls**

Append to `frontend/src/index.css`:

```css
.app-header__user {
  font-size: 12px;
  color: var(--ink-muted);
  display: flex;
  align-items: center;
  gap: var(--sp-1);
}

.app-header__logout {
  font-size: 12px;
  padding: 2px 8px;
}
```

- [ ] **Step 6: Type-check, run the frontend suite, and build**

Run: `cd frontend && npx tsc --noEmit -p tsconfig.app.json && npm test && npm run build`
Expected: PASS.

- [ ] **Step 7: Manually verify**

No component-rendering test harness exists in this repo (same constraint
as Part 1). Verify by running `docker compose up --build`: the dashboard
should now load `http://localhost:5173` and show the login form (not the
old broken CORS-blocked dashboard from Part 1); signing in with the
`MIRRAURA_ADMIN_USER`/`MIRRAURA_ADMIN_PASSWORD` from `.env` should reach
the dashboard, show `Sign out` in the header, and uploading a sample from
`samples/` should work end to end (this also exercises Task 7's nginx
proxy and Task 4's actor recording for real).

- [ ] **Step 8: Commit**

```bash
git add frontend/src/components/LoginPage.tsx frontend/src/App.tsx frontend/src/components/UploadPanel.tsx frontend/src/index.css
git commit -m "feat: add login page and gate the dashboard behind a session"
```

---

### Task 10: Documentation

**Files:**
- Modify: `docs/concepts.md`
- Modify: `README.md`

**Interfaces:** none — documentation only.

- [ ] **Step 1: Update `docs/concepts.md`**

Add a new bullet under "Tools & libraries — what and why" (find that
section header) for `bcrypt`:

```markdown
**golang.org/x/crypto/bcrypt (Go)** — Industry-standard adaptive password
hashing (not a fast general-purpose hash like SHA-256, which would make
brute-forcing a stolen password database cheap). Used to store the admin
password (and any `users.json` entries) as a hash, never plaintext, and to
check a login attempt in constant time relative to the stored hash.
```

Add a new bullet for nginx same-origin serving in the same section:

```markdown
**nginx (reverse proxy)** — Serves the built frontend as static files and
proxies `/api/` (including the WebSocket upgrade for `/api/live`) to the
backend on the same origin. This is what actually fixes the
`VITE_BACKEND_URL`-baked-in-at-build-time bug from Part 1: the frontend no
longer needs to know the backend's address at all, it just calls relative
`/api/...` URLs on its own origin. It's also what makes the session cookie
(`SameSite=Strict`) and the WebSocket origin check (tightened in Part 1)
both actually work in the shipped stack, since frontend and backend are no
longer different origins.
```

Add a new subsection near the "Human-approval gate" paragraph (which
already exists) explaining the auth model — insert after that paragraph:

```markdown
## Authentication and sessions (Part 2)

No public sign-up — this is a security tool, not a public service. Exactly
one admin account is seeded from `MIRRAURA_ADMIN_USER`/
`MIRRAURA_ADMIN_PASSWORD` at startup (the backend refuses to start if the
password is unset or under 12 characters); additional users can be added
via an optional `users.json` of `{username, bcrypt_hash, role}` entries
(generate a hash with `go run ./backend/cmd/hashpw <password>`). Two
roles: `admin` (can approve/reject hashes and reconnect an isolated
endpoint) and `analyst` (read-only plus upload). A session is a random
32-byte token held in an in-memory map on the backend (lost on restart —
fine for a single-instance deployment, see the `// ponytail:` comment on
`SessionStore`), sent as an `HttpOnly`, `SameSite=Strict` cookie, sliding
forward 8 hours on every authenticated request. Login is rate-limited to 5
failed attempts per IP per 15 minutes. Every consequential action —
uploading a sample, approving/rejecting a hash, reconnecting an isolated
endpoint — now records the authenticated username as `actor` in the
tamper-evident audit log, so the human-approval gate (see above) has an
actual named human behind every entry, not just "someone with dashboard
access."
```

- [ ] **Step 2: Update `README.md`**

Replace the existing "Known gap" paragraph (added by Part 1's final fix
wave) — the gap it describes is now fixed by this plan's Task 7 — with a
short note about the new login step and env vars. Change:

```markdown
Once the stack is up, the dashboard is at http://localhost:5173.

**Known gap:** the dashboard is not functional yet when served this way — the
frontend (`:5173`) and backend (`:8080`) are different origins, and CORS plus
the WebSocket same-origin check (both intentionally tightened) block every
request. This is expected until a same-origin reverse proxy lands in a later
change, not a regression.
```

to:

```markdown
Before running `./setup.sh`, set `MIRRAURA_ADMIN_USER` and
`MIRRAURA_ADMIN_PASSWORD` in `.env` (12+ characters, no default — the
script refuses to start otherwise).

Once the stack is up, the dashboard is at http://localhost:5173. Sign in
with the admin credentials from `.env`. There's no public sign-up; add more
accounts via an optional `MIRRAURA_USERS_PATH` JSON file (see
`.env.example`) if you need more than one user.
```

- [ ] **Step 3: Commit**

```bash
git add docs/concepts.md README.md
git commit -m "docs: document the auth model, sessions, roles, and nginx serving"
```

---

## Definition of done for this plan

- `cd backend && go build ./... && go vet ./... && go test ./...` passes
  (aside from any pre-existing Docker-daemon-dependent test if this
  environment has no daemon — unrelated to this plan).
- `cd verdict-engine && python -m pytest tests/ -q` passes.
- `cd frontend && npx tsc --noEmit -p tsconfig.app.json && npm test && npm run build` passes.
- Manually verified via `docker compose up --build` (Task 9's Step 7):
  login page loads, admin login reaches the dashboard, sample upload works
  end to end through the nginx proxy, the audit log shows the admin
  username as `actor`, and signing out returns to the login page. If
  possible, also sign in as an analyst (added via `MIRRAURA_USERS_PATH`)
  and confirm hash approve/reject and monitor reconnect are forbidden
  (403) rather than merely hidden.
- `docs/concepts.md` and `README.md` updated per Task 10.
- Ten commits land in this plan's order, each building and passing tests
  on its own.
