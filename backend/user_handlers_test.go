package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/bcrypt"
)

func newTestUsersPoolForHandlers(t *testing.T) *pgxpool.Pool {
	t.Helper()
	adminURL := testAdminURL(t)
	runtimeURL := "postgres://backend_role:backend_test_pw@localhost:5432/mirraura"
	ctx := context.Background()
	if err := RunMigrations(ctx, adminURL, runtimeURL, "migrations"); err != nil {
		t.Fatalf("RunMigrations: %v", err)
	}
	pool, err := NewPool(ctx, runtimeURL)
	if err != nil {
		t.Fatalf("NewPool(runtime): %v", err)
	}
	hash, _ := bcrypt.GenerateFromPassword([]byte("adminpassword123"), bcrypt.DefaultCost)
	pool.Exec(ctx, "INSERT INTO users (username, password_hash, role) VALUES ('admin', $1, 'admin')", string(hash))
	t.Cleanup(func() {
		pool.Exec(ctx, "DELETE FROM users")
		pool.Exec(ctx, "DELETE FROM sessions")
		pool.Close()
	})
	return pool
}

// newFakeAuditEngine stands in for the verdict-engine's /audit/action route
// and returns a func reporting every audit body it received.
func newFakeAuditEngine(t *testing.T) (*httptest.Server, func() []map[string]string) {
	t.Helper()
	var mu sync.Mutex
	var got []map[string]string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/audit/action" || r.Method != http.MethodPost {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		var body map[string]string
		json.NewDecoder(r.Body).Decode(&body)
		mu.Lock()
		got = append(got, body)
		mu.Unlock()
	}))
	t.Cleanup(srv.Close)
	return srv, func() []map[string]string {
		mu.Lock()
		defer mu.Unlock()
		return append([]map[string]string(nil), got...)
	}
}

func assertSingleAudit(t *testing.T, audits []map[string]string, action, target string) {
	t.Helper()
	if len(audits) != 1 {
		t.Fatalf("expected exactly 1 audit post, got %d: %v", len(audits), audits)
	}
	a := audits[0]
	if a["action"] != action || a["device_id"] != target || a["actor"] != "admin" {
		t.Fatalf("expected {action:%s device_id:%s actor:admin}, got %v", action, target, a)
	}
}

func adminSessionContext() context.Context {
	return context.WithValue(context.Background(), sessionCtxKey, Session{Username: "admin", Role: "admin"})
}

func TestCreateUserHandler(t *testing.T) {
	pool := newTestUsersPoolForHandlers(t)
	engine, audits := newFakeAuditEngine(t)
	body, _ := json.Marshal(map[string]string{"username": "bob", "password": "bobspassword123", "role": "analyst"})
	req := httptest.NewRequest(http.MethodPost, "/api/users", bytes.NewReader(body)).WithContext(adminSessionContext())
	w := httptest.NewRecorder()

	createUserHandler(pool, engine.URL)(w, req)

	if w.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d: %s", w.Code, w.Body.String())
	}
	user, err := GetUser(context.Background(), pool, "bob")
	if err != nil {
		t.Fatalf("GetUser(bob): %v", err)
	}
	if user.Role != "analyst" {
		t.Fatalf("expected role analyst, got %q", user.Role)
	}
	assertSingleAudit(t, audits(), "user_created", "bob")
}

func TestCreateUserHandlerRejectsEmptyUsername(t *testing.T) {
	pool := newTestUsersPoolForHandlers(t)
	engine, audits := newFakeAuditEngine(t)
	body, _ := json.Marshal(map[string]string{"username": "   ", "password": "somepassword123", "role": "analyst"})
	req := httptest.NewRequest(http.MethodPost, "/api/users", bytes.NewReader(body)).WithContext(adminSessionContext())
	w := httptest.NewRecorder()

	createUserHandler(pool, engine.URL)(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
	var n int
	if err := pool.QueryRow(context.Background(), "SELECT count(*) FROM users WHERE trim(username) = ''").Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 0 {
		t.Fatalf("expected no blank-username row, got %d", n)
	}
	if len(audits()) != 0 {
		t.Fatalf("expected no audit post for a rejected create, got %v", audits())
	}
}

func TestDeleteUserHandlerRejectsLastAdmin(t *testing.T) {
	pool := newTestUsersPoolForHandlers(t)
	engine, audits := newFakeAuditEngine(t)
	store := NewSessionStore(pool)
	req := httptest.NewRequest(http.MethodDelete, "/api/users/admin", nil).WithContext(adminSessionContext())
	req.SetPathValue("username", "admin")
	w := httptest.NewRecorder()

	deleteUserHandler(store, pool, engine.URL)(w, req)

	if w.Code != http.StatusConflict {
		t.Fatalf("expected 409 when deleting the last admin, got %d: %s", w.Code, w.Body.String())
	}
	if len(audits()) != 0 {
		t.Fatalf("expected no audit post for a rejected delete, got %v", audits())
	}
}

func TestUpdateUserRoleHandlerRejectsDemotingLastAdmin(t *testing.T) {
	pool := newTestUsersPoolForHandlers(t)
	engine, audits := newFakeAuditEngine(t)
	store := NewSessionStore(pool)
	body, _ := json.Marshal(map[string]string{"role": "analyst"})
	req := httptest.NewRequest(http.MethodPatch, "/api/users/admin/role", bytes.NewReader(body)).WithContext(adminSessionContext())
	req.SetPathValue("username", "admin")
	w := httptest.NewRecorder()

	updateUserRoleHandler(store, pool, engine.URL)(w, req)

	if w.Code != http.StatusConflict {
		t.Fatalf("expected 409 when demoting the last admin, got %d: %s", w.Code, w.Body.String())
	}
	if len(audits()) != 0 {
		t.Fatalf("expected no audit post for a rejected demotion, got %v", audits())
	}
}

func TestDeleteUserHandlerInvalidatesExistingSessions(t *testing.T) {
	pool := newTestUsersPoolForHandlers(t)
	engine, audits := newFakeAuditEngine(t)
	store := NewSessionStore(pool)
	ctx := context.Background()
	// A second admin so deleting "bob" (an analyst) below doesn't trip the
	// last-admin check -- this test is about session invalidation, not that.
	hash, err := bcrypt.GenerateFromPassword([]byte("bobspassword123"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("GenerateFromPassword: %v", err)
	}
	if _, err := pool.Exec(ctx, "INSERT INTO users (username, password_hash, role) VALUES ('bob', $1, 'analyst')", string(hash)); err != nil {
		t.Fatalf("seed bob: %v", err)
	}
	token, err := store.Create(ctx, "bob", "analyst")
	if err != nil {
		t.Fatalf("store.Create: %v", err)
	}
	if _, ok := store.Get(ctx, token); !ok {
		t.Fatal("expected bob's session to be valid before deletion")
	}

	req := httptest.NewRequest(http.MethodDelete, "/api/users/bob", nil).WithContext(adminSessionContext())
	req.SetPathValue("username", "bob")
	w := httptest.NewRecorder()

	deleteUserHandler(store, pool, engine.URL)(w, req)

	if w.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d: %s", w.Code, w.Body.String())
	}
	if _, ok := store.Get(ctx, token); ok {
		t.Fatal("expected bob's session to be invalidated after deletion")
	}
	assertSingleAudit(t, audits(), "user_removed", "bob")
}

func TestUpdateUserRoleHandlerInvalidatesExistingSessions(t *testing.T) {
	pool := newTestUsersPoolForHandlers(t)
	engine, audits := newFakeAuditEngine(t)
	store := NewSessionStore(pool)
	ctx := context.Background()
	hash, err := bcrypt.GenerateFromPassword([]byte("bobspassword123"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("GenerateFromPassword: %v", err)
	}
	if _, err := pool.Exec(ctx, "INSERT INTO users (username, password_hash, role) VALUES ('bob', $1, 'admin')", string(hash)); err != nil {
		t.Fatalf("seed bob: %v", err)
	}
	token, err := store.Create(ctx, "bob", "admin")
	if err != nil {
		t.Fatalf("store.Create: %v", err)
	}
	if _, ok := store.Get(ctx, token); !ok {
		t.Fatal("expected bob's session to be valid before the role change")
	}

	body, _ := json.Marshal(map[string]string{"role": "analyst"})
	req := httptest.NewRequest(http.MethodPatch, "/api/users/bob/role", bytes.NewReader(body)).WithContext(adminSessionContext())
	req.SetPathValue("username", "bob")
	w := httptest.NewRecorder()

	updateUserRoleHandler(store, pool, engine.URL)(w, req)

	if w.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d: %s", w.Code, w.Body.String())
	}
	if _, ok := store.Get(ctx, token); ok {
		t.Fatal("expected bob's session to be invalidated after the role change")
	}
	assertSingleAudit(t, audits(), "user_role_changed", "bob")
}
