package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
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
		pool.Close()
	})
	return pool
}

func adminSessionContext() context.Context {
	return context.WithValue(context.Background(), sessionCtxKey, Session{Username: "admin", Role: "admin"})
}

func TestCreateUserHandler(t *testing.T) {
	pool := newTestUsersPoolForHandlers(t)
	body, _ := json.Marshal(map[string]string{"username": "bob", "password": "bobspassword123", "role": "analyst"})
	req := httptest.NewRequest(http.MethodPost, "/api/users", bytes.NewReader(body)).WithContext(adminSessionContext())
	w := httptest.NewRecorder()

	createUserHandler(pool)(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	user, err := GetUser(context.Background(), pool, "bob")
	if err != nil {
		t.Fatalf("GetUser(bob): %v", err)
	}
	if user.Role != "analyst" {
		t.Fatalf("expected role analyst, got %q", user.Role)
	}
}

func TestDeleteUserHandlerRejectsLastAdmin(t *testing.T) {
	pool := newTestUsersPoolForHandlers(t)
	req := httptest.NewRequest(http.MethodDelete, "/api/users/admin", nil).WithContext(adminSessionContext())
	req.SetPathValue("username", "admin")
	w := httptest.NewRecorder()

	deleteUserHandler(pool)(w, req)

	if w.Code != http.StatusConflict {
		t.Fatalf("expected 409 when deleting the last admin, got %d: %s", w.Code, w.Body.String())
	}
}

func TestUpdateUserRoleHandlerRejectsDemotingLastAdmin(t *testing.T) {
	pool := newTestUsersPoolForHandlers(t)
	body, _ := json.Marshal(map[string]string{"role": "analyst"})
	req := httptest.NewRequest(http.MethodPatch, "/api/users/admin/role", bytes.NewReader(body)).WithContext(adminSessionContext())
	req.SetPathValue("username", "admin")
	w := httptest.NewRecorder()

	updateUserRoleHandler(pool)(w, req)

	if w.Code != http.StatusConflict {
		t.Fatalf("expected 409 when demoting the last admin, got %d: %s", w.Code, w.Body.String())
	}
}
