package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
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

func newTestUsersPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	adminURL := testAdminURL(t)
	runtimeURL := testRuntimeURL(t, adminURL, "backend_role", "backend_test_pw")
	ctx := context.Background()
	if err := RunMigrations(ctx, adminURL, runtimeURL, "migrations"); err != nil {
		t.Fatalf("RunMigrations: %v", err)
	}
	pool, err := NewPool(ctx, runtimeURL)
	if err != nil {
		t.Fatalf("NewPool(runtime): %v", err)
	}
	t.Cleanup(func() {
		pool.Exec(ctx, "DELETE FROM users")
		pool.Close()
	})
	return pool
}

func TestSeedUsersSeedsAdminFromEnv(t *testing.T) {
	pool := newTestUsersPool(t)
	withEnv(t, "MIRRAURA_ADMIN_USER", "admin")
	withEnv(t, "MIRRAURA_ADMIN_PASSWORD", "correcthorsebatterystaple")
	withEnv(t, "MIRRAURA_USERS_PATH", "")
	ctx := context.Background()

	if err := SeedUsers(ctx, pool); err != nil {
		t.Fatalf("SeedUsers: %v", err)
	}
	admin, err := GetUser(ctx, pool, "admin")
	if err != nil {
		t.Fatalf("GetUser: %v", err)
	}
	if admin.Role != "admin" {
		t.Fatalf("expected role admin, got %q", admin.Role)
	}
	if err := bcrypt.CompareHashAndPassword([]byte(admin.PasswordHash), []byte("correcthorsebatterystaple")); err != nil {
		t.Fatalf("expected password hash to verify, got: %v", err)
	}
}

func TestSeedUsersRejectsShortPassword(t *testing.T) {
	pool := newTestUsersPool(t)
	withEnv(t, "MIRRAURA_ADMIN_USER", "admin")
	withEnv(t, "MIRRAURA_ADMIN_PASSWORD", "short")
	withEnv(t, "MIRRAURA_USERS_PATH", "")

	if err := SeedUsers(context.Background(), pool); err == nil {
		t.Fatal("expected an error for a password shorter than 12 characters")
	}
}

func TestSeedUsersIsIdempotent(t *testing.T) {
	pool := newTestUsersPool(t)
	withEnv(t, "MIRRAURA_ADMIN_USER", "admin")
	withEnv(t, "MIRRAURA_ADMIN_PASSWORD", "correcthorsebatterystaple")
	withEnv(t, "MIRRAURA_USERS_PATH", "")
	ctx := context.Background()

	if err := SeedUsers(ctx, pool); err != nil {
		t.Fatalf("first seed: %v", err)
	}
	// A runtime admin action changes the seeded admin's role; re-seeding
	// (e.g. on restart) must not clobber it back.
	if _, err := pool.Exec(ctx, "UPDATE users SET role = 'analyst' WHERE username = 'admin'"); err != nil {
		t.Fatalf("simulate runtime change: %v", err)
	}
	if err := SeedUsers(ctx, pool); err != nil {
		t.Fatalf("second seed: %v", err)
	}
	admin, err := GetUser(ctx, pool, "admin")
	if err != nil {
		t.Fatalf("GetUser: %v", err)
	}
	if admin.Role != "analyst" {
		t.Fatalf("expected re-seeding to leave the runtime-changed role alone, got %q", admin.Role)
	}
}

func TestSeedUsersMergesUsersJSON(t *testing.T) {
	pool := newTestUsersPool(t)
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
	os.WriteFile(path, data, 0644)
	withEnv(t, "MIRRAURA_USERS_PATH", path)
	ctx := context.Background()

	if err := SeedUsers(ctx, pool); err != nil {
		t.Fatalf("SeedUsers: %v", err)
	}
	alice, err := GetUser(ctx, pool, "alice")
	if err != nil {
		t.Fatalf("GetUser(alice): %v", err)
	}
	if alice.Role != "analyst" {
		t.Fatalf("expected alice with role analyst, got %+v", alice)
	}
}

func TestSeedUsersDoesNotResurrectRemovedUser(t *testing.T) {
	pool := newTestUsersPool(t)
	withEnv(t, "MIRRAURA_ADMIN_USER", "admin")
	withEnv(t, "MIRRAURA_ADMIN_PASSWORD", "correcthorsebatterystaple")
	withEnv(t, "MIRRAURA_USERS_PATH", "")
	ctx := context.Background()

	if err := SeedUsers(ctx, pool); err != nil {
		t.Fatalf("first seed: %v", err)
	}
	// Realistic runtime flow: add a replacement admin, then remove the
	// (e.g. compromised) bootstrap admin. The table is non-empty afterward.
	hash, _ := bcrypt.GenerateFromPassword([]byte("replacementpw123"), bcrypt.DefaultCost)
	if _, err := pool.Exec(ctx, "INSERT INTO users (username, password_hash, role) VALUES ('admin2', $1, 'admin')", string(hash)); err != nil {
		t.Fatalf("add replacement admin: %v", err)
	}
	if _, err := pool.Exec(ctx, "DELETE FROM users WHERE username = 'admin'"); err != nil {
		t.Fatalf("remove bootstrap admin: %v", err)
	}
	if err := SeedUsers(ctx, pool); err != nil {
		t.Fatalf("second seed (restart): %v", err)
	}
	if _, err := GetUser(ctx, pool, "admin"); err == nil {
		t.Fatal("expected the removed bootstrap admin to stay removed after re-seeding")
	}
}
