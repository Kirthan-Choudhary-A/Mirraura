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

func TestLoadUsersRejectsInvalidRole(t *testing.T) {
	withEnv(t, "MIRRAURA_ADMIN_USER", "admin")
	withEnv(t, "MIRRAURA_ADMIN_PASSWORD", "correcthorsebatterystaple")

	dir := t.TempDir()
	path := filepath.Join(dir, "users.json")
	hash, _ := bcrypt.GenerateFromPassword([]byte("whatever12345"), bcrypt.DefaultCost)
	entries := []map[string]string{
		{"username": "bob", "bcrypt_hash": string(hash), "role": "superadmin"},
	}
	data, _ := json.Marshal(entries)
	os.WriteFile(path, data, 0644)
	withEnv(t, "MIRRAURA_USERS_PATH", path)

	if _, err := loadUsers(); err == nil {
		t.Fatal("expected an error for a users.json entry with an invalid role")
	}
}

func TestLoadUsersRejectsDuplicateUsernameWithinUsersJSON(t *testing.T) {
	withEnv(t, "MIRRAURA_ADMIN_USER", "admin")
	withEnv(t, "MIRRAURA_ADMIN_PASSWORD", "correcthorsebatterystaple")

	dir := t.TempDir()
	path := filepath.Join(dir, "users.json")
	hash, _ := bcrypt.GenerateFromPassword([]byte("whatever12345"), bcrypt.DefaultCost)
	entries := []map[string]string{
		{"username": "alice", "bcrypt_hash": string(hash), "role": "analyst"},
		{"username": "alice", "bcrypt_hash": string(hash), "role": "analyst"},
	}
	data, _ := json.Marshal(entries)
	os.WriteFile(path, data, 0644)
	withEnv(t, "MIRRAURA_USERS_PATH", path)

	if _, err := loadUsers(); err == nil {
		t.Fatal("expected an error for duplicate usernames within users.json")
	}
}
