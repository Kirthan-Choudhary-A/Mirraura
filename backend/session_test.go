package main

import (
	"context"
	"testing"
	"time"
)

func newTestSessionStore(t *testing.T) *SessionStore {
	t.Helper()
	adminURL := testAdminURL(t)
	// Every Go test that migrates the real "migrations" directory must share
	// this exact role -- schema_migrations tracks a migration as applied
	// globally, by filename, not per caller, so a different role name here
	// would never actually get bootstrapped once another test file wins the
	// race to apply 0001_create_sessions.sql first.
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
		pool.Exec(ctx, "DELETE FROM sessions")
		pool.Close()
	})
	return NewSessionStore(pool)
}

func TestSessionStoreCreateAndGet(t *testing.T) {
	store := newTestSessionStore(t)
	ctx := context.Background()
	token, err := store.Create(ctx, "alice", "analyst")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if token == "" {
		t.Fatal("expected a non-empty token")
	}
	sess, ok := store.Get(ctx, token)
	if !ok {
		t.Fatal("expected the created session to be found")
	}
	if sess.Username != "alice" || sess.Role != "analyst" {
		t.Fatalf("unexpected session: %+v", sess)
	}
}

func TestSessionStoreGetUnknownTokenFails(t *testing.T) {
	store := newTestSessionStore(t)
	if _, ok := store.Get(context.Background(), "does-not-exist"); ok {
		t.Fatal("expected an unknown token to not be found")
	}
}

func TestSessionStoreDelete(t *testing.T) {
	store := newTestSessionStore(t)
	ctx := context.Background()
	token, _ := store.Create(ctx, "alice", "analyst")
	store.Delete(ctx, token)
	if _, ok := store.Get(ctx, token); ok {
		t.Fatal("expected the deleted session to be gone")
	}
}

func TestSessionStoreCleanupExpiredRemovesExpiredRows(t *testing.T) {
	store := newTestSessionStore(t)
	ctx := context.Background()
	token, _ := store.Create(ctx, "alice", "analyst")
	// Force it into the past directly, bypassing the TTL constant.
	if _, err := store.pool.Exec(ctx, "UPDATE sessions SET expires_at = $1 WHERE token = $2", time.Now().Add(-time.Hour), token); err != nil {
		t.Fatalf("force-expire: %v", err)
	}
	if err := store.CleanupExpired(ctx); err != nil {
		t.Fatalf("CleanupExpired: %v", err)
	}
	var count int
	if err := store.pool.QueryRow(ctx, "SELECT count(*) FROM sessions WHERE token = $1", token).Scan(&count); err != nil {
		t.Fatalf("count: %v", err)
	}
	if count != 0 {
		t.Fatal("expected the expired row to have been deleted")
	}
}

func TestSessionStoreGetRejectsExpiredSession(t *testing.T) {
	store := newTestSessionStore(t)
	ctx := context.Background()
	token, _ := store.Create(ctx, "alice", "analyst")
	// Force expiry directly, without running CleanupExpired -- Get() itself
	// must refuse an expired-but-still-present row, not rely on the cleanup
	// job having run first.
	if _, err := store.pool.Exec(ctx, "UPDATE sessions SET expires_at = $1 WHERE token = $2", time.Now().Add(-time.Minute), token); err != nil {
		t.Fatalf("force-expire: %v", err)
	}
	if _, ok := store.Get(ctx, token); ok {
		t.Fatal("expected Get to reject an expired session")
	}
}
