package main

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func newTestQuarantinePool(t *testing.T) *pgxpool.Pool {
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
		if _, err := pool.Exec(ctx, "DELETE FROM quarantined_files"); err != nil {
			t.Errorf("cleanup: DELETE FROM quarantined_files: %v", err)
		}
		pool.Close()
	})
	return pool
}

func TestInsertAndListPendingQuarantine(t *testing.T) {
	pool := newTestQuarantinePool(t)
	ctx := context.Background()

	id, err := insertQuarantine(ctx, pool, "abc123", "payload.sh", "/home/user/Downloads/payload.sh", "Suspicious", 0.45)
	if err != nil {
		t.Fatalf("insertQuarantine: %v", err)
	}
	if id == 0 {
		t.Fatal("expected a nonzero id")
	}

	pending, err := listPendingQuarantine(ctx, pool)
	if err != nil {
		t.Fatalf("listPendingQuarantine: %v", err)
	}
	if len(pending) != 1 {
		t.Fatalf("expected 1 pending entry, got %d", len(pending))
	}
	if pending[0].ID != id || pending[0].Filename != "payload.sh" || pending[0].Status != "pending" {
		t.Fatalf("unexpected entry: %+v", pending[0])
	}
}

func TestDecideQuarantineApprove(t *testing.T) {
	pool := newTestQuarantinePool(t)
	ctx := context.Background()

	id, err := insertQuarantine(ctx, pool, "abc123", "payload.sh", "/home/user/Downloads/payload.sh", "Suspicious", 0.45)
	if err != nil {
		t.Fatalf("insertQuarantine: %v", err)
	}

	q, err := decideQuarantine(ctx, pool, id, "approved")
	if err != nil {
		t.Fatalf("decideQuarantine: %v", err)
	}
	if q.Status != "approved" {
		t.Fatalf("expected status approved, got %s", q.Status)
	}

	pending, err := listPendingQuarantine(ctx, pool)
	if err != nil {
		t.Fatalf("listPendingQuarantine: %v", err)
	}
	if len(pending) != 0 {
		t.Fatalf("expected approved entry to drop out of the pending list, got %d", len(pending))
	}
}

func TestDecideQuarantineTwiceFails(t *testing.T) {
	pool := newTestQuarantinePool(t)
	ctx := context.Background()

	id, err := insertQuarantine(ctx, pool, "abc123", "payload.sh", "/home/user/Downloads/payload.sh", "Suspicious", 0.45)
	if err != nil {
		t.Fatalf("insertQuarantine: %v", err)
	}
	if _, err := decideQuarantine(ctx, pool, id, "rejected"); err != nil {
		t.Fatalf("first decide: %v", err)
	}
	if _, err := decideQuarantine(ctx, pool, id, "approved"); err != pgx.ErrNoRows {
		t.Fatalf("expected pgx.ErrNoRows deciding an already-decided row, got %v", err)
	}
}

func TestGetQuarantineStatus(t *testing.T) {
	pool := newTestQuarantinePool(t)
	ctx := context.Background()

	id, err := insertQuarantine(ctx, pool, "abc123", "payload.sh", "/home/user/Downloads/payload.sh", "Inconclusive", 0.0)
	if err != nil {
		t.Fatalf("insertQuarantine: %v", err)
	}

	status, err := getQuarantineStatus(ctx, pool, id)
	if err != nil {
		t.Fatalf("getQuarantineStatus: %v", err)
	}
	if status != "pending" {
		t.Fatalf("expected pending, got %s", status)
	}

	if _, err := decideQuarantine(ctx, pool, id, "approved"); err != nil {
		t.Fatalf("decideQuarantine: %v", err)
	}
	status, err = getQuarantineStatus(ctx, pool, id)
	if err != nil {
		t.Fatalf("getQuarantineStatus after decide: %v", err)
	}
	if status != "approved" {
		t.Fatalf("expected approved, got %s", status)
	}
}

func TestGetQuarantineStatusNotFound(t *testing.T) {
	pool := newTestQuarantinePool(t)
	if _, err := getQuarantineStatus(context.Background(), pool, 999999); err == nil {
		t.Fatal("expected an error for a nonexistent id")
	}
}
