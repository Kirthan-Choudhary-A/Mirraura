package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func testAdminURL(t *testing.T) string {
	t.Helper()
	url := os.Getenv("MIRRAURA_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("MIRRAURA_TEST_DATABASE_URL not set; skipping Postgres-backed test")
	}
	return url
}

func writeMigration(t *testing.T, dir, name, sql string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(sql), 0644); err != nil {
		t.Fatalf("write migration %s: %v", name, err)
	}
}

func TestRunMigrationsAppliesInOrderAndIsIdempotent(t *testing.T) {
	adminURL := testAdminURL(t)
	runtimeURL := "postgres://db_test_role:db_test_pw@localhost:5432/mirraura"
	dir := t.TempDir()
	writeMigration(t, dir, "0001_role.sql", `
DO $$ BEGIN
  EXECUTE 'CREATE ROLE {{ROLE_NAME}} LOGIN PASSWORD ''{{ROLE_PASSWORD}}''';
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;
CREATE TABLE IF NOT EXISTS db_test_table (id INT PRIMARY KEY);
GRANT SELECT, INSERT ON db_test_table TO {{ROLE_NAME}};
`)
	ctx := context.Background()

	if err := RunMigrations(ctx, adminURL, runtimeURL, dir); err != nil {
		t.Fatalf("first run: %v", err)
	}
	// Second run must not error on "role already exists" / re-applying.
	if err := RunMigrations(ctx, adminURL, runtimeURL, dir); err != nil {
		t.Fatalf("second run (idempotency): %v", err)
	}

	pool, err := NewPool(ctx, adminURL)
	if err != nil {
		t.Fatalf("NewPool: %v", err)
	}
	defer pool.Close()
	defer pool.Exec(ctx, "DROP TABLE IF EXISTS db_test_table; DROP ROLE IF EXISTS db_test_role; DELETE FROM schema_migrations WHERE version = '0001_role.sql';")

	var applied int
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM schema_migrations WHERE version = '0001_role.sql'").Scan(&applied); err != nil {
		t.Fatalf("query schema_migrations: %v", err)
	}
	if applied != 1 {
		t.Fatalf("expected migration recorded exactly once, got %d", applied)
	}
}

func TestNewPoolFailsFastOnBadURL(t *testing.T) {
	_, err := NewPool(context.Background(), "postgres://nope:nope@127.0.0.1:1/doesnotexist")
	if err == nil {
		t.Fatal("expected an error connecting to an unreachable database")
	}
}
