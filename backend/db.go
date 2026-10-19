package main

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"sort"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"
)

// NewPool opens a connection pool against databaseURL and confirms it's
// reachable. The pool lives for the process lifetime (no graceful shutdown
// today, matching DockerManager's client).
func NewPool(ctx context.Context, databaseURL string) (*pgxpool.Pool, error) {
	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		return nil, fmt.Errorf("open pool: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping: %w", err)
	}
	return pool, nil
}

// roleCredentials extracts the username/password embedded in a connection
// URL, so a migration can bootstrap the exact role the runtime pool will
// later connect as, without a separate password env var to keep in sync.
func roleCredentials(databaseURL string) (username, password string, err error) {
	u, err := url.Parse(databaseURL)
	if err != nil {
		return "", "", fmt.Errorf("parse database url: %w", err)
	}
	if u.User == nil {
		return "", "", fmt.Errorf("database url has no credentials")
	}
	pw, _ := u.User.Password()
	return u.User.Username(), pw, nil
}

// RunMigrations applies every *.sql file in dir, in filename order, not yet
// recorded in schema_migrations. adminURL must have CREATE/GRANT privileges;
// runtimeURL's own role/password are substituted for {{ROLE_NAME}}/
// {{ROLE_PASSWORD}} placeholders so a migration can bootstrap that role.
func RunMigrations(ctx context.Context, adminURL, runtimeURL, dir string) error {
	roleName, rolePassword, err := roleCredentials(runtimeURL)
	if err != nil {
		return fmt.Errorf("extract runtime role credentials: %w", err)
	}

	pool, err := pgxpool.New(ctx, adminURL)
	if err != nil {
		return fmt.Errorf("open admin pool: %w", err)
	}
	defer pool.Close()

	if _, err := pool.Exec(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (version TEXT PRIMARY KEY, applied_at TIMESTAMPTZ NOT NULL DEFAULT now())`); err != nil {
		return fmt.Errorf("create schema_migrations: %w", err)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("read migrations dir: %w", err)
	}
	var files []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".sql") {
			files = append(files, e.Name())
		}
	}
	sort.Strings(files)

	for _, name := range files {
		var applied bool
		if err := pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE version = $1)`, name).Scan(&applied); err != nil {
			return fmt.Errorf("check migration %s: %w", name, err)
		}
		if applied {
			continue
		}
		raw, err := os.ReadFile(dir + "/" + name)
		if err != nil {
			return fmt.Errorf("read %s: %w", name, err)
		}
		sql := strings.NewReplacer(
			"{{ROLE_NAME}}", roleName,
			"{{ROLE_PASSWORD}}", rolePassword,
		).Replace(string(raw))

		tx, err := pool.Begin(ctx)
		if err != nil {
			return fmt.Errorf("begin tx for %s: %w", name, err)
		}
		if _, err := tx.Exec(ctx, sql); err != nil {
			tx.Rollback(ctx)
			return fmt.Errorf("apply %s: %w", name, err)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO schema_migrations (version) VALUES ($1)`, name); err != nil {
			tx.Rollback(ctx)
			return fmt.Errorf("record %s: %w", name, err)
		}
		if err := tx.Commit(ctx); err != nil {
			return fmt.Errorf("commit %s: %w", name, err)
		}
	}
	return nil
}
