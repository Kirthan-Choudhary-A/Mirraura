# Postgres Migration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Move all four of Mirraura's flat-file/in-memory data stores (sessions, users, known-bad hashes, audit log) to Postgres, add runtime user management, and give the audit log real tamper protection via a restricted DB role.

**Architecture:** Go backend and Python verdict-engine each get their own Postgres connection pair (an admin URL for migrations, a least-privilege-role URL for runtime traffic) against one shared Postgres instance. Each service keeps owning its own tables — no cross-service table access. Migrations are plain numbered `.sql` files applied by a small runner at startup.

**Tech Stack:** Postgres 16 (docker-compose `postgres` service), `github.com/jackc/pgx/v5` (Go), `psycopg[binary]` v3 (Python).

**Spec:** `docs/superpowers/specs/2026-10-19-postgres-migration-design.md`

## Global Constraints

- Each service connects as its own restricted role (`backend_role`, `verdict_role`) for runtime traffic — never as the migration-time admin role.
- `verdict_role` gets no `UPDATE`/`DELETE` grant on `audit_log` — enforced by Postgres, not application code.
- No flat-file data import — fresh tables (confirmed: demo/test data, not worth the import-script risk).
- Fail fast (don't start serving) if Postgres is unreachable or migrations fail at startup.
- No new migration framework (golang-migrate/alembic) — plain `.sql` files + a small tracking table.
- Tests run against a real test Postgres instance (connection string via env var), matching this project's existing convention of testing against real infrastructure.

## Review Focus

- A second concurrent approve/reject call on the same hash must not corrupt state — today's `threading.Lock()` serializes this in-process; Postgres must do the equivalent.
- `verdict_role` attempting `UPDATE`/`DELETE` on `audit_log` directly must fail with a Postgres permission error — this is the whole point of the migration's security improvement, so it needs its own explicit test, not just an assumption.
- Running the same migration file twice (restart, redeploy) must not crash on "role already exists" or "table already exists."
- Deleting or demoting the last remaining admin user must be rejected — otherwise an admin can lock everyone out of the admin role entirely.
- An expired session token must stop authenticating exactly at its expiry boundary, and the cleanup job must actually remove expired rows (not just make them unusable).

---

### Task 1: Postgres service in docker-compose

**Files:**
- Modify: `docker-compose.yml`
- Modify: `.env.example`

**Interfaces:**
- Produces: a reachable Postgres at `postgres:5432` inside the compose network, superuser `postgres`/`${POSTGRES_PASSWORD}`, database `mirraura`.

- [ ] **Step 1: Add the postgres service**

Add to `docker-compose.yml`, alongside the existing services:

```yaml
  postgres:
    image: postgres:16-alpine
    environment:
      - POSTGRES_USER=postgres
      - POSTGRES_PASSWORD=${POSTGRES_PASSWORD}
      - POSTGRES_DB=mirraura
    volumes:
      - postgres-data:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U postgres"]
      interval: 5s
      timeout: 5s
      retries: 10
```

Add `postgres-data:` under the top-level `volumes:` key (alongside the existing `audit-log-data:`).

In the `backend` service, replace its existing list-form `depends_on: - verdict-engine` with the map form needed to add a health condition:
```yaml
    depends_on:
      verdict-engine:
        condition: service_started
      postgres:
        condition: service_healthy
```

In the `verdict-engine` service (which has no `depends_on` today), add:
```yaml
    depends_on:
      postgres:
        condition: service_healthy
```

Add these env vars to both `backend` and `verdict-engine` services' `environment:` blocks:

```yaml
      - BACKEND_DATABASE_URL=postgres://backend_role:${BACKEND_DB_PASSWORD}@postgres:5432/mirraura
      - BACKEND_MIGRATIONS_DATABASE_URL=postgres://postgres:${POSTGRES_PASSWORD}@postgres:5432/mirraura
```
(for `verdict-engine`, use `VERDICT_DATABASE_URL`/`VERDICT_MIGRATIONS_DATABASE_URL` and `verdict_role`/`${VERDICT_DB_PASSWORD}` instead).

- [ ] **Step 2: Document the new env vars**

Add to `.env.example`:

```
# Postgres (all four data stores live here now)
POSTGRES_PASSWORD=
BACKEND_DB_PASSWORD=
VERDICT_DB_PASSWORD=
```

- [ ] **Step 3: Verify it starts**

Run: `docker compose up -d postgres` then `docker compose exec postgres pg_isready -U postgres`
Expected: `accepting connections`

- [ ] **Step 4: Commit**

```bash
git add docker-compose.yml .env.example
git commit -m "chore: add postgres service to docker-compose"
```

---

### Task 2: Go — connection pool and migration runner

**Files:**
- Create: `backend/db.go`
- Test: `backend/db_test.go`

**Interfaces:**
- Produces: `NewPool(ctx context.Context, databaseURL string) (*pgxpool.Pool, error)`, `RunMigrations(ctx context.Context, adminURL, runtimeURL, dir string) error`.

- [ ] **Step 1: Add the pgx dependency**

Run: `cd backend && go get github.com/jackc/pgx/v5/pgxpool`

- [ ] **Step 2: Write the failing tests**

```go
// backend/db_test.go
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
	defer pool.Exec(ctx, "DROP TABLE IF EXISTS db_test_table; DROP ROLE IF EXISTS db_test_role;")

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
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `docker compose up -d postgres && MIRRAURA_TEST_DATABASE_URL="postgres://postgres:$POSTGRES_PASSWORD@localhost:5432/mirraura" go test ./backend/... -run TestRunMigrations -v`
Expected: FAIL — `RunMigrations`/`NewPool` not defined.

- [ ] **Step 4: Implement `backend/db.go`**

```go
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
```

- [ ] **Step 5: Run tests to verify they pass**

Run: same command as Step 3
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add backend/db.go backend/db_test.go backend/go.mod backend/go.sum
git commit -m "feat: Postgres connection pool and migration runner"
```

---

### Task 3: Go — sessions table, SessionStore rewrite, and initial Postgres wiring in main.go

**Files:**
- Create: `backend/migrations/0001_create_sessions.sql`
- Modify: `backend/session.go`
- Modify: `backend/session_test.go`
- Modify: `backend/auth_handlers.go` (call-site updates)
- Modify: `backend/auth_handlers_test.go` (its `NewSessionStore()` calls now need a pool)
- Modify: `backend/main.go` (create the Postgres pool, run migrations, construct `NewSessionStore(pool)`, add the session-cleanup ticker — the rest of `main()`/`newMux` stays untouched until Task 4, since `loadUsers()`/`users`/`newMux`'s signature don't change here)
- Modify: `backend/Dockerfile`

**Interfaces:**
- Consumes: `NewPool`, `RunMigrations` (Task 2).
- Produces: `NewSessionStore(pool *pgxpool.Pool) *SessionStore`, `(*SessionStore).Create(ctx, username, role string) (string, error)`, `.Get(ctx, token string) (Session, bool)`, `.Delete(ctx, token string)`, `.CleanupExpired(ctx) error`.

**Why main.go changes land here, not in a separate task:** `NewSessionStore()` takes no arguments today; once it requires a `*pgxpool.Pool`, every caller — including `main.go` and `auth_handlers_test.go` — needs one immediately, or the package stops compiling. Deferring that wiring to a later task would leave `go build`/`go test` broken for this task and the next, which breaks every other task's own test run too (Go compiles a whole package together; a broken `main.go` fails `go test ./backend/...` regardless of which test you target). `loadUsers()`/`users`/`newMux`'s signature are untouched here specifically so this task is the smallest compiling slice — Task 4 is the one that changes those, for the same compiling-slice reason.

- [ ] **Step 1: Write the migration**

```sql
-- backend/migrations/0001_create_sessions.sql
DO $$ BEGIN
  EXECUTE 'CREATE ROLE {{ROLE_NAME}} LOGIN PASSWORD ''{{ROLE_PASSWORD}}''';
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

CREATE TABLE IF NOT EXISTS sessions (
  token TEXT PRIMARY KEY,
  username TEXT NOT NULL,
  role TEXT NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL
);

GRANT SELECT, INSERT, UPDATE, DELETE ON sessions TO {{ROLE_NAME}};
```

- [ ] **Step 2: Write the failing tests**

Replace `backend/session_test.go` entirely with:

```go
package main

import (
	"context"
	"testing"
	"time"
)

func newTestSessionStore(t *testing.T) *SessionStore {
	t.Helper()
	adminURL := testAdminURL(t)
	runtimeURL := "postgres://session_test_role:session_test_pw@localhost:5432/mirraura"
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
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `docker compose up -d postgres && MIRRAURA_TEST_DATABASE_URL="postgres://postgres:$POSTGRES_PASSWORD@localhost:5432/mirraura" go test ./backend/... -run TestSessionStore -v`
Expected: FAIL — `NewSessionStore` signature mismatch / `store.pool` undefined.

- [ ] **Step 4: Rewrite `backend/session.go`**

```go
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

type Session struct {
	Username string
	Role     string
}

const sessionTTL = 8 * time.Hour

// SessionStore persists sessions in Postgres so the backend can run as more
// than one instance -- replaces the old in-memory map, which lost every
// session on restart and only ever worked for exactly one process.
type SessionStore struct {
	pool *pgxpool.Pool
}

func NewSessionStore(pool *pgxpool.Pool) *SessionStore {
	return &SessionStore{pool: pool}
}

func (s *SessionStore) Create(ctx context.Context, username, role string) (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	token := hex.EncodeToString(b)
	_, err := s.pool.Exec(ctx,
		`INSERT INTO sessions (token, username, role, expires_at) VALUES ($1, $2, $3, $4)`,
		token, username, role, time.Now().Add(sessionTTL),
	)
	if err != nil {
		return "", err
	}
	return token, nil
}

func (s *SessionStore) Get(ctx context.Context, token string) (Session, bool) {
	var sess Session
	var expiresAt time.Time
	err := s.pool.QueryRow(ctx,
		`SELECT username, role, expires_at FROM sessions WHERE token = $1`, token,
	).Scan(&sess.Username, &sess.Role, &expiresAt)
	if err != nil {
		return Session{}, false
	}
	if time.Now().After(expiresAt) {
		s.pool.Exec(ctx, `DELETE FROM sessions WHERE token = $1`, token)
		return Session{}, false
	}
	s.pool.Exec(ctx, `UPDATE sessions SET expires_at = $1 WHERE token = $2`, time.Now().Add(sessionTTL), token)
	return sess, true
}

func (s *SessionStore) Delete(ctx context.Context, token string) {
	s.pool.Exec(ctx, `DELETE FROM sessions WHERE token = $1`, token)
}

// CleanupExpired deletes every expired session row. Call on a periodic
// ticker (see main.go) -- Postgres never does this on its own.
func (s *SessionStore) CleanupExpired(ctx context.Context) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM sessions WHERE expires_at < now()`)
	return err
}
```

- [ ] **Step 5: Update call sites in `backend/auth_handlers.go`**

In `requireAuth`, change `sess, ok := store.Get(cookie.Value)` to `sess, ok := store.Get(r.Context(), cookie.Value)`.

In `loginHandler`, change:
```go
			token := store.Create(user.Username, user.Role)
```
to:
```go
			token, err := store.Create(r.Context(), user.Username, user.Role)
			if err != nil {
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
```

In `logoutHandler`, change `store.Delete(cookie.Value)` to `store.Delete(r.Context(), cookie.Value)`.

- [ ] **Step 6: Update `backend/auth_handlers_test.go`'s `NewSessionStore()` calls**

`NewSessionStore` now requires a pool. Add this helper near the top of the file (after the existing imports) and use it everywhere `NewSessionStore()` was called bare:

```go
func testAuthPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	adminURL := testAdminURL(t)
	runtimeURL := "postgres://auth_test_role:auth_test_pw@localhost:5432/mirraura"
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
	return pool
}
```

Add `"context"` and `"github.com/jackc/pgx/v5/pgxpool"` to the file's import block (`"context"` may already be pulled in transitively by other test files in the package, but import it explicitly here since this file now uses it directly).

In `testMux`, change:
```go
	return newMux(nil, "http://unused", hub, mon, NewSessionStore(), testUsers(t), NewLoginLimiter())
```
to:
```go
	return newMux(nil, "http://unused", hub, mon, NewSessionStore(testAuthPool(t)), testUsers(t), NewLoginLimiter())
```

Do the same replacement (`NewSessionStore()` → `NewSessionStore(testAuthPool(t))`) in the other four inline `newMux(...)` calls: `TestAnalystGets403OnHashApprove`, `TestAdminCanApproveHash`, `TestWebSocketRejectedWithoutCookie`, `TestWebSocketAcceptedWithValidCookie`. `newMux`'s own signature and the `users`/`testUsers(t)` argument are untouched in this task — only the `SessionStore` construction changes.

- [ ] **Step 7: Wire the Postgres pool into `backend/main.go`**

Replace the start of `main()`:
```go
func main() {
	if len(os.Getenv("MIRRAURA_ADMIN_PASSWORD")) < 12 {
		log.Fatal("MIRRAURA_ADMIN_PASSWORD must be set and at least 12 characters")
	}
	users, err := loadUsers()
	if err != nil {
		log.Fatalf("loadUsers: %v", err)
	}
```
with:
```go
func main() {
	ctx := context.Background()

	backendDBURL := os.Getenv("BACKEND_DATABASE_URL")
	backendMigrationsURL := os.Getenv("BACKEND_MIGRATIONS_DATABASE_URL")
	if backendDBURL == "" || backendMigrationsURL == "" {
		log.Fatal("BACKEND_DATABASE_URL and BACKEND_MIGRATIONS_DATABASE_URL must both be set")
	}
	if err := RunMigrations(ctx, backendMigrationsURL, backendDBURL, "migrations"); err != nil {
		log.Fatalf("RunMigrations: %v", err)
	}
	pool, err := NewPool(ctx, backendDBURL)
	if err != nil {
		log.Fatalf("NewPool: %v", err)
	}

	if len(os.Getenv("MIRRAURA_ADMIN_PASSWORD")) < 12 {
		log.Fatal("MIRRAURA_ADMIN_PASSWORD must be set and at least 12 characters")
	}
	users, err := loadUsers()
	if err != nil {
		log.Fatalf("loadUsers: %v", err)
	}
```
(`loadUsers()`/`users` stay exactly as they are today — Task 4 replaces them. This step only adds the pool.)

Change:
```go
	initCtx, initCancel := context.WithTimeout(context.Background(), 10*time.Second)
```
to:
```go
	initCtx, initCancel := context.WithTimeout(ctx, 10*time.Second)
```

Change:
```go
	store := NewSessionStore()
```
to:
```go
	store := NewSessionStore(pool)
```

Add a second periodic-ticker goroutine right after the existing monitor-tick one (same function, just add this block after it, before the `port := os.Getenv("BACKEND_PORT")` line):
```go
	go func() {
		ticker := time.NewTicker(1 * time.Hour)
		defer ticker.Stop()
		for range ticker.C {
			cleanupCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			if err := store.CleanupExpired(cleanupCtx); err != nil {
				log.Printf("session cleanup failed: %v", err)
			}
			cancel()
		}
	}()
```

- [ ] **Step 8: Add migrations to the Docker image**

In `backend/Dockerfile`'s final stage, add a line copying the migrations directory:

```dockerfile
FROM alpine:3.19
WORKDIR /app
COPY --from=build /app/backend .
COPY migrations/ ./migrations
EXPOSE 8080
CMD ["./backend"]
```

- [ ] **Step 9: Run tests to verify they pass**

Run: same command as Step 3, plus the full package to confirm `main.go`/`auth_handlers_test.go` still compile: `MIRRAURA_TEST_DATABASE_URL="postgres://postgres:$POSTGRES_PASSWORD@localhost:5432/mirraura" go test ./backend/... -v`
Expected: PASS (this also runs the pre-existing `auth_handlers_test.go` suite against real Postgres now, instead of the old in-memory store).

- [ ] **Step 10: Commit**

```bash
git add backend/migrations/0001_create_sessions.sql backend/session.go backend/session_test.go backend/auth_handlers.go backend/auth_handlers_test.go backend/main.go backend/Dockerfile
git commit -m "feat: move session store to Postgres"
```

---

### Task 4: Go — users table, runtime user management, and final main.go/newMux rewire

**Files:**
- Create: `backend/migrations/0002_create_users.sql`
- Create: `backend/user_handlers.go`
- Test: `backend/user_handlers_test.go`
- Modify: `backend/users.go`
- Modify: `backend/users_test.go`
- Modify: `backend/auth_handlers.go` (login now uses `GetUser`, not a map)
- Modify: `backend/auth_handlers_test.go` (final rewire: `newMux` stops taking a `users` map)
- Modify: `backend/main.go` (final rewire: `SeedUsers` replaces `loadUsers`, `newMux`'s signature changes, new `/api/users*` routes)

**Interfaces:**
- Consumes: `NewPool`, `RunMigrations` (Task 2); `NewSessionStore` (Task 3).
- Produces: `SeedUsers(ctx, pool) error`, `GetUser(ctx, pool, username) (User, error)`, `ListUsers(ctx, pool) ([]User, error)`, HTTP routes `GET /api/users`, `POST /api/users`, `DELETE /api/users/{username}`, `PATCH /api/users/{username}/role` (all admin-only).

**Design note:** `users.json` and the admin env vars become a **one-time seed**, not a continuously-reloaded source — otherwise a restart would re-insert users a runtime admin action just removed. Seeding uses `INSERT ... ON CONFLICT (username) DO NOTHING`.

**Why this task absorbs what might look like three separate concerns (users table, runtime endpoints, main.go rewire):** removing the `users map[string]User` from `main()` (a direct consequence of moving users to Postgres) forces `newMux` and `loginHandler` to stop taking that map in the same change — there is no intermediate state where `main.go` has no `users` variable but `newMux`/`loginHandler` still expect one and the package still compiles. Splitting this across tasks would leave `go build`/`go test` broken between them, the same reasoning Task 3 used to justify absorbing its own main.go wiring.

**Review Focus item owned here:** deleting or demoting the last remaining admin must be rejected.

- [ ] **Step 1: Write the migration**

```sql
-- backend/migrations/0002_create_users.sql
CREATE TABLE IF NOT EXISTS users (
  username TEXT PRIMARY KEY,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL CHECK (role IN ('admin', 'analyst'))
);

GRANT SELECT, INSERT, UPDATE, DELETE ON users TO {{ROLE_NAME}};
```

- [ ] **Step 2: Write the failing tests for `users.go`**

Replace `backend/users_test.go` entirely with:

```go
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
	runtimeURL := "postgres://users_test_role:users_test_pw@localhost:5432/mirraura"
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
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `MIRRAURA_TEST_DATABASE_URL="postgres://postgres:$POSTGRES_PASSWORD@localhost:5432/mirraura" go test ./backend/... -run "TestSeedUsers" -v`
Expected: FAIL — `SeedUsers`/`GetUser` not defined.

- [ ] **Step 4: Rewrite `backend/users.go`**

```go
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/jackc/pgx/v5/pgxpool"
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

// SeedUsers inserts the env-seeded admin and any optional users.json entries
// into the users table, skipping any username that already exists -- a
// one-time seed, not a continuous reload, so a runtime admin action
// (promote/demote/remove) survives a restart.
func SeedUsers(ctx context.Context, pool *pgxpool.Pool) error {
	adminUser := os.Getenv("MIRRAURA_ADMIN_USER")
	adminPassword := os.Getenv("MIRRAURA_ADMIN_PASSWORD")
	if adminUser == "" {
		return fmt.Errorf("MIRRAURA_ADMIN_USER must be set")
	}
	if len(adminPassword) < 12 {
		return fmt.Errorf("MIRRAURA_ADMIN_PASSWORD must be at least 12 characters")
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(adminPassword), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("hash admin password: %w", err)
	}
	if err := upsertUserIfAbsent(ctx, pool, adminUser, string(hash), "admin"); err != nil {
		return fmt.Errorf("seed admin: %w", err)
	}

	usersPath := os.Getenv("MIRRAURA_USERS_PATH")
	if usersPath == "" {
		return nil
	}
	data, err := os.ReadFile(usersPath)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read %s: %w", usersPath, err)
	}
	var entries []userJSONEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		return fmt.Errorf("parse %s: %w", usersPath, err)
	}
	for _, e := range entries {
		if e.Role != "admin" && e.Role != "analyst" {
			return fmt.Errorf("%s: user %q has invalid role %q (must be admin or analyst)", usersPath, e.Username, e.Role)
		}
		if err := upsertUserIfAbsent(ctx, pool, e.Username, e.BcryptHash, e.Role); err != nil {
			return fmt.Errorf("seed %s: %w", e.Username, err)
		}
	}
	return nil
}

func upsertUserIfAbsent(ctx context.Context, pool *pgxpool.Pool, username, passwordHash, role string) error {
	_, err := pool.Exec(ctx,
		`INSERT INTO users (username, password_hash, role) VALUES ($1, $2, $3) ON CONFLICT (username) DO NOTHING`,
		username, passwordHash, role,
	)
	return err
}

func GetUser(ctx context.Context, pool *pgxpool.Pool, username string) (User, error) {
	var u User
	u.Username = username
	err := pool.QueryRow(ctx, `SELECT password_hash, role FROM users WHERE username = $1`, username).Scan(&u.PasswordHash, &u.Role)
	return u, err
}

func ListUsers(ctx context.Context, pool *pgxpool.Pool) ([]User, error) {
	rows, err := pool.Query(ctx, `SELECT username, password_hash, role FROM users ORDER BY username`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var users []User
	for rows.Next() {
		var u User
		if err := rows.Scan(&u.Username, &u.PasswordHash, &u.Role); err != nil {
			return nil, err
		}
		users = append(users, u)
	}
	return users, rows.Err()
}
```

- [ ] **Step 5: Run the users tests to verify they pass**

Run: same command as Step 3
Expected: PASS

- [ ] **Step 6: Write the failing tests for the runtime user-management endpoints**

```go
// backend/user_handlers_test.go
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
	runtimeURL := "postgres://user_handlers_test_role:user_handlers_test_pw@localhost:5432/mirraura"
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
```

- [ ] **Step 7: Run tests to verify they fail**

Run: `MIRRAURA_TEST_DATABASE_URL="postgres://postgres:$POSTGRES_PASSWORD@localhost:5432/mirraura" go test ./backend/... -run "TestCreateUserHandler|TestDeleteUserHandlerRejectsLastAdmin|TestUpdateUserRoleHandlerRejectsDemotingLastAdmin" -v`
Expected: FAIL — handlers not defined.

- [ ] **Step 8: Implement `backend/user_handlers.go`**

```go
package main

import (
	"encoding/json"
	"net/http"

	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/bcrypt"
)

func listUsersHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		users, err := ListUsers(r.Context(), pool)
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		type userView struct {
			Username string `json:"username"`
			Role     string `json:"role"`
		}
		views := make([]userView, 0, len(users))
		for _, u := range users {
			views = append(views, userView{Username: u.Username, Role: u.Role})
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(views)
	}
}

type createUserRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Role     string `json:"role"`
}

func createUserHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req createUserRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return
		}
		if req.Role != "admin" && req.Role != "analyst" {
			http.Error(w, "role must be admin or analyst", http.StatusBadRequest)
			return
		}
		if len(req.Password) < 12 {
			http.Error(w, "password must be at least 12 characters", http.StatusBadRequest)
			return
		}
		hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		_, err = pool.Exec(r.Context(),
			`INSERT INTO users (username, password_hash, role) VALUES ($1, $2, $3)`,
			req.Username, string(hash), req.Role,
		)
		if err != nil {
			http.Error(w, "username already exists", http.StatusConflict)
			return
		}
		w.WriteHeader(http.StatusOK)
	}
}

// countAdmins is used by both the delete and role-update handlers to refuse
// an action that would leave zero admins.
func countAdmins(r *http.Request, pool *pgxpool.Pool) (int, error) {
	var n int
	err := pool.QueryRow(r.Context(), `SELECT count(*) FROM users WHERE role = 'admin'`).Scan(&n)
	return n, err
}

func deleteUserHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		username := r.PathValue("username")
		target, err := GetUser(r.Context(), pool, username)
		if err != nil {
			http.Error(w, "user not found", http.StatusNotFound)
			return
		}
		if target.Role == "admin" {
			n, err := countAdmins(r, pool)
			if err != nil {
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
			if n <= 1 {
				http.Error(w, "cannot remove the last admin", http.StatusConflict)
				return
			}
		}
		if _, err := pool.Exec(r.Context(), `DELETE FROM users WHERE username = $1`, username); err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

type updateRoleRequest struct {
	Role string `json:"role"`
}

func updateUserRoleHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		username := r.PathValue("username")
		var req updateRoleRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return
		}
		if req.Role != "admin" && req.Role != "analyst" {
			http.Error(w, "role must be admin or analyst", http.StatusBadRequest)
			return
		}
		target, err := GetUser(r.Context(), pool, username)
		if err != nil {
			http.Error(w, "user not found", http.StatusNotFound)
			return
		}
		if target.Role == "admin" && req.Role == "analyst" {
			n, err := countAdmins(r, pool)
			if err != nil {
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
			if n <= 1 {
				http.Error(w, "cannot demote the last admin", http.StatusConflict)
				return
			}
		}
		if _, err := pool.Exec(r.Context(), `UPDATE users SET role = $1 WHERE username = $2`, req.Role, username); err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}
```

- [ ] **Step 9: Update `loginHandler` to use `GetUser` instead of a map**

In `backend/auth_handlers.go`, change `loginHandler`'s signature from `func loginHandler(store *SessionStore, users map[string]User, limiter *LoginLimiter) http.HandlerFunc` to `func loginHandler(store *SessionStore, pool *pgxpool.Pool, limiter *LoginLimiter) http.HandlerFunc`, and replace:
```go
		user, ok := users[req.Username]
		hash := dummyPasswordHash
		if ok {
			hash = []byte(user.PasswordHash)
		}
```
with:
```go
		user, err := GetUser(r.Context(), pool, req.Username)
		ok := err == nil
		hash := dummyPasswordHash
		if ok {
			hash = []byte(user.PasswordHash)
		}
```
Add the `"github.com/jackc/pgx/v5/pgxpool"` import to `backend/auth_handlers.go`.

- [ ] **Step 10: Rewrite `main()` and `newMux` in `backend/main.go`**

Replace the `users, err := loadUsers()` block (added in Task 3 Step 7) with `SeedUsers`:
```go
	if err := SeedUsers(ctx, pool); err != nil {
		log.Fatalf("SeedUsers: %v", err)
	}
```
(delete the `if len(os.Getenv("MIRRAURA_ADMIN_PASSWORD")) < 12 { ... }` check and the `users, err := loadUsers() ...` block entirely — `SeedUsers` does the equivalent validation itself).

Change:
```go
	mux := newMux(dm, verdictEngineURL, hub, mon, store, users, limiter)
```
to:
```go
	mux := newMux(dm, verdictEngineURL, hub, mon, store, pool, limiter)
```

Replace `newMux`'s signature and body entirely:
```go
func newMux(dm *DockerManager, verdictEngineURL string, hub *Hub, mon *Monitor, store *SessionStore, pool *pgxpool.Pool, limiter *LoginLimiter) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/health", healthHandler)
	mux.HandleFunc("/api/login", loginHandler(store, pool, limiter))
	mux.Handle("/api/logout", requireAuth(store)(logoutHandler(store)))
	mux.Handle("/api/me", requireAuth(store)(meHandler()))
	mux.Handle("/api/samples", requireAuth(store)(samplesHandler(dm, verdictEngineURL, hub)))
	mux.Handle("/api/verdicts", requireAuth(store)(verdictsListHandler(verdictEngineURL)))
	mux.Handle("/api/verdicts/", requireAuth(store)(verdictDetailHandler(verdictEngineURL)))
	mux.Handle("/api/audit/verify", requireAuth(store)(chainVerifyHandler(verdictEngineURL)))
	mux.Handle("/api/live", requireAuth(store)(http.HandlerFunc(hub.HandleWS)))
	mux.Handle("/api/monitor/status", requireAuth(store)(monitorStatusHandler(mon)))
	mux.Handle("/api/monitor/reconnect", requireAuth(store)(requireRole("admin")(monitorReconnectHandler(mon))))
	mux.Handle("/api/hashes", requireAuth(store)(hashesHandler(verdictEngineURL)))
	mux.Handle("/api/hashes/", requireAuth(store)(requireRole("admin")(hashDecisionHandler(verdictEngineURL))))
	mux.Handle("/api/users", requireAuth(store)(requireRole("admin")(dispatchByMethod(map[string]http.HandlerFunc{
		http.MethodGet:  listUsersHandler(pool),
		http.MethodPost: createUserHandler(pool),
	}))))
	mux.Handle("/api/users/{username}", requireAuth(store)(requireRole("admin")(dispatchByMethod(map[string]http.HandlerFunc{
		http.MethodDelete: deleteUserHandler(pool),
	}))))
	mux.Handle("/api/users/{username}/role", requireAuth(store)(requireRole("admin")(dispatchByMethod(map[string]http.HandlerFunc{
		http.MethodPatch: updateUserRoleHandler(pool),
	}))))
	return mux
}

// dispatchByMethod routes to the handler registered for r.Method, or 405.
func dispatchByMethod(byMethod map[string]http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		h, ok := byMethod[r.Method]
		if !ok {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		h(w, r)
	}
}
```

Add `"github.com/jackc/pgx/v5/pgxpool"` to `main.go`'s import block.

- [ ] **Step 11: Rewrite `backend/auth_handlers_test.go`'s user-seeding helper and every `newMux` call site**

`newMux` no longer takes a `users` map, so `testUsers(t)` (which built that map) and every call site passing it need to change. Replace `testUsers(t)` entirely with a helper that seeds real rows into the pool `testAuthPool` (added in Task 3) already migrates:

```go
func seedTestUsers(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	ctx := context.Background()
	adminHash, err := bcrypt.GenerateFromPassword([]byte("adminpassword123"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("GenerateFromPassword: %v", err)
	}
	analystHash, err := bcrypt.GenerateFromPassword([]byte("analystpassword123"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("GenerateFromPassword: %v", err)
	}
	if _, err := pool.Exec(ctx, "INSERT INTO users (username, password_hash, role) VALUES ('admin', $1, 'admin')", string(adminHash)); err != nil {
		t.Fatalf("seed admin: %v", err)
	}
	if _, err := pool.Exec(ctx, "INSERT INTO users (username, password_hash, role) VALUES ('analyst', $1, 'analyst')", string(analystHash)); err != nil {
		t.Fatalf("seed analyst: %v", err)
	}
	t.Cleanup(func() {
		pool.Exec(ctx, "DELETE FROM users")
	})
}
```

Change `testMux`:
```go
func testMux(t *testing.T) *http.ServeMux {
	t.Helper()
	pool := testAuthPool(t)
	seedTestUsers(t, pool)
	hub := NewHub()
	mon := NewMonitor(&fakeMonitorDocker{}, "http://unused", hub)
	return newMux(nil, "http://unused", hub, mon, NewSessionStore(pool), pool, NewLoginLimiter())
}
```

In each of the four tests that build their own mux inline (`TestAnalystGets403OnHashApprove`, `TestAdminCanApproveHash`, `TestWebSocketRejectedWithoutCookie`, `TestWebSocketAcceptedWithValidCookie`), change (this is the Task-3-modified text — Task 3 Step 6 already changed the bare `NewSessionStore()` in these same four lines to `NewSessionStore(testAuthPool(t))`; this step is what finally removes `testUsers(t)`):
```go
	mux := newMux(nil, fakeEngine.URL, hub, mon, NewSessionStore(testAuthPool(t)), testUsers(t), NewLoginLimiter())
```
(or the `"http://unused"` variant) to:
```go
	pool := testAuthPool(t)
	seedTestUsers(t, pool)
	mux := newMux(nil, fakeEngine.URL, hub, mon, NewSessionStore(pool), pool, NewLoginLimiter())
```
(substituting `"http://unused"` for `fakeEngine.URL` in the two WebSocket tests, matching what each already passes today).

- [ ] **Step 12: Run the full backend suite**

Run: `cd backend && go build ./...`
Expected: clean build.

Run: `MIRRAURA_TEST_DATABASE_URL="postgres://postgres:$POSTGRES_PASSWORD@localhost:5432/mirraura" go test ./... -v`
Expected: all tests PASS. This is the first point every pre-existing backend test (not just this task's new ones) runs against the full Postgres-backed stack — surface and fix forward any other stale call site here.

- [ ] **Step 13: Commit**

```bash
git add backend/migrations/0002_create_users.sql backend/user_handlers.go backend/user_handlers_test.go backend/users.go backend/users_test.go backend/auth_handlers.go backend/auth_handlers_test.go backend/main.go
git commit -m "feat: runtime user management, refuse removing the last admin, final Postgres rewire"
```


---

### Task 5: Python — connection pool and migration runner

**Files:**
- Create: `verdict-engine/db.py`
- Test: `verdict-engine/tests/test_db.py`

**Interfaces:**
- Produces: `new_pool(database_url: str) -> ConnectionPool`, `run_migrations(admin_url: str, runtime_url: str, migrations_dir: Path) -> None`.

- [ ] **Step 1: Add the psycopg dependency**

Add to `verdict-engine/requirements.txt`: `psycopg[binary]==3.2.3`

Run: `cd verdict-engine && pip install -r requirements.txt`

- [ ] **Step 2: Write the failing tests**

```python
# verdict-engine/tests/test_db.py
import os
import re
from pathlib import Path

import psycopg
import pytest

from db import new_pool, run_migrations


def _test_admin_url():
    url = os.getenv("MIRRAURA_TEST_DATABASE_URL")
    if not url:
        pytest.skip("MIRRAURA_TEST_DATABASE_URL not set; skipping Postgres-backed test")
    return url


def test_run_migrations_applies_in_order_and_is_idempotent(tmp_path):
    admin_url = _test_admin_url()
    runtime_url = "postgres://db_test_role_py:db_test_pw_py@localhost:5432/mirraura"
    (tmp_path / "0001_role.sql").write_text(
        """
DO $$ BEGIN
  EXECUTE 'CREATE ROLE {{ROLE_NAME}} LOGIN PASSWORD ''{{ROLE_PASSWORD}}''';
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;
CREATE TABLE IF NOT EXISTS db_test_table_py (id INT PRIMARY KEY);
GRANT SELECT, INSERT ON db_test_table_py TO {{ROLE_NAME}};
"""
    )

    run_migrations(admin_url, runtime_url, tmp_path)
    run_migrations(admin_url, runtime_url, tmp_path)  # idempotent re-run

    with psycopg.connect(admin_url) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT count(*) FROM schema_migrations WHERE version = %s", ("0001_role.sql",))
            assert cur.fetchone()[0] == 1
            cur.execute("DROP TABLE IF EXISTS db_test_table_py; DROP ROLE IF EXISTS db_test_role_py;")
            conn.commit()


def test_new_pool_fails_fast_on_bad_url():
    with pytest.raises(Exception):
        pool = new_pool("postgres://nope:nope@127.0.0.1:1/doesnotexist")
        pool.connection().__enter__()
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `docker compose up -d postgres && MIRRAURA_TEST_DATABASE_URL="postgres://postgres:$POSTGRES_PASSWORD@localhost:5432/mirraura" pytest tests/test_db.py -v`
Expected: FAIL — `db` module not found.

- [ ] **Step 4: Implement `verdict-engine/db.py`**

```python
from pathlib import Path
from urllib.parse import urlparse

import psycopg
from psycopg_pool import ConnectionPool


def new_pool(database_url: str) -> ConnectionPool:
    """Opens a connection pool against database_url and confirms it's reachable."""
    pool = ConnectionPool(database_url, open=True)
    pool.wait(timeout=5)
    return pool


def _role_credentials(database_url: str) -> tuple[str, str]:
    parsed = urlparse(database_url)
    if not parsed.username:
        raise ValueError("database url has no credentials")
    return parsed.username, parsed.password or ""


def run_migrations(admin_url: str, runtime_url: str, migrations_dir: Path) -> None:
    """Applies every *.sql file in migrations_dir, in filename order, not yet
    recorded in schema_migrations. admin_url must have CREATE/GRANT
    privileges; runtime_url's own role/password are substituted for
    {{ROLE_NAME}}/{{ROLE_PASSWORD}} placeholders so a migration can bootstrap
    that role.
    """
    role_name, role_password = _role_credentials(runtime_url)

    with psycopg.connect(admin_url, autocommit=False) as conn:
        with conn.cursor() as cur:
            cur.execute(
                "CREATE TABLE IF NOT EXISTS schema_migrations "
                "(version TEXT PRIMARY KEY, applied_at TIMESTAMPTZ NOT NULL DEFAULT now())"
            )
        conn.commit()

        files = sorted(p for p in Path(migrations_dir).iterdir() if p.suffix == ".sql")
        for path in files:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE version = %s)",
                    (path.name,),
                )
                already_applied = cur.fetchone()[0]
            if already_applied:
                continue

            sql = path.read_text().replace("{{ROLE_NAME}}", role_name).replace(
                "{{ROLE_PASSWORD}}", role_password
            )
            with conn.cursor() as cur:
                cur.execute(sql)
                cur.execute("INSERT INTO schema_migrations (version) VALUES (%s)", (path.name,))
            conn.commit()
```

- [ ] **Step 5: Run tests to verify they pass**

Run: same command as Step 3
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add verdict-engine/db.py verdict-engine/tests/test_db.py verdict-engine/requirements.txt
git commit -m "feat: Postgres connection pool and migration runner (verdict-engine)"
```

---

### Task 6: Python — known_bad_hashes table and hash_lookup rewrite

**Files:**
- Create: `verdict-engine/migrations/0001_create_known_bad_hashes.sql`
- Modify: `verdict-engine/hash_lookup.py`
- Modify: `verdict-engine/tests/test_hash_lookup.py`
- Modify: `verdict-engine/tests/conftest.py` (remove the flat-file fixture for known-bad hashes; add a Postgres one)

**Interfaces:**
- Consumes: `new_pool`, `run_migrations` (Task 5).
- Produces: `load_known_bad(pool) -> dict`, `check_hash(pool, sample_hash) -> str | None`, `list_hashes(pool) -> list[dict]`, `propose_hash(pool, sample_hash, label, source) -> dict`, `approve_hash(pool, sample_hash) -> dict`, `reject_hash(pool, sample_hash) -> dict`. Same signatures as today, each gaining a leading `pool` parameter.

**Review Focus item owned here:** a second concurrent approve/reject on the same hash must not corrupt state.

**Expected transient breakage:** `tests/test_app.py` imports `app.py` directly and will fail after this task, until Task 8 (wire app.py) lands -- `app.py` still calls the old pre-pool `hash_lookup` signatures until then. This task's own verification command (Step 3 above) is scoped to `tests/test_hash_lookup.py` specifically for this reason; don't treat a `tests/test_app.py` failure here as a regression this task introduced.

- [ ] **Step 1: Write the migration**

```sql
-- verdict-engine/migrations/0001_create_known_bad_hashes.sql
DO $$ BEGIN
  EXECUTE 'CREATE ROLE {{ROLE_NAME}} LOGIN PASSWORD ''{{ROLE_PASSWORD}}''';
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

CREATE TABLE IF NOT EXISTS known_bad_hashes (
  hash TEXT PRIMARY KEY,
  label TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('pending', 'approved', 'rejected')),
  source TEXT NOT NULL,
  proposed_at TIMESTAMPTZ NOT NULL,
  reviewed_at TIMESTAMPTZ
);

GRANT SELECT, INSERT, UPDATE, DELETE ON known_bad_hashes TO {{ROLE_NAME}};
```

- [ ] **Step 2: Write the failing tests**

Replace `verdict-engine/tests/test_hash_lookup.py` entirely with:

```python
import os
import threading

import pytest

import hash_lookup
from db import new_pool, run_migrations
from hash_lookup import (
    HashExistsError,
    HashNotFoundError,
    HashNotPendingError,
    approve_hash,
    check_hash,
    is_valid_hash,
    list_hashes,
    load_known_bad,
    propose_hash,
    reject_hash,
)

EICAR_HASH = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"


@pytest.fixture
def pool():
    admin_url = os.getenv("MIRRAURA_TEST_DATABASE_URL")
    if not admin_url:
        pytest.skip("MIRRAURA_TEST_DATABASE_URL not set; skipping Postgres-backed test")
    runtime_url = "postgres://hash_lookup_test_role:hash_lookup_test_pw@localhost:5432/mirraura"
    run_migrations(admin_url, runtime_url, "migrations")
    p = new_pool(runtime_url)
    propose_hash(p, EICAR_HASH, "EICAR-Test-File", source="manual")
    approve_hash(p, EICAR_HASH)
    yield p
    with p.connection() as conn:
        conn.execute("DELETE FROM known_bad_hashes")
        conn.commit()
    p.close()


def test_known_bad_hash_returns_label(pool):
    assert check_hash(pool, EICAR_HASH) == "EICAR-Test-File"


def test_unknown_hash_returns_none(pool):
    assert check_hash(pool, "0" * 64) is None


def test_propose_hash_rejects_invalid_hash(pool):
    with pytest.raises(ValueError):
        propose_hash(pool, "not-a-hash", "label", source="manual")


def test_propose_hash_rejects_duplicate(pool):
    propose_hash(pool, "1" * 64, "label", source="manual")
    with pytest.raises(HashExistsError):
        propose_hash(pool, "1" * 64, "label", source="manual")


def test_approve_hash_rejects_unknown_hash(pool):
    with pytest.raises(HashNotFoundError):
        approve_hash(pool, "2" * 64)


def test_approve_hash_rejects_already_decided_hash(pool):
    with pytest.raises(HashNotPendingError):
        approve_hash(pool, EICAR_HASH)  # already approved by the fixture


def test_concurrent_decisions_on_same_hash_dont_corrupt_state(pool):
    propose_hash(pool, "3" * 64, "race-test", source="manual")
    results = []

    def decide():
        try:
            approve_hash(pool, "3" * 64)
            results.append("approved")
        except HashNotPendingError:
            results.append("already-decided")

    threads = [threading.Thread(target=decide) for _ in range(5)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert results.count("approved") == 1
    assert results.count("already-decided") == 4
    entries = [e for e in list_hashes(pool) if e["hash"] == "3" * 64]
    assert len(entries) == 1
    assert entries[0]["status"] == "approved"
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `MIRRAURA_TEST_DATABASE_URL="postgres://postgres:$POSTGRES_PASSWORD@localhost:5432/mirraura" pytest tests/test_hash_lookup.py -v`
Expected: FAIL — `hash_lookup` functions don't accept a `pool` argument yet.

- [ ] **Step 4: Rewrite `verdict-engine/hash_lookup.py`**

```python
import re
from datetime import datetime, timezone
from typing import Dict, List, Optional

import psycopg

_HASH_RE = re.compile(r"^[0-9a-f]{64}$")


class HashExistsError(Exception):
    pass


class HashNotFoundError(Exception):
    pass


class HashNotPendingError(Exception):
    pass


def is_valid_hash(value: str) -> bool:
    return bool(_HASH_RE.fullmatch(value))


def load_known_bad(pool) -> Dict[str, str]:
    with pool.connection() as conn:
        rows = conn.execute("SELECT hash, label FROM known_bad_hashes WHERE status = 'approved'").fetchall()
    return {row[0]: row[1] for row in rows}


def check_hash(pool, sample_hash: str) -> Optional[str]:
    with pool.connection() as conn:
        row = conn.execute(
            "SELECT label FROM known_bad_hashes WHERE hash = %s AND status = 'approved'",
            (sample_hash,),
        ).fetchone()
    return row[0] if row else None


def list_hashes(pool) -> List[dict]:
    with pool.connection() as conn:
        rows = conn.execute(
            "SELECT hash, label, status, source, proposed_at, reviewed_at FROM known_bad_hashes ORDER BY proposed_at"
        ).fetchall()
    return [
        {
            "hash": r[0],
            "label": r[1],
            "status": r[2],
            "source": r[3],
            "proposed_at": r[4].isoformat(),
            "reviewed_at": r[5].isoformat() if r[5] else None,
        }
        for r in rows
    ]


def propose_hash(pool, sample_hash: str, label: str, source: str) -> dict:
    # Validated here, not in the route: /score's auto-propose path is
    # unauthenticated and would otherwise write arbitrary strings into the
    # known-bad store.
    if not is_valid_hash(sample_hash):
        raise ValueError(f"not a valid sha256 hex hash: {sample_hash[:80]!r}")
    now = datetime.now(timezone.utc)
    try:
        with pool.connection() as conn:
            conn.execute(
                "INSERT INTO known_bad_hashes (hash, label, status, source, proposed_at) "
                "VALUES (%s, %s, 'pending', %s, %s)",
                (sample_hash, label, source, now),
            )
    except psycopg.errors.UniqueViolation as e:
        raise HashExistsError(sample_hash) from e
    return {
        "hash": sample_hash,
        "label": label,
        "status": "pending",
        "source": source,
        "proposed_at": now.isoformat(),
        "reviewed_at": None,
    }


def _decide(pool, sample_hash: str, new_status: str) -> dict:
    now = datetime.now(timezone.utc)
    with pool.connection() as conn:
        with conn.transaction():
            # SELECT ... FOR UPDATE serializes concurrent decisions on the
            # same row -- the second caller blocks until the first commits,
            # then sees status already changed and raises instead of
            # double-applying.
            row = conn.execute(
                "SELECT status, label FROM known_bad_hashes WHERE hash = %s FOR UPDATE",
                (sample_hash,),
            ).fetchone()
            if row is None:
                raise HashNotFoundError(sample_hash)
            status, label = row
            if status != "pending":
                raise HashNotPendingError(sample_hash)
            conn.execute(
                "UPDATE known_bad_hashes SET status = %s, reviewed_at = %s WHERE hash = %s",
                (new_status, now, sample_hash),
            )
    return {
        "hash": sample_hash,
        "label": label,
        "status": new_status,
        "reviewed_at": now.isoformat(),
    }


def approve_hash(pool, sample_hash: str) -> dict:
    return _decide(pool, sample_hash, "approved")


def reject_hash(pool, sample_hash: str) -> dict:
    return _decide(pool, sample_hash, "rejected")
```

- [ ] **Step 5: Remove the known-bad-hashes flat-file fixture from `conftest.py`**

In `verdict-engine/tests/conftest.py`, remove the `_TEST_KNOWN_BAD`/`KNOWN_BAD_HASHES_PATH` block (the four lines setting it up and the matching cleanup line in `pytest_sessionfinish`) — hash storage no longer reads that env var.

- [ ] **Step 6: Run tests to verify they pass**

Run: same command as Step 3
Expected: PASS

- [ ] **Step 7: Commit**

```bash
git add verdict-engine/migrations/0001_create_known_bad_hashes.sql verdict-engine/hash_lookup.py verdict-engine/tests/test_hash_lookup.py verdict-engine/tests/conftest.py
git commit -m "feat: move known-bad hashes to Postgres with row-level locking"
```

---

### Task 7: Python — audit_log table with restricted role, and AuditLog rewrite

**Files:**
- Create: `verdict-engine/migrations/0002_create_audit_log.sql`
- Modify: `verdict-engine/audit_log.py`
- Modify: `verdict-engine/tests/test_audit_log.py`
- Modify: `verdict-engine/tests/conftest.py` (remove the flat-file fixture for the audit log — `AuditLog` no longer takes a `Path`, so `AUDIT_LOG_PATH` becomes unused here, same reasoning Task 6 applied to `KNOWN_BAD_HASHES_PATH`)

**Interfaces:**
- Consumes: `new_pool`, `run_migrations` (Task 5).
- Produces: `AuditLog(pool)` (replaces `AuditLog(path)`), same method names (`append`, `all`, `get`, `verify_chain_detail`, `verify_chain`).

**Review Focus items owned here:** `verdict_role` attempting `UPDATE`/`DELETE` on `audit_log` must fail with a Postgres permission error; the append-race protection (advisory lock) must actually prevent two concurrent appends from computing the same `prev_log_hash`.

**Expected transient breakage:** same reasoning as Task 6 -- `tests/test_app.py` will still fail after this task (fixed by Task 8), since `app.py` hasn't been updated to construct `AuditLog(pool)` yet. This task's own verification (Step 3) is scoped to `tests/test_audit_log.py`.

- [ ] **Step 1: Write the migration**

```sql
-- verdict-engine/migrations/0002_create_audit_log.sql
CREATE TABLE IF NOT EXISTS audit_log (
  id BIGSERIAL PRIMARY KEY,
  entry_hash TEXT NOT NULL,
  prev_log_hash TEXT NOT NULL,
  data JSONB NOT NULL
);
CREATE INDEX IF NOT EXISTS audit_log_entry_hash_idx ON audit_log (entry_hash);

-- verdict_role can append and read, but never edit or delete a past entry --
-- this is the actual tamper-evidence improvement over the old flat file.
GRANT SELECT, INSERT ON audit_log TO {{ROLE_NAME}};
```

- [ ] **Step 2: Write the failing tests**

Replace `verdict-engine/tests/test_audit_log.py` entirely with:

```python
import os
import threading

import psycopg
import pytest

from audit_log import AuditLog
from db import new_pool, run_migrations

GENESIS_HASH = "0" * 64


@pytest.fixture
def admin_url():
    url = os.getenv("MIRRAURA_TEST_DATABASE_URL")
    if not url:
        pytest.skip("MIRRAURA_TEST_DATABASE_URL not set; skipping Postgres-backed test")
    return url


@pytest.fixture
def pool(admin_url):
    runtime_url = "postgres://audit_log_test_role:audit_log_test_pw@localhost:5432/mirraura"
    run_migrations(admin_url, runtime_url, "migrations")
    p = new_pool(runtime_url)
    yield p
    with p.connection() as conn:
        conn.execute("DELETE FROM audit_log")
        conn.commit()
    p.close()


def test_append_and_read_back(pool):
    log = AuditLog(pool)
    record = log.append({"verdict_id": "v1", "verdict": "Normal"})
    assert record["prev_log_hash"] == GENESIS_HASH
    assert "entry_hash" in record
    assert log.get("v1")["verdict_id"] == "v1"


def test_chain_links_entries(pool):
    log = AuditLog(pool)
    r1 = log.append({"verdict_id": "v1", "verdict": "Normal"})
    r2 = log.append({"verdict_id": "v2", "verdict": "Suspicious"})
    assert r2["prev_log_hash"] == r1["entry_hash"]
    assert log.verify_chain() is True


def test_concurrent_appends_dont_duplicate_prev_hash(pool):
    log = AuditLog(pool)

    def do_append(i):
        log.append({"verdict_id": f"v{i}"})

    threads = [threading.Thread(target=do_append, args=(i,)) for i in range(10)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert log.verify_chain() is True
    assert log.verify_chain_detail()["entries"] == 10


def test_app_role_cannot_update_audit_log(admin_url, pool):
    log = AuditLog(pool)
    log.append({"verdict_id": "v1", "verdict": "Normal"})

    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        with pool.connection() as conn:
            conn.execute("UPDATE audit_log SET entry_hash = 'tampered' WHERE id = 1")
            conn.commit()


def test_superuser_tampering_is_still_detected(admin_url, pool):
    # Even though the app role can't tamper (previous test), prove the chain
    # math itself still catches it if someone with elevated access does --
    # the hash-chain property, not just the permission grant, is what makes
    # this tamper-evident end to end.
    log = AuditLog(pool)
    log.append({"verdict_id": "v1", "verdict": "Normal"})
    log.append({"verdict_id": "v2", "verdict": "Suspicious"})

    with psycopg.connect(admin_url, autocommit=True) as conn:
        conn.execute("UPDATE audit_log SET entry_hash = 'tampered' WHERE id = 1")

    assert AuditLog(pool).verify_chain() is False


def test_verify_chain_detail_reports_broken_entry_one_indexed(admin_url, pool):
    log = AuditLog(pool)
    log.append({"verdict_id": "v1"})
    log.append({"verdict_id": "v2"})

    with psycopg.connect(admin_url, autocommit=True) as conn:
        conn.execute("UPDATE audit_log SET entry_hash = 'tampered' WHERE id = 1")

    result = AuditLog(pool).verify_chain_detail()
    assert result["intact"] is False
    assert result["entries"] == 2
    assert result["broken_at"] == 1
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `MIRRAURA_TEST_DATABASE_URL="postgres://postgres:$POSTGRES_PASSWORD@localhost:5432/mirraura" pytest tests/test_audit_log.py -v`
Expected: FAIL — `AuditLog.__init__` still expects a `Path`.

- [ ] **Step 4: Rewrite `verdict-engine/audit_log.py`**

```python
import hashlib
import json
from typing import List, Optional

GENESIS_HASH = "0" * 64

# A fixed, arbitrary key for the Postgres advisory lock that serializes
# appends -- any two processes passing the same integer to pg_advisory_xact_lock
# contend for the same lock, which is all that's needed here (one logical
# resource: "the end of this audit log").
_APPEND_LOCK_KEY = 847_362_910


class AuditLog:
    def __init__(self, pool):
        self.pool = pool

    def _last_hash(self, conn) -> str:
        row = conn.execute("SELECT entry_hash FROM audit_log ORDER BY id DESC LIMIT 1").fetchone()
        return row[0] if row else GENESIS_HASH

    def append(self, verdict: dict) -> dict:
        with self.pool.connection() as conn:
            with conn.transaction():
                # Holds until this transaction commits or rolls back, so a
                # second concurrent append can't read the same "last hash"
                # as this one and silently fork the chain.
                conn.execute("SELECT pg_advisory_xact_lock(%s)", (_APPEND_LOCK_KEY,))
                prev_hash = self._last_hash(conn)
                entry = {**verdict, "prev_log_hash": prev_hash}
                entry_hash = hashlib.sha256(json.dumps(entry, sort_keys=True).encode()).hexdigest()
                conn.execute(
                    "INSERT INTO audit_log (entry_hash, prev_log_hash, data) VALUES (%s, %s, %s)",
                    (entry_hash, prev_hash, json.dumps(entry)),
                )
        return {**entry, "entry_hash": entry_hash}

    def all(self) -> List[dict]:
        with self.pool.connection() as conn:
            rows = conn.execute("SELECT data, entry_hash FROM audit_log ORDER BY id").fetchall()
        return [{**row[0], "entry_hash": row[1]} for row in rows]

    def get(self, verdict_id: str) -> Optional[dict]:
        for record in self.all():
            if record.get("verdict_id") == verdict_id:
                return record
        return None

    def verify_chain_detail(self) -> dict:
        prev_hash = GENESIS_HASH
        with self.pool.connection() as conn:
            rows = conn.execute("SELECT data, entry_hash FROM audit_log ORDER BY id").fetchall()
        for i, (data, stored_entry_hash) in enumerate(rows):
            if data.get("prev_log_hash") != prev_hash:
                return {"intact": False, "entries": len(rows), "broken_at": i + 1}
            expected = hashlib.sha256(json.dumps(data, sort_keys=True).encode()).hexdigest()
            if expected != stored_entry_hash:
                return {"intact": False, "entries": len(rows), "broken_at": i + 1}
            prev_hash = stored_entry_hash
        return {"intact": True, "entries": len(rows), "broken_at": None}

    def verify_chain(self) -> bool:
        return self.verify_chain_detail()["intact"]
```

- [ ] **Step 5: Remove the audit-log flat-file fixture from `conftest.py`**

In `verdict-engine/tests/conftest.py`, remove the `_TEST_AUDIT_LOG`/`AUDIT_LOG_PATH` block (the two setup lines and the matching cleanup line in `pytest_sessionfinish`) — `AuditLog` no longer reads that env var.

- [ ] **Step 6: Run tests to verify they pass**

Run: same command as Step 3
Expected: PASS

- [ ] **Step 7: Commit**

```bash
git add verdict-engine/migrations/0002_create_audit_log.sql verdict-engine/audit_log.py verdict-engine/tests/test_audit_log.py verdict-engine/tests/conftest.py
git commit -m "feat: move audit log to Postgres, restrict app role to insert+select"
```

---

### Task 8: Python — wire startup (app.py)

**Files:**
- Modify: `verdict-engine/app.py`

**Interfaces:**
- Consumes: `new_pool`, `run_migrations` (Task 5), the new `pool`-taking signatures from Tasks 6-7.

- [ ] **Step 1: Rewrite the module-level setup and every call site**

In `verdict-engine/app.py`, replace:
```python
app = FastAPI()
audit_log = AuditLog(Path(os.getenv("AUDIT_LOG_PATH", "/data/audit_log.jsonl")))
event_archive = EventArchive(Path(os.getenv("EVENT_ARCHIVE_PATH", "/data/event_archive.jsonl")))
logger = logging.getLogger(__name__)
```
with:
```python
from db import new_pool, run_migrations

app = FastAPI()

_verdict_db_url = os.getenv("VERDICT_DATABASE_URL")
_verdict_migrations_url = os.getenv("VERDICT_MIGRATIONS_DATABASE_URL")
if not _verdict_db_url or not _verdict_migrations_url:
    raise RuntimeError("VERDICT_DATABASE_URL and VERDICT_MIGRATIONS_DATABASE_URL must both be set")
run_migrations(_verdict_migrations_url, _verdict_db_url, Path(__file__).parent / "migrations")
_pool = new_pool(_verdict_db_url)

audit_log = AuditLog(_pool)
event_archive = EventArchive(Path(os.getenv("EVENT_ARCHIVE_PATH", "/data/event_archive.jsonl")))
logger = logging.getLogger(__name__)
```

Then update every call site that currently calls a `hash_lookup` function to pass `_pool` as the first argument: `check_hash(req.sample_hash)` → `check_hash(_pool, req.sample_hash)`; `propose_hash(req.sample_hash, ...)` → `propose_hash(_pool, req.sample_hash, ...)`; `list_hashes()` → `list_hashes(_pool)`; `approve_hash(hash)` → `approve_hash(_pool, hash)`; `reject_hash(hash)` → `reject_hash(_pool, hash)`.

- [ ] **Step 2: Run the full verdict-engine suite**

Run: `MIRRAURA_TEST_DATABASE_URL="postgres://postgres:$POSTGRES_PASSWORD@localhost:5432/mirraura" pytest tests/ -v`
Expected: all PASS — this surfaces any remaining call site still using an old signature.

- [ ] **Step 3: Commit**

```bash
git add verdict-engine/app.py
git commit -m "feat: wire Postgres pool and migrations into verdict-engine startup"
```

---

### Task 9: Frontend — user management UI

**Files:**
- Create: `frontend/src/components/UserManagement.tsx`
- Create: `frontend/src/components/UserManagement.css`
- Modify: `frontend/src/api.ts`
- Modify: `frontend/src/api.test.ts`
- Modify: `frontend/src/App.tsx` (admin-only tab alongside Audit log / Hash approvals)

**Interfaces:**
- Consumes: `Tabs`/`TabPanel` (existing), `Card`, `ConfirmDialog`, `useToast` (existing).
- Produces: `fetchUsers()`, `createUser(username, password, role)`, `deleteUser(username)`, `updateUserRole(username, role)` in `api.ts`.

- [ ] **Step 1: Add API client functions**

Add to `frontend/src/api.ts`:
```ts
export type UserEntry = { username: string; role: "admin" | "analyst" };

export async function fetchUsers(): Promise<UserEntry[]> {
  return request("/api/users");
}

export async function createUser(username: string, password: string, role: "admin" | "analyst"): Promise<void> {
  await request("/api/users", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username, password, role }),
  });
}

export async function deleteUser(username: string): Promise<void> {
  await request(`/api/users/${encodeURIComponent(username)}`, { method: "DELETE" });
}

export async function updateUserRole(username: string, role: "admin" | "analyst"): Promise<void> {
  await request(`/api/users/${encodeURIComponent(username)}/role`, {
    method: "PATCH",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ role }),
  });
}
```

Add to `frontend/src/api.test.ts`:
```ts
describe("user management", () => {
  it("fetchUsers calls the backend users endpoint", async () => {
    (fetch as any).mockResolvedValue({
      ok: true,
      json: async () => [{ username: "admin", role: "admin" }],
    });
    const result = await fetchUsers();
    expect(fetch).toHaveBeenCalledWith(
      expect.stringContaining("/api/users"),
      expect.objectContaining({ credentials: "same-origin" })
    );
    expect(result).toEqual([{ username: "admin", role: "admin" }]);
  });

  it("createUser posts to the users endpoint", async () => {
    (fetch as any).mockResolvedValue({ ok: true, status: 200 });
    await createUser("bob", "bobspassword123", "analyst");
    expect(fetch).toHaveBeenCalledWith(
      expect.stringContaining("/api/users"),
      expect.objectContaining({ method: "POST" })
    );
  });

  it("deleteUser deletes the specific user", async () => {
    (fetch as any).mockResolvedValue({ ok: true, status: 204 });
    await deleteUser("bob");
    expect(fetch).toHaveBeenCalledWith(
      expect.stringContaining("/api/users/bob"),
      expect.objectContaining({ method: "DELETE" })
    );
  });
});
```
(Add `fetchUsers, createUser, deleteUser, updateUserRole` to the existing import line from `"./api"` at the top of the file.)

- [ ] **Step 2: Run the new tests to verify they fail**

Run: `cd frontend && npm test`
Expected: FAIL — these functions don't exist yet.

- [ ] **Step 3: Build `UserManagement.tsx`**

```tsx
import { useEffect, useState } from "react";
import { createUser, deleteUser, fetchUsers, updateUserRole } from "../api";
import type { UserEntry } from "../api";
import { Card } from "./Card";
import { ConfirmDialog } from "./ConfirmDialog";
import { useToast } from "./Toast";
import "./UserManagement.css";

export function UserManagement() {
  const [users, setUsers] = useState<UserEntry[]>([]);
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [role, setRole] = useState<"admin" | "analyst">("analyst");
  const [error, setError] = useState<string | null>(null);
  const [pendingDelete, setPendingDelete] = useState<string | null>(null);
  const { push } = useToast();

  function refetch() {
    fetchUsers()
      .then(setUsers)
      .catch((e) => setError(e instanceof Error ? e.message : "failed to load users"));
  }

  useEffect(refetch, []);

  async function handleCreate(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    try {
      await createUser(username, password, role);
      setUsername("");
      setPassword("");
      refetch();
      push(`Created user ${username}`, "success");
    } catch (err) {
      setError(err instanceof Error ? err.message : "failed to create user");
    }
  }

  async function handleDelete(target: string) {
    setPendingDelete(null);
    try {
      await deleteUser(target);
      refetch();
      push(`Removed user ${target}`, "success");
    } catch (err) {
      push(err instanceof Error ? err.message : "failed to remove user", "error");
    }
  }

  async function handleRoleChange(target: string, newRole: "admin" | "analyst") {
    try {
      await updateUserRole(target, newRole);
      refetch();
    } catch (err) {
      push(err instanceof Error ? err.message : "failed to change role", "error");
    }
  }

  return (
    <Card title="User management">
      {error && <p className="error-text">{error}</p>}
      <table className="user-table">
        <thead>
          <tr>
            <th>Username</th>
            <th>Role</th>
            <th>Action</th>
          </tr>
        </thead>
        <tbody>
          {users.map((u) => (
            <tr key={u.username}>
              <td className="mono">{u.username}</td>
              <td>
                <select value={u.role} onChange={(e) => handleRoleChange(u.username, e.target.value as "admin" | "analyst")}>
                  <option value="admin">admin</option>
                  <option value="analyst">analyst</option>
                </select>
              </td>
              <td>
                <button type="button" className="reject-button" onClick={() => setPendingDelete(u.username)}>
                  Remove
                </button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>

      <form onSubmit={handleCreate} className="user-form">
        <input placeholder="username" value={username} onChange={(e) => setUsername(e.target.value)} required />
        <input
          placeholder="password (12+ chars)"
          type="password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          required
        />
        <select value={role} onChange={(e) => setRole(e.target.value as "admin" | "analyst")}>
          <option value="analyst">analyst</option>
          <option value="admin">admin</option>
        </select>
        <button type="submit">Add user</button>
      </form>

      <ConfirmDialog
        open={pendingDelete !== null}
        title="Remove this user?"
        description={<p>{pendingDelete} will no longer be able to sign in.</p>}
        confirmLabel="Remove"
        onConfirm={() => pendingDelete && handleDelete(pendingDelete)}
        onCancel={() => setPendingDelete(null)}
      />
    </Card>
  );
}
```

```css
/* frontend/src/components/UserManagement.css */
.user-table {
  width: 100%;
  border-collapse: collapse;
  font-size: var(--fs-2);
  margin-bottom: var(--sp-3);
}

.user-table th {
  text-align: left;
  color: var(--text-faint);
  text-transform: uppercase;
  font-size: var(--fs-1);
  padding: var(--sp-1);
  border-bottom: 1px solid var(--border);
}

.user-table td {
  padding: var(--sp-1);
  border-bottom: 1px solid var(--border);
}

.user-form {
  display: flex;
  gap: var(--sp-1);
  flex-wrap: wrap;
}

.user-form input,
.user-form select {
  background: var(--bg);
  color: var(--text);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  padding: 6px var(--sp-2);
}
```

- [ ] **Step 4: Wire into `App.tsx`**

In `frontend/src/App.tsx`, import `UserManagement` and add a third tab to the existing `log-zone` `Tabs`/`TabPanel` block, visible only when `role === "admin"`:
```tsx
          { id: "audit", label: "Audit log" },
          {
            id: "hashes",
            label: "Hash approvals",
            badge: pendingCount > 0 ? <span className="tabs__badge">{pendingCount}</span> : undefined,
          },
          ...(role === "admin" ? [{ id: "users", label: "Users" }] : []),
```
and add a matching `<TabPanel id="users" active={bottomTab}><UserManagement /></TabPanel>` after the existing two panels (only reachable when the tab list above includes it, since `role !== "admin"` never renders the "users" tab at all).

- [ ] **Step 5: Run tests and build**

Run: `cd frontend && npx tsc --noEmit -p tsconfig.app.json && npm test && npm run build`
Expected: PASS, clean build.

- [ ] **Step 6: Commit**

```bash
git add frontend/src/components/UserManagement.tsx frontend/src/components/UserManagement.css frontend/src/api.ts frontend/src/api.test.ts frontend/src/App.tsx
git commit -m "feat: admin-only user management UI"
```

---

### Task 10: Docs

**Files:**
- Modify: `docs/concepts.md`

- [ ] **Step 1: Add an entry under "Tools & libraries — what and why"**

```markdown
**Postgres + pgx (Go) / psycopg (Python)** — Replaces four flat-file/in-memory
stores (sessions, users, known-bad hashes, audit log) with a real database,
fixing the session store's single-instance-only limitation. Each service
connects as its own least-privilege role; the audit log's role gets no
UPDATE/DELETE grant at all, so even a compromised verdict-engine process
can't edit a past entry -- a real improvement over the old flat file, not
just a storage swap.
```

- [ ] **Step 2: Commit**

```bash
git add docs/concepts.md
git commit -m "docs: document the Postgres migration"
```
