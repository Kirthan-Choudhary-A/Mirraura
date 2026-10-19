# Postgres Migration — Design Spec

## Goal

Move all four of Mirraura's flat-file/in-memory data stores to Postgres: Go's session store and user list, and Python's known-bad-hashes list and audit log. Fixes the single-instance-only session store (the biggest blocker to running more than one backend replica) and adds runtime user management as a side benefit of moving users off a static file.

## Scope

In scope: `sessions`, `users` (+ runtime admin CRUD), `known_bad_hashes`, `audit_log`. No import of existing flat-file data — fresh tables, old files left on disk unused (demo/test data, not worth the import-script risk).

Out of scope (future, not this spec): SSO/OIDC, multi-region, connection-pool tuning beyond driver defaults, horizontal scaling of the verdict-engine/backend themselves.

## Architecture

Both services connect to one Postgres instance but keep their existing service boundary — each owns its own tables, neither queries the other's:

- **Go backend owns:** `sessions`, `users`
- **Python verdict-engine owns:** `known_bad_hashes`, `audit_log`

**Two connection strings per service**, since migrations need elevated privileges and runtime traffic shouldn't have them:

- `MIGRATIONS_DATABASE_URL` — admin-level, used once at startup to create/alter tables and grant/revoke permissions. Locally this is the docker-compose Postgres superuser; in production it's whatever an ops team provides for schema changes.
- `DATABASE_URL` — the service's own least-privilege role (`backend_role` or `verdict_role`), used for all normal query traffic.

Postgres itself: a `postgres` service in docker-compose for local dev/demo, swappable to an external managed DB (RDS/Cloud SQL/etc.) via the same two env vars in production.

Migrations: plain numbered `.sql` files per service (`backend/migrations/0001_*.sql`, `verdict-engine/migrations/0001_*.sql`), tracked in a `schema_migrations` table, applied by a small runner at startup — no new framework dependency (golang-migrate/alembic are overkill for a handful of forward-only files).

## Schemas

**`sessions`** (backend_role: full CRUD)
```sql
CREATE TABLE sessions (
  token TEXT PRIMARY KEY,
  username TEXT NOT NULL,
  role TEXT NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL
);
```
`Create`/`Get`/`Delete` become SQL. `Get`'s sliding-expiry bump becomes an `UPDATE`. A periodic job (`DELETE WHERE expires_at < now()`, same ticker pattern the backend already uses for continuous monitoring) prevents unbounded growth, since expired rows otherwise never get removed.

**`users`** (backend_role: full CRUD)
```sql
CREATE TABLE users (
  username TEXT PRIMARY KEY,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL CHECK (role IN ('admin', 'analyst'))
);
```
Seeded on first startup from `MIRRAURA_ADMIN_USER`/`MIRRAURA_ADMIN_PASSWORD` (same as today), but now mutable at runtime. New admin-only endpoints: create user, remove user, change role — mirroring the existing hash-approval auth pattern (`requireRole("admin")`), each action recorded as an `actor`-attributed entry in the audit log. New frontend section for managing users.

**`known_bad_hashes`** (verdict_role: full CRUD)
```sql
CREATE TABLE known_bad_hashes (
  hash TEXT PRIMARY KEY,
  label TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('pending', 'approved', 'rejected')),
  source TEXT NOT NULL,
  proposed_at TIMESTAMPTZ NOT NULL,
  reviewed_at TIMESTAMPTZ
);
```
A DB transaction replaces `threading.Lock()` + the atomic tmp-file-rename dance — real concurrency safety instead of a single-process-only lock.

**`audit_log`** (verdict_role: **INSERT, SELECT only — no UPDATE/DELETE grant**)
```sql
CREATE TABLE audit_log (
  id BIGSERIAL PRIMARY KEY,
  entry_hash TEXT NOT NULL,
  prev_log_hash TEXT NOT NULL,
  data JSONB NOT NULL
);
CREATE INDEX ON audit_log (entry_hash);
```
Entries stay heterogeneous (verdict records vs. action records have different fields) so `data` holds everything else exactly as stored today — `verify_chain_detail()`'s logic barely changes, just reads rows instead of file lines, ordered by `id`.

**Tamper-evidence improvement:** `verdict_role` has no `UPDATE`/`DELETE` grant on `audit_log` at all, enforced by Postgres. Today a flat-file tamperer needs filesystem access; after this, `verdict_role`'s own queries can never edit an old entry, even if the verdict engine's code is exploited through something like SQL injection — a real security improvement over the current file, not just a storage swap. Migrations run as a separate one-shot step (`backend-migrate`/`verdict-migrate` compose services) that holds the admin credential (`*_MIGRATIONS_DATABASE_URL`); the `backend`/`verdict-engine` app containers never receive it, so a compromised app process has no superuser credential in its own environment to fall back on.

**Race protection:** each append wraps "get last hash, compute new hash, insert" in a transaction using a Postgres advisory lock, so this stays correct even if the verdict-engine ever runs more than one worker (today's code has no such protection, just doesn't need it yet with one process).

## Error handling

Each service runs its own migrations at startup, then connects its runtime pool. Unreachable DB or failed migration → fail fast with a clear error (`log.Fatal`/equivalent), same as today's `loadUsers()` behavior on bad config — no silent degraded mode. Transient connection loss during normal operation is handled by the driver/pool's own retry behavior (Go: `pgx`; Python: `psycopg`) — no custom retry logic layered on top.

## Testing

Tests run against a real test Postgres instance via a connection-string env var, matching this project's existing convention of testing against real infrastructure rather than mocks (`dockermanager_test.go` already spins up real Docker containers for its tests; `hash_lookup`/`session` tests today exercise the real flat-file/in-memory implementations directly).

## Docs

`docs/concepts.md` needs a new entry for the Postgres driver choices (Go: `pgx`; Python: `psycopg`) and the least-privilege role model, added as part of the implementation plan — not duplicated here.
