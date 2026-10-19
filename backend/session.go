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

// DeleteByUsername removes every session belonging to username. Call this
// when an admin deletes a user or changes their role, so the change takes
// effect immediately instead of waiting for the session to naturally expire
// (sessions renew on every authenticated request, so without this a
// deleted/demoted user could otherwise keep their old access indefinitely).
func (s *SessionStore) DeleteByUsername(ctx context.Context, username string) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM sessions WHERE username = $1`, username)
	return err
}
