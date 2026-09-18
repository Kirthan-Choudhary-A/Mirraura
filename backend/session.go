package main

import (
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"
)

type Session struct {
	Username string
	Role     string
}

type sessionEntry struct {
	Session
	expiresAt time.Time
}

const sessionTTL = 8 * time.Hour

// SessionStore is an in-memory session table: sessions are lost on backend
// restart. That's an accepted tradeoff for a single-instance deployment.
// ponytail: move to a shared store (e.g. Redis) if the backend ever runs
// as more than one instance.
type SessionStore struct {
	mu       sync.Mutex
	sessions map[string]sessionEntry
}

func NewSessionStore() *SessionStore {
	return &SessionStore{sessions: make(map[string]sessionEntry)}
}

func (s *SessionStore) Create(username, role string) string {
	b := make([]byte, 32)
	rand.Read(b)
	token := hex.EncodeToString(b)

	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[token] = sessionEntry{
		Session:   Session{Username: username, Role: role},
		expiresAt: time.Now().Add(sessionTTL),
	}
	return token
}

func (s *SessionStore) Get(token string) (Session, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, ok := s.sessions[token]
	if !ok {
		return Session{}, false
	}
	if time.Now().After(entry.expiresAt) {
		delete(s.sessions, token)
		return Session{}, false
	}
	entry.expiresAt = time.Now().Add(sessionTTL)
	s.sessions[token] = entry
	return entry.Session, true
}

func (s *SessionStore) Delete(token string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, token)
}
