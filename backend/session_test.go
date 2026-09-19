package main

import (
	"testing"
	"time"
)

func TestSessionStoreCreateAndGet(t *testing.T) {
	store := NewSessionStore()
	token := store.Create("alice", "analyst")
	if token == "" {
		t.Fatal("expected a non-empty token")
	}
	sess, ok := store.Get(token)
	if !ok {
		t.Fatal("expected the created session to be found")
	}
	if sess.Username != "alice" || sess.Role != "analyst" {
		t.Fatalf("unexpected session: %+v", sess)
	}
}

func TestSessionStoreGetUnknownTokenFails(t *testing.T) {
	store := NewSessionStore()
	if _, ok := store.Get("does-not-exist"); ok {
		t.Fatal("expected an unknown token to not be found")
	}
}

func TestSessionStoreDelete(t *testing.T) {
	store := NewSessionStore()
	token := store.Create("alice", "analyst")
	store.Delete(token)
	if _, ok := store.Get(token); ok {
		t.Fatal("expected the deleted session to no longer be found")
	}
}

func TestSessionStoreExpiresAfterTTL(t *testing.T) {
	store := NewSessionStore()
	token := store.Create("alice", "analyst")
	// Reach into the store to simulate 8+ hours of inactivity, rather than
	// sleeping in the test.
	store.mu.Lock()
	entry := store.sessions[token]
	entry.expiresAt = time.Now().Add(-time.Second)
	store.sessions[token] = entry
	store.mu.Unlock()

	if _, ok := store.Get(token); ok {
		t.Fatal("expected an expired session to not be found")
	}
}

func TestSessionStoreSlidesExpiryOnGet(t *testing.T) {
	store := NewSessionStore()
	token := store.Create("alice", "analyst")
	store.mu.Lock()
	entry := store.sessions[token]
	nearExpiry := time.Now().Add(time.Second)
	entry.expiresAt = nearExpiry
	store.sessions[token] = entry
	store.mu.Unlock()

	if _, ok := store.Get(token); !ok {
		t.Fatal("expected the session to still be valid just before its near-term expiry")
	}
	store.mu.Lock()
	slid := store.sessions[token].expiresAt
	store.mu.Unlock()
	if !slid.After(nearExpiry) {
		t.Fatal("expected Get to slide the expiry forward")
	}
}

func TestSessionStoreTokensAreUnique(t *testing.T) {
	store := NewSessionStore()
	a := store.Create("alice", "analyst")
	b := store.Create("alice", "analyst")
	if a == b {
		t.Fatal("expected two calls to Create to produce different tokens")
	}
}
