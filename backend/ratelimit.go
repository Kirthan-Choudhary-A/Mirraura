package main

import (
	"sync"
	"time"
)

const (
	loginMaxFailures = 5
	loginWindow      = 15 * time.Minute
)

// LoginLimiter tracks failed login attempts per IP in memory. ponytail:
// like SessionStore, this resets on restart and doesn't share state across
// instances — fine for a single-instance deployment.
type LoginLimiter struct {
	mu       sync.Mutex
	failures map[string][]time.Time
}

func NewLoginLimiter() *LoginLimiter {
	return &LoginLimiter{failures: make(map[string][]time.Time)}
}

func (l *LoginLimiter) Allow(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.recentFailuresLocked(ip)) < loginMaxFailures
}

func (l *LoginLimiter) RecordFailure(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	recent := l.recentFailuresLocked(ip)
	l.failures[ip] = append(recent, time.Now())
}

// recentFailuresLocked prunes and returns failures within the window for
// ip. Caller must hold l.mu.
func (l *LoginLimiter) recentFailuresLocked(ip string) []time.Time {
	cutoff := time.Now().Add(-loginWindow)
	var kept []time.Time
	for _, t := range l.failures[ip] {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	l.failures[ip] = kept
	return kept
}
