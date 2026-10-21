package main

import (
	"sync"
	"time"
)

// releaseIgnore suppresses the watcher from re-quarantining a file the
// daemon just moved back to its original path itself (release/approve) --
// without this, the write that restores the file looks like a brand-new
// download and the daemon quarantines it again forever.
var releaseIgnore = struct {
	mu    sync.Mutex
	until map[string]time.Time
}{until: make(map[string]time.Time)}

// ponytail: fixed window, not tied to actual move duration -- fine for
// demo-sized files; a multi-GB release could outlast it and get re-caught.
const releaseIgnoreWindow = 5 * time.Second

func markReleased(path string) {
	releaseIgnore.mu.Lock()
	defer releaseIgnore.mu.Unlock()
	releaseIgnore.until[path] = time.Now().Add(releaseIgnoreWindow)
}

func isJustReleased(path string) bool {
	releaseIgnore.mu.Lock()
	defer releaseIgnore.mu.Unlock()
	exp, ok := releaseIgnore.until[path]
	if !ok {
		return false
	}
	if time.Now().After(exp) {
		delete(releaseIgnore.until, path)
		return false
	}
	return true
}
