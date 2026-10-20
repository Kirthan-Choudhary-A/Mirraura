package main

import (
	"sync"
	"time"
)

// stabilizer debounces a burst of write events on the same path into a
// single "this path is done changing" signal. fsnotify has no equivalent
// of inotify's raw IN_CLOSE_WRITE flag, so each write event resets a
// per-path timer; the path is only announced once it goes quiet for
// settleDelay. This also does double duty as the burst control: a flurry
// of writes from one archive extraction settles out before anything gets
// submitted, rather than firing once per individual write.
type stabilizer struct {
	settleDelay time.Duration
	stable      chan string

	mu     sync.Mutex
	timers map[string]*time.Timer
}

func newStabilizer(settleDelay time.Duration) *stabilizer {
	return &stabilizer{
		settleDelay: settleDelay,
		stable:      make(chan string, 256),
		timers:      make(map[string]*time.Timer),
	}
}

// touch resets path's settle timer, extending it on every call. A caller
// should call this once per write/create event observed for path.
func (s *stabilizer) touch(path string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if t, ok := s.timers[path]; ok {
		t.Stop()
	}
	s.timers[path] = time.AfterFunc(s.settleDelay, func() {
		s.mu.Lock()
		delete(s.timers, path)
		s.mu.Unlock()
		s.stable <- path
	})
}

// cancel stops tracking path without announcing it -- used when a path
// turns out not to be a real file (e.g. a directory creation event) so it
// never gets queued.
func (s *stabilizer) cancel(path string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if t, ok := s.timers[path]; ok {
		t.Stop()
		delete(s.timers, path)
	}
}
