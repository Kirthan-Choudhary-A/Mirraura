package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/fsnotify/fsnotify"
)

// TestWatcherDetectsNewFile is the one real-filesystem check promised in
// the design spec: a file written into a watched temp "home" directory
// should actually reach the stabilizer's stable channel, proving the
// fsnotify wiring -- not just the pure helper functions -- works.
func TestWatcherDetectsNewFile(t *testing.T) {
	home := t.TempDir()
	quarantineDir := filepath.Join(home, ".mirraura-quarantine")

	w, err := fsnotify.NewWatcher()
	if err != nil {
		t.Fatalf("NewWatcher: %v", err)
	}
	defer w.Close()
	if err := watchRecursively(w, home, quarantineDir); err != nil {
		t.Fatalf("watchRecursively: %v", err)
	}

	stab := newStabilizer(50 * time.Millisecond)
	go runWatchLoop(w, quarantineDir, stab)

	target := filepath.Join(home, "Downloads", "payload.sh")
	if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
		t.Fatal(err)
	}
	// Give the watcher a beat to pick up the newly created Downloads dir
	// before writing into it (handleEvent adds the watch asynchronously).
	time.Sleep(50 * time.Millisecond)
	if err := os.WriteFile(target, []byte("echo hi"), 0644); err != nil {
		t.Fatal(err)
	}

	select {
	case got := <-stab.stable:
		if got != target {
			t.Fatalf("got %s, want %s", got, target)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("file was never announced as stable")
	}
}

// TestWatcherIgnoresDotDir confirms a file written inside an excluded
// dotdir never reaches the stable channel at all.
func TestWatcherIgnoresDotDir(t *testing.T) {
	home := t.TempDir()
	quarantineDir := filepath.Join(home, ".mirraura-quarantine")
	if err := os.MkdirAll(filepath.Join(home, ".cache"), 0755); err != nil {
		t.Fatal(err)
	}

	w, err := fsnotify.NewWatcher()
	if err != nil {
		t.Fatalf("NewWatcher: %v", err)
	}
	defer w.Close()
	if err := watchRecursively(w, home, quarantineDir); err != nil {
		t.Fatalf("watchRecursively: %v", err)
	}

	stab := newStabilizer(50 * time.Millisecond)
	go runWatchLoop(w, quarantineDir, stab)

	target := filepath.Join(home, ".cache", "something")
	if err := os.WriteFile(target, []byte("noise"), 0644); err != nil {
		t.Fatal(err)
	}

	select {
	case got := <-stab.stable:
		t.Fatalf("expected nothing from an excluded dotdir, got %s", got)
	case <-time.After(300 * time.Millisecond):
	}
}
