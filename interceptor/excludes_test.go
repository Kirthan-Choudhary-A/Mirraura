package main

import (
	"os"
	"path/filepath"
	"testing"
)

// shouldSkipDir only inspects dir's own basename, not its ancestors --
// correct because filepath.WalkDir's SkipDir already stops the walk from
// ever descending into an excluded directory's children in the first
// place, so a nested path like ".config/app" is never offered to this
// function at all in real usage.
func TestShouldSkipDir(t *testing.T) {
	quarantine := "/home/user/.mirraura-quarantine"
	cases := map[string]bool{
		"/home/user/Downloads":            false,
		"/home/user/Documents/reports":    false,
		"/home/user/.cache":               true,
		"/home/user/.config":              true,
		"/home/user/.mirraura-quarantine": true,
		"/media/usb/Documents":            false,
	}
	for dir, want := range cases {
		if got := shouldSkipDir(dir, quarantine); got != want {
			t.Errorf("shouldSkipDir(%q) = %v, want %v", dir, got, want)
		}
	}
}

// A directory containing .git is a developer's own project (e.g. this
// repo itself, cloned under $HOME), not downloaded content -- regression
// test for files getting vacuumed into quarantine on every git pull.
func TestShouldSkipDirSkipsGitRepoRoot(t *testing.T) {
	repo := t.TempDir()
	if err := os.Mkdir(filepath.Join(repo, ".git"), 0755); err != nil {
		t.Fatal(err)
	}
	if !shouldSkipDir(repo, "/home/user/.mirraura-quarantine") {
		t.Errorf("shouldSkipDir(%q) = false, want true (contains .git)", repo)
	}

	plain := t.TempDir()
	if shouldSkipDir(plain, "/home/user/.mirraura-quarantine") {
		t.Errorf("shouldSkipDir(%q) = true, want false (no .git)", plain)
	}
}
