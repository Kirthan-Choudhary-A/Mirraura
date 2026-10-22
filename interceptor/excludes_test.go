package main

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// shouldSkipDir only inspects dir's own basename, not its ancestors --
// correct because filepath.WalkDir's SkipDir already stops the walk from
// ever descending into an excluded directory's children in the first
// place, so a nested path like ".config/app" is never offered to this
// function at all in real usage.
func TestShouldSkipDir(t *testing.T) {
	excludes := []string{"/home/user/.mirraura-quarantine", "/home/user/go"}
	cases := map[string]bool{
		"/home/user/Downloads":            false,
		"/home/user/Documents/reports":    false,
		"/home/user/.cache":               true,
		"/home/user/.config":              true,
		"/home/user/.mirraura-quarantine": true,
		"/home/user/go":                   true,
		"/home/user/go/pkg/mod":           false, // only the exact root matches, not nested paths -- SkipDir already stops descent
		"/media/usb/Documents":            false,
	}
	for dir, want := range cases {
		if got := shouldSkipDir(dir, excludes); got != want {
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
	excludes := []string{"/home/user/.mirraura-quarantine"}
	if !shouldSkipDir(repo, excludes) {
		t.Errorf("shouldSkipDir(%q) = false, want true (contains .git)", repo)
	}

	plain := t.TempDir()
	if shouldSkipDir(plain, excludes) {
		t.Errorf("shouldSkipDir(%q) = true, want false (no .git)", plain)
	}
}

// GOPATH exclusion: confirmed live when building this daemon's own binary
// quarantined 4500+ files from `go mod download` extracting dependency
// source into ~/go/pkg/mod in one burst.
func TestLoadConfigExcludesGoPath(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("BACKEND_URL", "http://localhost:5173")
	t.Setenv("INTERCEPTOR_TOKEN", "test-token")
	t.Setenv("GOPATH", "")

	cfg, err := loadConfig()
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	wantGoPath := filepath.Join(home, "go")
	if !slices.Contains(cfg.ExactExcludes, wantGoPath) {
		t.Fatalf("ExactExcludes = %v, want it to contain %s", cfg.ExactExcludes, wantGoPath)
	}
}
