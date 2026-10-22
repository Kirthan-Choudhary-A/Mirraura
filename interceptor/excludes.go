package main

import (
	"os"
	"path/filepath"
	"slices"
)

// shouldSkipDir reports whether the watcher should never descend into or
// watch dir. Covers four cases: app-internal churn (any dotdir --
// .cache, .config, .mozilla, .local, etc.) that isn't "content the user
// brought onto the machine," an exact-match exclude root (the daemon's
// own quarantine dir, and GOPATH -- both must never be watched: the
// quarantine dir would try to intercept the files it just quarantined,
// and GOPATH's `go/pkg/mod` gets thousands of files written in one burst
// by `go mod download`/`go build`, confirmed live when building this
// daemon flooded quarantine with its own dependency source tree), and a
// git working tree (a directory containing .git), which is a
// developer's own project, not downloaded content -- without this,
// every `git pull`/`git checkout` on a repo sitting under $HOME gets its
// changed files vacuumed into quarantine.
func shouldSkipDir(dir string, exactExcludes []string) bool {
	if slices.Contains(exactExcludes, dir) {
		return true
	}
	base := filepath.Base(dir)
	if len(base) > 0 && base[0] == '.' {
		return true
	}
	if _, err := os.Stat(filepath.Join(dir, ".git")); err == nil {
		return true
	}
	return false
}

// shouldSkipFile reports whether a regular file should never be quarantined:
// dotfiles (.zsh_history, .bash_history, .viminfo, ...) are app/shell-
// internal state that churns on every command, not downloaded content.
func shouldSkipFile(path string) bool {
	base := filepath.Base(path)
	return len(base) > 0 && base[0] == '.'
}
