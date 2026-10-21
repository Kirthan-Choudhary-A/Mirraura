package main

import (
	"os"
	"path/filepath"
)

// shouldSkipDir reports whether the watcher should never descend into or
// watch dir. Covers three cases: app-internal churn (any dotdir --
// .cache, .config, .mozilla, .local, etc.) that isn't "content the user
// brought onto the machine," the daemon's own quarantine directory,
// which must never be watched or it would try to intercept the files it
// just quarantined, and a git working tree (a directory containing
// .git), which is a developer's own project, not downloaded content --
// without this, every `git pull`/`git checkout` on a repo sitting under
// $HOME gets its changed files vacuumed into quarantine.
func shouldSkipDir(dir, quarantineDir string) bool {
	if dir == quarantineDir {
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
