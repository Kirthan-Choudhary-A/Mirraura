package main

import "path/filepath"

// shouldSkipDir reports whether the watcher should never descend into or
// watch dir. Covers two cases: app-internal churn (any dotdir -- .cache,
// .config, .mozilla, .local, etc.) that isn't "content the user brought
// onto the machine," and the daemon's own quarantine directory, which must
// never be watched or it would try to intercept the files it just
// quarantined.
func shouldSkipDir(dir, quarantineDir string) bool {
	if dir == quarantineDir {
		return true
	}
	base := filepath.Base(dir)
	return len(base) > 0 && base[0] == '.'
}

// shouldSkipFile reports whether a regular file should never be quarantined:
// dotfiles (.zsh_history, .bash_history, .viminfo, ...) are app/shell-
// internal state that churns on every command, not downloaded content.
func shouldSkipFile(path string) bool {
	base := filepath.Base(path)
	return len(base) > 0 && base[0] == '.'
}
