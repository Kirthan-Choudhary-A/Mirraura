package main

import (
	"fmt"
	"os"
	"path/filepath"
)

// Config holds everything read from the environment at startup. Kept as a
// plain struct (not globals) so tests can construct one directly without
// touching the real environment.
type Config struct {
	Home          string // directory watched recursively, e.g. $HOME
	QuarantineDir string // e.g. $HOME/.mirraura-quarantine -- must live under Home so release/quarantine moves within Home are same-filesystem renames
	BackendURL    string // e.g. http://localhost:5173, the nginx-fronted origin the daemon talks to
	Token         string // INTERCEPTOR_TOKEN, sent as a bearer token
	// ExactExcludes are directories shouldSkipDir rejects by exact path
	// match: QuarantineDir plus GOPATH (go/pkg/mod gets a burst of
	// unrelated files from `go mod download`/`go build`, not downloaded
	// content -- see shouldSkipDir's comment).
	ExactExcludes []string
}

func loadConfig() (Config, error) {
	home := os.Getenv("HOME")
	if home == "" {
		return Config{}, fmt.Errorf("HOME must be set")
	}
	backendURL := os.Getenv("BACKEND_URL")
	if backendURL == "" {
		return Config{}, fmt.Errorf("BACKEND_URL must be set")
	}
	token := os.Getenv("INTERCEPTOR_TOKEN")
	if token == "" {
		return Config{}, fmt.Errorf("INTERCEPTOR_TOKEN must be set")
	}
	quarantineDir := filepath.Join(home, ".mirraura-quarantine")
	goPath := os.Getenv("GOPATH")
	if goPath == "" {
		goPath = filepath.Join(home, "go") // go's own default when GOPATH is unset
	}
	return Config{
		Home:          home,
		QuarantineDir: quarantineDir,
		BackendURL:    backendURL,
		Token:         token,
		ExactExcludes: []string{quarantineDir, goPath},
	}, nil
}
