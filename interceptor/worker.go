package main

import (
	"crypto/rand"
	"encoding/hex"
	"log"
	"os"
	"path/filepath"
)

func randomID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// runWorkers starts n goroutines pulling file paths off jobs, one at a
// time each. This -- not a new queue service -- is the whole fix for "a
// 40-file archive extraction shouldn't launch 40 containers at once":
// bounded concurrency via channel + worker pool, nothing more.
func runWorkers(cfg Config, jobs <-chan string, n int) {
	for i := 0; i < n; i++ {
		go func() {
			for path := range jobs {
				processNewFile(cfg, path)
			}
		}()
	}
}

// processNewFile quarantines a single newly-stable file and submits it,
// acting immediately on a release/block decision. A "hold" decision is
// left for the held-poller (runHeldPoller) to pick up -- this function's
// job ends once the entry is safely recorded on disk as "held".
func processNewFile(cfg Config, path string) {
	if _, err := os.Stat(path); err != nil {
		return // gone already (moved, deleted) before we got to it
	}
	id := randomID()
	entryDir := quarantineEntryDir(cfg.QuarantineDir, id)
	filename := filepath.Base(path)

	if err := moveFile(path, payloadPath(entryDir)); err != nil {
		log.Printf("quarantine %s: %v", path, err)
		return
	}
	meta := QuarantineMeta{OriginalPath: path, Filename: filename, State: "pending_submit"}
	if err := writeMeta(entryDir, meta); err != nil {
		log.Printf("quarantine %s: write meta: %v", path, err)
		return
	}

	submitAndAct(cfg, entryDir, meta)
}

// submitAndAct posts an already-quarantined entry and acts on the result.
// Shared by processNewFile (first submission) and the startup sweep
// (resubmitting anything still "pending_submit" from a daemon crash).
func submitAndAct(cfg Config, entryDir string, meta QuarantineMeta) {
	result, err := submit(cfg, payloadPath(entryDir), meta.Filename, meta.OriginalPath)
	if err != nil {
		// Fails safe: stays quarantined as "pending_submit" and will be
		// retried on the next startup sweep, or a future retry loop.
		// Never silently released on a network error.
		log.Printf("submit %s: %v", meta.Filename, err)
		return
	}

	switch result.Decision {
	case "release":
		if err := moveFile(payloadPath(entryDir), meta.OriginalPath); err != nil {
			log.Printf("release %s: %v", meta.Filename, err)
			return
		}
		os.RemoveAll(entryDir)
		notify("Mirraura", meta.Filename+" was clean and has been released.")
	case "block":
		meta.State = "blocked"
		writeMeta(entryDir, meta)
		notify("Mirraura — blocked", meta.Filename+" was flagged Compromised and is quarantined, not released.")
	case "hold":
		meta.State = "held"
		meta.QuarantineID = result.QuarantineID
		writeMeta(entryDir, meta)
		notify("Mirraura — review needed", meta.Filename+" needs admin review before it's released.")
	default:
		log.Printf("submit %s: unknown decision %q", meta.Filename, result.Decision)
	}
}
