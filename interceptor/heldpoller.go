package main

import (
	"log"
	"os"
	"time"
)

// runHeldPoller periodically scans quarantineDir for entries in the
// "held" state and asks the backend whether a human has decided yet. The
// filesystem is the source of truth for which entries are held -- no
// separate in-memory list to keep in sync or lose on restart.
func runHeldPoller(cfg Config, interval time.Duration, stop <-chan struct{}) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			pollHeldEntries(cfg)
		}
	}
}

func pollHeldEntries(cfg Config) {
	ids, err := listQuarantineEntries(cfg.QuarantineDir)
	if err != nil {
		log.Printf("held poller: list entries: %v", err)
		return
	}
	for _, id := range ids {
		entryDir := quarantineEntryDir(cfg.QuarantineDir, id)
		meta, err := readMeta(entryDir)
		if err != nil || meta.State != "held" {
			continue
		}
		status, err := pollStatus(cfg, meta.QuarantineID)
		if err != nil {
			log.Printf("held poller: poll status for %s: %v", meta.Filename, err)
			continue
		}
		switch status {
		case "approved":
			markReleased(meta.OriginalPath)
			if err := moveFile(payloadPath(entryDir), meta.OriginalPath); err != nil {
				log.Printf("held poller: release %s: %v", meta.Filename, err)
				continue
			}
			os.RemoveAll(entryDir)
			notify("Mirraura", meta.Filename+" was approved and has been released.")
		case "rejected":
			meta.State = "blocked"
			writeMeta(entryDir, meta)
			notify("Mirraura — rejected", meta.Filename+" was rejected and stays quarantined.")
		case "pending":
			// still waiting on a human -- check again next tick
		}
	}
}
