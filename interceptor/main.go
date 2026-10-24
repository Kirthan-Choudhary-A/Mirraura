package main

import (
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/fsnotify/fsnotify"
)

const (
	settleDelay       = 750 * time.Millisecond
	workerPoolSize    = 3
	mountPollInterval = 2 * time.Second
	heldPollInterval  = 5 * time.Second
	procMountsPath    = "/proc/mounts"
)

func main() {
	cfg, err := loadConfig()
	if err != nil {
		log.Fatal(err)
	}
	if err := os.MkdirAll(cfg.QuarantineDir, 0700); err != nil {
		log.Fatalf("create quarantine dir: %v", err)
	}
	log.Printf("mirraura-interceptor: watching %s, quarantine at %s", cfg.Home, cfg.QuarantineDir)

	jobs := make(chan string, 256)
	runWorkers(cfg, jobs, workerPoolSize)
	go runHeldPoller(cfg, heldPollInterval, nil)

	// Startup sweep: anything left "pending_submit" means the daemon
	// crashed between quarantining a file and submitting it -- resubmit now
	// rather than leaving it stuck. "held" entries need no action here;
	// the held-poller's own periodic scan already picks them up.
	resubmitPendingEntries(cfg)

	w, err := fsnotify.NewWatcher()
	if err != nil {
		log.Fatalf("create watcher: %v", err)
	}
	defer w.Close()
	if err := watchRecursively(w, cfg.Home, cfg.ExactExcludes); err != nil {
		log.Fatalf("initial watch of %s: %v", cfg.Home, err)
	}

	stab := newStabilizer(settleDelay)
	go func() {
		for path := range stab.stable {
			jobs <- path
		}
	}()

	go pollRemovableMedia(cfg, jobs)

	runWatchLoop(w, cfg.ExactExcludes, stab)
}

func resubmitPendingEntries(cfg Config) {
	ids, err := listQuarantineEntries(cfg.QuarantineDir)
	if err != nil {
		log.Printf("startup sweep: %v", err)
		return
	}
	for _, id := range ids {
		entryDir := quarantineEntryDir(cfg.QuarantineDir, id)
		meta, err := readMeta(entryDir)
		if err != nil || meta.State != "pending_submit" {
			continue
		}
		log.Printf("startup sweep: resubmitting %s", meta.Filename)
		submitAndAct(cfg, entryDir, meta)
	}
}

// pollRemovableMedia polls /proc/mounts for newly mounted removable media
// (the classic plug-in-a-USB-drive case) and sweeps every existing file
// already on it into jobs -- an already-infected drive gets scanned, not
// just files added to it afterward.
func pollRemovableMedia(cfg Config, jobs chan<- string) {
	known, err := removableMountPaths(procMountsPath)
	if err != nil {
		log.Printf("removable media: initial read of %s: %v", procMountsPath, err)
		known = nil
	}
	ticker := time.NewTicker(mountPollInterval)
	defer ticker.Stop()
	for range ticker.C {
		current, err := removableMountPaths(procMountsPath)
		if err != nil {
			continue
		}
		for _, mount := range newMounts(known, current) {
			log.Printf("removable media mounted: %s -- sweeping", mount)
			sweepDirectory(mount, cfg.ExactExcludes, jobs)
		}
		known = current
	}
}

// sweepDirectory walks root and enqueues every regular file found,
// skipping excluded directories. Used both for a freshly mounted drive and
// could be reused for any future "scan this whole tree now" need.
func sweepDirectory(root string, exactExcludes []string, jobs chan<- string) {
	filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if path != root && shouldSkipDir(path, exactExcludes) {
				return filepath.SkipDir
			}
			return nil
		}
		if shouldSkipFile(path) {
			return nil
		}
		jobs <- path
		return nil
	})
}
