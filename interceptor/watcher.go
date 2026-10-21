package main

import (
	"log"
	"os"
	"path/filepath"

	"github.com/fsnotify/fsnotify"
)

// watchRecursively adds w as a watch on root and every subdirectory under
// it (fsnotify only watches the directory you add, not its children), and
// keeps adding watches for new directories as they're created. Every
// write/create to a regular file touches the stabilizer; the stabilizer's
// own settle delay is what actually decides when a file is "done."
func watchRecursively(w *fsnotify.Watcher, root, quarantineDir string) error {
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil // unreadable subtree (permissions, race with deletion) -- skip, don't abort the whole walk
		}
		if d.IsDir() {
			if path != root && shouldSkipDir(path, quarantineDir) {
				return filepath.SkipDir
			}
			if err := w.Add(path); err != nil {
				log.Printf("watch %s: %v", path, err)
			}
		}
		return nil
	})
	return err
}

// runWatchLoop consumes fsnotify events forever, adding watches for newly
// created directories and touching the stabilizer for file writes/creates.
func runWatchLoop(w *fsnotify.Watcher, quarantineDir string, stab *stabilizer) {
	for {
		select {
		case event, ok := <-w.Events:
			if !ok {
				return
			}
			handleEvent(w, event, quarantineDir, stab)
		case err, ok := <-w.Errors:
			if !ok {
				return
			}
			log.Printf("watcher error: %v", err)
		}
	}
}

func handleEvent(w *fsnotify.Watcher, event fsnotify.Event, quarantineDir string, stab *stabilizer) {
	info, err := os.Stat(event.Name)
	if err != nil {
		// File/dir disappeared (e.g. a rename-away or delete) between the
		// event firing and this stat -- nothing left to quarantine.
		stab.cancel(event.Name)
		return
	}
	if info.IsDir() {
		if event.Op&(fsnotify.Create) != 0 && !shouldSkipDir(event.Name, quarantineDir) {
			if err := w.Add(event.Name); err != nil {
				log.Printf("watch %s: %v", event.Name, err)
			}
		}
		return
	}
	if shouldSkipDir(filepath.Dir(event.Name), quarantineDir) || shouldSkipFile(event.Name) {
		return
	}
	if event.Op&(fsnotify.Write|fsnotify.Create) != 0 {
		if isJustReleased(event.Name) {
			return
		}
		stab.touch(event.Name)
	}
}
