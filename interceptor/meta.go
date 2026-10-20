package main

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
)

// QuarantineMeta is the sidecar record kept next to every quarantined
// file's payload, under <quarantineDir>/<id>/meta.json. The filesystem IS
// the daemon's durable state: a restart just rescans quarantineDir instead
// of needing a local database, and "held" entries get picked back up by
// the same periodic scan that looks for them in normal operation.
type QuarantineMeta struct {
	OriginalPath string `json:"original_path"`
	Filename     string `json:"filename"`
	// State: "pending_submit" (quarantined, not yet sent to the backend --
	// only seen if the daemon crashed between quarantining and submitting),
	// "held" (backend said hold, waiting on a human decision),
	// "blocked" (backend said block -- terminal, left in quarantine).
	State        string `json:"state"`
	QuarantineID int64  `json:"quarantine_id,omitempty"`
}

func quarantineEntryDir(quarantineDir, id string) string {
	return filepath.Join(quarantineDir, id)
}

func payloadPath(entryDir string) string {
	return filepath.Join(entryDir, "payload")
}

func metaPath(entryDir string) string {
	return filepath.Join(entryDir, "meta.json")
}

func writeMeta(entryDir string, m QuarantineMeta) error {
	data, err := json.Marshal(m)
	if err != nil {
		return err
	}
	return os.WriteFile(metaPath(entryDir), data, 0600)
}

func readMeta(entryDir string) (QuarantineMeta, error) {
	var m QuarantineMeta
	data, err := os.ReadFile(metaPath(entryDir))
	if err != nil {
		return m, err
	}
	err = json.Unmarshal(data, &m)
	return m, err
}

// listQuarantineEntries returns every entry directory's id under
// quarantineDir that has a readable meta.json. Missing/corrupt entries are
// skipped rather than failing the whole scan -- one bad entry shouldn't
// block recovery of every other one.
func listQuarantineEntries(quarantineDir string) ([]string, error) {
	entries, err := os.ReadDir(quarantineDir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var ids []string
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		if _, err := readMeta(filepath.Join(quarantineDir, e.Name())); err != nil {
			continue
		}
		ids = append(ids, e.Name())
	}
	return ids, nil
}

// moveFile moves src to dst, preferring an atomic same-filesystem rename
// and falling back to copy-then-remove when they're on different
// filesystems (EXDEV) -- the common case for a file swept in from a
// removable-media mount, since the quarantine directory lives under $HOME.
func moveFile(src, dst string) error {
	if err := os.MkdirAll(filepath.Dir(dst), 0700); err != nil {
		return err
	}
	if err := os.Rename(src, dst); err == nil {
		return nil
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		os.Remove(dst)
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	return os.Remove(src)
}
