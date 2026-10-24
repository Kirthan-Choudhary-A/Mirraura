package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWriteReadMetaRoundTrip(t *testing.T) {
	dir := t.TempDir()
	want := QuarantineMeta{
		OriginalPath: "/home/user/Downloads/sample.sh",
		Filename:     "sample.sh",
		State:        "held",
		QuarantineID: 42,
	}
	if err := writeMeta(dir, want); err != nil {
		t.Fatalf("writeMeta: %v", err)
	}
	got, err := readMeta(dir)
	if err != nil {
		t.Fatalf("readMeta: %v", err)
	}
	if got != want {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}

func TestListQuarantineEntriesSkipsEntriesWithoutMeta(t *testing.T) {
	root := t.TempDir()
	good := quarantineEntryDir(root, "good")
	bad := quarantineEntryDir(root, "bad")
	os.MkdirAll(good, 0700)
	os.MkdirAll(bad, 0700)
	writeMeta(good, QuarantineMeta{Filename: "x", State: "held"})
	// "bad" has no meta.json at all.

	ids, err := listQuarantineEntries(root)
	if err != nil {
		t.Fatalf("listQuarantineEntries: %v", err)
	}
	if len(ids) != 1 || ids[0] != "good" {
		t.Fatalf("expected only [good], got %v", ids)
	}
}

func TestListQuarantineEntriesOnMissingDir(t *testing.T) {
	ids, err := listQuarantineEntries(filepath.Join(t.TempDir(), "does-not-exist"))
	if err != nil {
		t.Fatalf("expected no error for a missing quarantine dir, got %v", err)
	}
	if ids != nil {
		t.Fatalf("expected nil, got %v", ids)
	}
}

func TestMoveFileSameFilesystem(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src.txt")
	dst := filepath.Join(dir, "sub", "dst.txt")
	if err := os.WriteFile(src, []byte("hello"), 0644); err != nil {
		t.Fatal(err)
	}

	if err := moveFile(src, dst); err != nil {
		t.Fatalf("moveFile: %v", err)
	}
	if _, err := os.Stat(src); !os.IsNotExist(err) {
		t.Fatal("expected src to be gone after move")
	}
	data, err := os.ReadFile(dst)
	if err != nil {
		t.Fatalf("read dst: %v", err)
	}
	if string(data) != "hello" {
		t.Fatalf("got %q", data)
	}
}
