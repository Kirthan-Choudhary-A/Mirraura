package main

import (
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"
)

func TestRemovableMountPaths(t *testing.T) {
	content := `proc /proc proc rw 0 0
/dev/sda1 / ext4 rw 0 0
/dev/sdb1 /media/user/USBDRIVE vfat rw,nosuid 0 0
tmpfs /mnt/external tmpfs rw 0 0
/dev/sdc1 /home ext4 rw 0 0
`
	path := filepath.Join(t.TempDir(), "mounts")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	mounts, err := removableMountPaths(path)
	if err != nil {
		t.Fatalf("removableMountPaths: %v", err)
	}
	sort.Strings(mounts)
	want := []string{"/media/user/USBDRIVE", "/mnt/external"}
	if !reflect.DeepEqual(mounts, want) {
		t.Fatalf("got %v, want %v", mounts, want)
	}
}

func TestNewMounts(t *testing.T) {
	before := []string{"/media/usb1"}
	after := []string{"/media/usb1", "/media/usb2"}
	added := newMounts(before, after)
	if len(added) != 1 || added[0] != "/media/usb2" {
		t.Fatalf("expected [/media/usb2], got %v", added)
	}
}

func TestNewMountsNoneAdded(t *testing.T) {
	before := []string{"/media/usb1"}
	after := []string{"/media/usb1"}
	if added := newMounts(before, after); len(added) != 0 {
		t.Fatalf("expected no new mounts, got %v", added)
	}
}
