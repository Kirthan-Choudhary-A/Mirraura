package main

import (
	"bufio"
	"os"
	"strings"
)

// removableMountPaths parses /proc/mounts and returns every mount point
// under /media or /mnt -- the standard auto-mount locations a Linux
// desktop environment (udisks2-backed) puts a plugged-in USB drive.
func removableMountPaths(procMountsPath string) ([]string, error) {
	f, err := os.Open(procMountsPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var mounts []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 2 {
			continue
		}
		mountPoint := fields[1]
		if strings.HasPrefix(mountPoint, "/media/") || strings.HasPrefix(mountPoint, "/mnt/") {
			mounts = append(mounts, mountPoint)
		}
	}
	return mounts, scanner.Err()
}

// newMounts returns entries in after that weren't in before -- the mount
// points that appeared since the last poll.
func newMounts(before, after []string) []string {
	seen := make(map[string]bool, len(before))
	for _, m := range before {
		seen[m] = true
	}
	var added []string
	for _, m := range after {
		if !seen[m] {
			added = append(added, m)
		}
	}
	return added
}
