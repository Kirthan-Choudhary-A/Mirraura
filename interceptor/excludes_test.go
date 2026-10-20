package main

import "testing"

// shouldSkipDir only inspects dir's own basename, not its ancestors --
// correct because filepath.WalkDir's SkipDir already stops the walk from
// ever descending into an excluded directory's children in the first
// place, so a nested path like ".config/app" is never offered to this
// function at all in real usage.
func TestShouldSkipDir(t *testing.T) {
	quarantine := "/home/user/.mirraura-quarantine"
	cases := map[string]bool{
		"/home/user/Downloads":            false,
		"/home/user/Documents/reports":    false,
		"/home/user/.cache":               true,
		"/home/user/.config":              true,
		"/home/user/.mirraura-quarantine": true,
		"/media/usb/Documents":            false,
	}
	for dir, want := range cases {
		if got := shouldSkipDir(dir, quarantine); got != want {
			t.Errorf("shouldSkipDir(%q) = %v, want %v", dir, got, want)
		}
	}
}
