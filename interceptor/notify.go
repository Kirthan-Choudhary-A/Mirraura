package main

import (
	"log"
	"os/exec"
)

// notify fires a desktop notification via notify-send, the standard
// freedesktop.org mechanism every mainstream Linux desktop environment
// implements. Best-effort: a VM with no notification daemon running (or a
// headless session) shouldn't crash the daemon over a missing toast --
// the outcome is already logged either way.
func notify(summary, body string) {
	if err := exec.Command("notify-send", summary, body).Run(); err != nil {
		log.Printf("notify-send failed (continuing): %v", err)
	}
}
