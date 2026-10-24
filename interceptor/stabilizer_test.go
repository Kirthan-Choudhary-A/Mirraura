package main

import (
	"testing"
	"time"
)

func TestStabilizerAnnouncesAfterSettleDelay(t *testing.T) {
	s := newStabilizer(20 * time.Millisecond)
	s.touch("/home/user/Downloads/file.bin")

	select {
	case path := <-s.stable:
		t.Fatalf("announced too early: %s", path)
	case <-time.After(5 * time.Millisecond):
	}

	select {
	case path := <-s.stable:
		if path != "/home/user/Downloads/file.bin" {
			t.Fatalf("got %s", path)
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("never announced")
	}
}

func TestStabilizerResetsOnRepeatedTouch(t *testing.T) {
	s := newStabilizer(20 * time.Millisecond)
	s.touch("/home/user/Downloads/file.bin")
	time.Sleep(10 * time.Millisecond)
	s.touch("/home/user/Downloads/file.bin") // resets the timer -- still mid-write

	select {
	case path := <-s.stable:
		t.Fatalf("announced before settling: %s", path)
	case <-time.After(15 * time.Millisecond):
	}

	select {
	case <-s.stable:
	case <-time.After(100 * time.Millisecond):
		t.Fatal("never announced after settling")
	}
}

func TestStabilizerCancel(t *testing.T) {
	s := newStabilizer(10 * time.Millisecond)
	s.touch("/home/user/Downloads/dir")
	s.cancel("/home/user/Downloads/dir")

	select {
	case path := <-s.stable:
		t.Fatalf("cancelled path was still announced: %s", path)
	case <-time.After(50 * time.Millisecond):
	}
}
