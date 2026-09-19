package main

import "testing"

func TestLoginLimiterAllowsUnderThreshold(t *testing.T) {
	l := NewLoginLimiter()
	for i := 0; i < 4; i++ {
		if !l.Allow("1.2.3.4") {
			t.Fatalf("expected Allow to be true on attempt %d", i+1)
		}
		l.RecordFailure("1.2.3.4")
	}
}

func TestLoginLimiterBlocksAfterFiveFailures(t *testing.T) {
	l := NewLoginLimiter()
	for i := 0; i < 5; i++ {
		l.RecordFailure("1.2.3.4")
	}
	if l.Allow("1.2.3.4") {
		t.Fatal("expected Allow to be false after 5 failures")
	}
}

func TestLoginLimiterIsPerIP(t *testing.T) {
	l := NewLoginLimiter()
	for i := 0; i < 5; i++ {
		l.RecordFailure("1.2.3.4")
	}
	if !l.Allow("5.6.7.8") {
		t.Fatal("expected a different IP to be unaffected by another IP's failures")
	}
}
