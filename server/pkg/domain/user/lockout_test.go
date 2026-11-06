package user

import (
	"testing"
	"time"
)

// Every failed attempt counts, including those made while the account is
// already locked, and each further run of maxAttempts failures doubles the
// lock, up to MaxLockoutDuration (research/189 B1a-1).
func TestLockoutAfter_BacksOff(t *testing.T) {
	const base = 15 * time.Minute
	cases := []struct {
		attempts int
		want     time.Duration
	}{
		{1, 0}, {4, 0},
		{5, base},
		{6, 0}, {9, 0}, // counted, the current lock is kept
		{10, 2 * base},
		{15, 4 * base},
		{20, 8 * base},
		{5 + 5*20, MaxLockoutDuration},
		{5 + 5*10000, MaxLockoutDuration},
	}
	for _, c := range cases {
		if got := LockoutAfter(c.attempts, 5, base); got != c.want {
			t.Errorf("LockoutAfter(%d) = %v, want %v", c.attempts, got, c.want)
		}
	}
	if got := LockoutAfter(3, 0, base); got != 0 {
		t.Errorf("maxAttempts 0 must not lock, got %v", got)
	}
}

func TestRecordFailedLogin_CountsDuringLockAndBacksOff(t *testing.T) {
	u := &User{}
	for range 5 {
		u.RecordFailedLogin(5, 15*time.Minute)
	}
	if !u.IsLocked() {
		t.Fatal("not locked after 5 failures")
	}
	first := *u.LockedUntil()
	for range 4 {
		u.RecordFailedLogin(5, 15*time.Minute)
	}
	if u.FailedLoginAttempts() != 9 {
		t.Fatalf("attempts during the lock not counted: %d", u.FailedLoginAttempts())
	}
	if !u.LockedUntil().Equal(first) {
		t.Fatal("the lock moved before the next run of failures")
	}
	u.RecordFailedLogin(5, 15*time.Minute)
	if d := time.Until(*u.LockedUntil()); d < 29*time.Minute || d > 31*time.Minute {
		t.Fatalf("after 10 failures the lock is %v, want about 30m", d)
	}
}
