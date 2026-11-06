package command

import (
	"testing"
	"time"
)

func TestLeaseRenewBefore(t *testing.T) {
	lease := 3 * time.Minute
	cases := []struct {
		interval, want time.Duration
	}{
		{0, lease},                            // unknown interval: renew on every heartbeat
		{5 * time.Second, 90 * time.Second},   // busy: half the lease
		{30 * time.Second, 90 * time.Second},  // idle: half the lease (2 × 30 s + 10 s = 70 s)
		{60 * time.Second, 130 * time.Second}, // lease / 3: two intervals + margin
		{5 * time.Minute, lease},              // longer than the lease: every heartbeat
	}
	for _, c := range cases {
		if got := LeaseRenewBefore(lease, c.interval); got != c.want {
			t.Errorf("LeaseRenewBefore(%v, %v) = %v, want %v", lease, c.interval, got, c.want)
		}
	}
	// One lost heartbeat never lets a lease run out: a beat that finds just
	// over the threshold left is followed by one 2 × interval later that
	// still finds a positive remainder below the threshold.
	for _, iv := range []time.Duration{time.Second, 5 * time.Second, 30 * time.Second, 60 * time.Second} {
		th := LeaseRenewBefore(lease, iv)
		if left := th - 2*iv; left <= 0 && th < lease {
			t.Errorf("interval %v: threshold %v leaves %v after a lost heartbeat", iv, th, left)
		}
	}
}
