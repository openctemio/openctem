package coverage

import (
	"fmt"
	"testing"
	"time"
)

func TestJitterFraction_DeterministicAndBounded(t *testing.T) {
	a := JitterFraction("0b7f5b1e-3a0c-4d4e-9f00-000000000001", "probe.http")
	if a != JitterFraction("0b7f5b1e-3a0c-4d4e-9f00-000000000001", "probe.http") {
		t.Fatal("jitter is not deterministic")
	}
	if a == JitterFraction("0b7f5b1e-3a0c-4d4e-9f00-000000000001", "scan.ports") {
		t.Error("two capabilities of one asset share a phase")
	}
	lo, hi := 1.0, 0.0
	for i := 0; i < 2000; i++ {
		f := JitterFraction(fmt.Sprintf("00000000-0000-0000-0000-%012d", i), "resolve.dns")
		if f < 0 || f >= 1 {
			t.Fatalf("fraction %v out of [0, 1)", f)
		}
		lo, hi = min(lo, f), max(hi, f)
	}
	// Spread over the range, not clustered.
	if lo > 0.01 || hi < 0.99 {
		t.Errorf("fractions span [%v, %v], want close to [0, 1)", lo, hi)
	}
}

func TestJittered_WithinTenPercent(t *testing.T) {
	every := 24 * time.Hour
	for i := 0; i < 500; i++ {
		d := Jittered(every, fmt.Sprintf("id-%d", i), "resolve.dns")
		if d < every || d >= every+every/10 {
			t.Fatalf("jittered %v outside [%v, %v)", d, every, every+every/10)
		}
	}
}

func TestLookahead(t *testing.T) {
	for every, want := range map[time.Duration]time.Duration{
		0:                   0,
		-time.Hour:          0,
		time.Hour:           6 * time.Minute,
		24 * time.Hour:      time.Hour,
		7 * 24 * time.Hour:  time.Hour,
		30 * time.Minute:    3 * time.Minute,
		3 * 24 * time.Hour:  time.Hour,
		10 * time.Hour:      time.Hour,
		5 * time.Hour:       30 * time.Minute,
		90 * 24 * time.Hour: time.Hour,
	} {
		if got := Lookahead(every); got != want {
			t.Errorf("Lookahead(%v) = %v, want %v", every, got, want)
		}
	}
}
