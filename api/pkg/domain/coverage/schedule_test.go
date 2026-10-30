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

func TestBatchWait_TenthOfCadenceCappedAtSixHours(t *testing.T) {
	for _, c := range []struct {
		every, want time.Duration
	}{
		{24 * time.Hour, 144 * time.Minute},
		{3 * 24 * time.Hour, 6 * time.Hour},
		{7 * 24 * time.Hour, 6 * time.Hour},
		{time.Hour, 6 * time.Minute},
		{0, 0},
	} {
		if got := BatchWait(c.every); got != c.want {
			t.Errorf("BatchWait(%v) = %v, want %v", c.every, got, c.want)
		}
	}
}

func TestBatchReady_FillsATaskOrWaitsAtMostTheBound(t *testing.T) {
	week := 7 * 24 * time.Hour
	cases := []struct {
		name     string
		n, min   int
		waited   time.Duration
		expected bool
	}{
		{"empty", 0, 25, 24 * time.Hour, false},
		{"fills one task", 25, 25, 0, true},
		{"more than one task", 60, 25, 0, true},
		{"small and fresh waits", 3, 25, time.Hour, false},
		{"small but waited the bound", 3, 25, 6 * time.Hour, true},
		{"tool without chunks", 1, 1, 0, true},
	}
	for _, c := range cases {
		if got := BatchReady(c.n, c.min, c.waited, week); got != c.expected {
			t.Errorf("%s: BatchReady(%d, %d, %v) = %v, want %v", c.name, c.n, c.min, c.waited, got, c.expected)
		}
	}
}

// Pairs settled together come due again spread over a tenth of the cadence
// (the jitter). With a one-hour coalescing window alone, a weekly
// capability started a run in nearly every hour of that spread; with the
// batch rule it starts one per filled task, or one when the oldest pair has
// waited the bound.
func TestBatchReady_JitteredPairsMakeFewRuns(t *testing.T) {
	const (
		pairs    = 100
		minBatch = 25
	)
	every := 7 * 24 * time.Hour
	settled := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	due := make([]time.Time, pairs)
	for i := range due {
		due[i] = settled.Add(Jittered(every, fmt.Sprintf("00000000-0000-0000-0000-%012d", i), "vuln.templates"))
	}
	runs := func(useBatchRule bool) (int, int) {
		taken := make([]bool, pairs)
		n, smallest := 0, pairs
		for now := settled.Add(every); now.Before(settled.Add(every + 24*time.Hour)); now = now.Add(time.Minute) {
			var batch []int
			anyDue, oldest := false, time.Duration(0)
			for i, d := range due {
				if taken[i] || d.After(now.Add(Lookahead(every))) {
					continue
				}
				batch = append(batch, i)
				if !d.After(now) {
					anyDue = true
					oldest = max(oldest, now.Sub(d))
				}
			}
			if !anyDue || (useBatchRule && !BatchReady(len(batch), minBatch, oldest, every)) {
				continue
			}
			for _, i := range batch {
				taken[i] = true
			}
			n++
			smallest = min(smallest, len(batch))
		}
		for i := range taken {
			if !taken[i] {
				t.Fatalf("pair %d was never started", i)
			}
		}
		return n, smallest
	}
	before, _ := runs(false)
	after, smallest := runs(true)
	if before < 10 {
		t.Fatalf("without the batch rule %d runs; the fixture no longer shows the fragmentation", before)
	}
	if after > pairs/minBatch+1 {
		t.Errorf("with the batch rule %d runs for %d pairs, want at most %d", after, pairs, pairs/minBatch+1)
	}
	if smallest < 5 {
		t.Errorf("smallest run carried %d pairs", smallest)
	}
}
