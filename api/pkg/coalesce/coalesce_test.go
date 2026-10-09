package coalesce

import (
	"strconv"
	"sync/atomic"
	"testing"
	"time"
)

func TestThrottle_RunsOnceThenFoldsIntoOneTrailingRun(t *testing.T) {
	th := New(50 * time.Millisecond)
	var runs atomic.Int32
	fn := func() { runs.Add(1) }

	if th.Do("k", fn) {
		t.Fatal("the first call must run at once")
	}
	if runs.Load() != 1 {
		t.Fatalf("runs = %d after the first call", runs.Load())
	}
	for range 100 {
		if !th.Do("k", fn) {
			t.Fatal("a call inside the interval must be folded")
		}
	}
	if runs.Load() != 1 {
		t.Fatalf("runs = %d inside the interval, want 1", runs.Load())
	}
	// Another key is independent.
	th.Do("other", fn)
	if runs.Load() != 2 {
		t.Fatalf("another key did not run at once: %d", runs.Load())
	}
	// The folded calls become exactly one run when the interval ends.
	deadline := time.Now().Add(2 * time.Second)
	for runs.Load() < 3 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	time.Sleep(120 * time.Millisecond)
	if runs.Load() != 3 {
		t.Fatalf("runs = %d, want the trailing run exactly once", runs.Load())
	}
}

func TestThrottle_ZeroIntervalRunsEveryCall(t *testing.T) {
	th := New(0)
	n := 0
	for range 5 {
		th.Do("k", func() { n++ })
	}
	if n != 5 {
		t.Fatalf("runs = %d", n)
	}
}

func TestThrottle_PrunesIdleKeys(t *testing.T) {
	th := New(time.Millisecond)
	for i := range pruneFloor {
		th.Do(strconv.Itoa(i), func() {})
	}
	time.Sleep(5 * time.Millisecond)
	th.Do("new", func() {})
	if n := th.Len(); n != 1 {
		t.Fatalf("keys = %d after a sweep, want only the new one", n)
	}
}
