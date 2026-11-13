package toolbudget

import (
	"testing"
	"time"
)

func TestForTask(t *testing.T) {
	// The incident's httpx task: 72 targets, 25 at a time, 15 s per target.
	got := ForTask("httpx", 72)
	if got.TargetSeconds != 15 {
		t.Errorf("httpx per target = %ds, want 15", got.TargetSeconds)
	}
	if got.TaskSeconds != int(MinTask/time.Second) {
		t.Errorf("httpx task = %ds, want the %s floor", got.TaskSeconds, MinTask)
	}
	if got.StallSeconds != int(MinStall/time.Second) {
		t.Errorf("httpx stall = %ds, want %s", got.StallSeconds, MinStall)
	}

	// nuclei: 25 targets, 10 at a time, 15 min per target: 2 min + 3 × 15 min.
	got = ForTask("nuclei", 25)
	if got.TargetSeconds != 900 || got.TaskSeconds != 120+3*900 || got.StallSeconds != 2700 {
		t.Errorf("nuclei = %+v", got)
	}

	// A huge chunk never exceeds the 24 h cap; zero targets count as one.
	if got := ForTask("unknown", 100000); got.TaskSeconds != int(MaxTask/time.Second) || got.StallSeconds != 3*360 {
		t.Errorf("unknown x100000 = %+v", got)
	}
	if got := ForTask("dnsx", 0); got.TaskSeconds != int(MinTask/time.Second) {
		t.Errorf("dnsx x0 = %+v", got)
	}
}

func TestPerTargetWithinBounds(t *testing.T) {
	for name := range defaults {
		b := For(name)
		if p := b.PerTarget(); p < b.Floor || p > b.Ceiling {
			t.Errorf("%s per target %s outside [%s, %s]", name, p, b.Floor, b.Ceiling)
		}
	}
}
