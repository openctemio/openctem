package scanrun

import "testing"

// The guard's count is read from sensor-supplied metadata: never negative,
// never more than the task's targets; the unlisted rest counts only when
// every listed entry is the guard's.
func TestGuardRefusedCount(t *testing.T) {
	for _, c := range []struct{ guard, listed, total, targets, want int }{
		{2, 3, 3, 4, 2},   // mixed with a local-policy refusal
		{0, 1, 1, 2, 0},   // local policy only
		{2, 2, 6, 8, 6},   // the list is bounded: the rest are the guard's
		{2, 3, 6, 8, 2},   // the rest are not known to be the guard's
		{1, 1, 500, 1, 1}, // never more than the task's targets
		{-3, 0, 0, 5, 0},  // never negative
		{0, 0, 9, 5, 0},   // nothing listed: nothing counted
	} {
		if got := GuardRefusedCount(c.guard, c.listed, c.total, c.targets); got != c.want {
			t.Errorf("GuardRefusedCount(%d, %d, %d, %d) = %d, want %d", c.guard, c.listed, c.total, c.targets, got, c.want)
		}
	}
}
