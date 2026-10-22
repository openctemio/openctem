package widgets

import (
	"testing"
	"time"
)

// A person gets a burst of previews, then one per PreviewEvery; another
// person is not affected, and idle buckets are dropped.
func TestPreviewLimiter_PerPersonBurstAndRefill(t *testing.T) {
	l := newPreviewLimiter(3, 2*time.Second)
	now := time.Unix(1_000_000, 0)
	for i := 0; i < 3; i++ {
		if w := l.take("t/a", now); w != 0 {
			t.Fatalf("preview %d waited %s", i, w)
		}
	}
	w := l.take("t/a", now)
	if w <= 0 || w > 2*time.Second {
		t.Fatalf("over the burst: wait = %s, want (0, 2s]", w)
	}
	if w := l.take("t/b", now); w != 0 {
		t.Fatalf("another person waited %s", w)
	}
	if w := l.take("t/a", now.Add(2*time.Second)); w != 0 {
		t.Fatalf("after one interval: wait = %s", w)
	}
	if w := l.take("t/a", now.Add(2*time.Second)); w == 0 {
		t.Fatal("second preview in the same interval was allowed")
	}
	l.take("t/c", now.Add(time.Hour))
	if _, ok := l.buckets["t/b"]; ok {
		t.Error("idle bucket kept")
	}
}
