package toolbudget

import (
	"testing"
	"time"
)

func TestForKnownAndFallback(t *testing.T) {
	if got := For(" Nuclei "); got != defaults["nuclei"] {
		t.Fatalf("For(nuclei) = %+v", got)
	}
	if got := For("no-such-tool"); got != fallback {
		t.Fatalf("unknown tool = %+v, want fallback", got)
	}
}

func TestDefaultsAreBounded(t *testing.T) {
	for name, b := range defaults {
		if b.Floor <= 0 || b.Floor > b.Expected || b.Expected > b.Ceiling {
			t.Errorf("%s: want 0 < floor <= expected <= ceiling, got %+v", name, b)
		}
		if b.Concurrency < 1 || b.Overhead <= 0 {
			t.Errorf("%s: concurrency and overhead must be positive: %+v", name, b)
		}
	}
}

func TestMinUseful(t *testing.T) {
	if got := For("nuclei").MinUseful(); got != 7*time.Minute {
		t.Fatalf("nuclei MinUseful = %s, want 7m", got)
	}
}
