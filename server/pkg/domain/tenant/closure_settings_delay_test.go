package tenant

import (
	"testing"
	"time"
)

func TestClosureSettings_ChooseWaitsOnLoosening(t *testing.T) {
	now := time.Date(2026, 10, 30, 10, 0, 0, 0, time.UTC)
	var s ClosureSettings // review

	waits, err := s.Choose(ClosureSettings{Mode: ClosingModeAuto, CriticalAutoClose: true}, now)
	if err != nil || !waits {
		t.Fatalf("loosening must wait: %v %v", waits, err)
	}
	if got := s.EffectiveAt(now.Add(23 * time.Hour)); got.EffectiveMode() != ClosingModeReview || got.CriticalAutoClose {
		t.Fatalf("before the delay: %+v", got)
	}
	if got := s.EffectiveAt(now.Add(ClosureRelaxationDelay)); got.Mode != ClosingModeAuto || !got.CriticalAutoClose {
		t.Fatalf("after the delay: %+v", got)
	}
	if _, at, ok := s.PendingIn(now); !ok || !at.Equal(now.Add(ClosureRelaxationDelay)) {
		t.Fatalf("pending: %v %v", at, ok)
	}

	// Mixed change: auto with critical in review while off is in force,
	// from auto+critical. The tightening part (critical back in review)
	// applies at once.
	s = ClosureSettings{Mode: ClosingModeReview, CriticalAutoClose: true}
	waits, _ = s.Choose(ClosureSettings{Mode: ClosingModeAuto}, now)
	if !waits || s.EffectiveAt(now).CriticalAutoClose || s.EffectiveAt(now).Mode != ClosingModeReview {
		t.Fatalf("mixed: %+v", s)
	}

	// Tightening applies at once and cancels the wait.
	if waits, _ := s.Choose(ClosureSettings{Mode: ClosingModeOff}, now.Add(time.Hour)); waits || s.PendingAt != nil || s.Mode != ClosingModeOff {
		t.Fatalf("tighten: %+v", s)
	}

	// Cancel keeps what is in force; a loosening whose time came stays.
	s = ClosureSettings{Mode: ClosingModeOff}
	_, _ = s.Choose(ClosureSettings{Mode: ClosingModeAuto}, now)
	if !s.CancelPending(now.Add(time.Hour)) || s.Mode != ClosingModeOff || s.PendingAt != nil {
		t.Fatalf("cancel: %+v", s)
	}
	_, _ = s.Choose(ClosureSettings{Mode: ClosingModeAuto}, now)
	if s.CancelPending(now.Add(25*time.Hour)) || s.Mode != ClosingModeAuto {
		t.Fatalf("cancel after the delay: %+v", s)
	}
	if _, err := s.Choose(ClosureSettings{Mode: "sometimes"}, now); err == nil {
		t.Fatal("bad mode accepted")
	}
}
