package remediation

import (
	"testing"

	"github.com/openctemio/api/pkg/domain/shared"
)

// Q4/WS-E: TryAutoComplete invariants. The campaign must advance to
// completed ONLY when (1) all findings are resolved AND (2) the
// current state permits the transition.

func newCampaign(t *testing.T, status CampaignStatus) *Campaign {
	t.Helper()
	c, err := NewCampaign(shared.NewID(), "test", CampaignPriorityHigh)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	// Walk from draft → requested state.
	switch status {
	case CampaignStatusDraft:
		// already there
	case CampaignStatusActive:
		_ = c.Activate()
	case CampaignStatusPaused:
		_ = c.Activate()
		_ = c.Pause()
	case CampaignStatusValidating:
		_ = c.Activate()
		_ = c.StartValidation()
	case CampaignStatusCompleted:
		_ = c.Activate()
		_ = c.Complete()
	case CampaignStatusCanceled:
		c.Cancel()
	}
	if c.Status() != status {
		t.Fatalf("could not drive to %s, stuck at %s", status, c.Status())
	}
	return c
}

func TestAllFindingsResolved_Empty(t *testing.T) {
	c := newCampaign(t, CampaignStatusActive)
	if c.AllFindingsResolved() {
		t.Fatal("empty campaign should not count as resolved")
	}
}

func TestAllFindingsResolved_Partial(t *testing.T) {
	c := newCampaign(t, CampaignStatusActive)
	c.UpdateProgress(10, 5)
	if c.AllFindingsResolved() {
		t.Fatal("5/10 is not all resolved")
	}
}

func TestAllFindingsResolved_Full(t *testing.T) {
	c := newCampaign(t, CampaignStatusActive)
	c.UpdateProgress(10, 10)
	if !c.AllFindingsResolved() {
		t.Fatal("10/10 must be all resolved")
	}
}

func TestAllFindingsResolved_ResolvedExceedsTotal(t *testing.T) {
	// Defensive: if the counts get momentarily inconsistent (race
	// between an ingest adding 1 and a worker marking it resolved),
	// the guard must still trigger rather than get stuck below 100%.
	c := newCampaign(t, CampaignStatusActive)
	c.UpdateProgress(3, 5)
	if !c.AllFindingsResolved() {
		t.Fatal("resolved ≥ total must count as all-resolved")
	}
}

func TestTryAutoComplete_FromActive(t *testing.T) {
	c := newCampaign(t, CampaignStatusActive)
	c.UpdateProgress(3, 3)
	done, err := c.TryAutoComplete()
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !done {
		t.Fatal("should auto-complete")
	}
	if c.Status() != CampaignStatusCompleted {
		t.Fatalf("status = %s", c.Status())
	}
	if c.CompletedAt() == nil {
		t.Fatal("completed_at must be set")
	}
}

func TestTryAutoComplete_FromValidating(t *testing.T) {
	c := newCampaign(t, CampaignStatusValidating)
	c.UpdateProgress(3, 3)
	done, err := c.TryAutoComplete()
	if err != nil || !done {
		t.Fatalf("should auto-complete from validating: done=%v err=%v", done, err)
	}
	if c.Status() != CampaignStatusCompleted {
		t.Fatalf("status = %s", c.Status())
	}
}

func TestTryAutoComplete_NotEligibleWhenPaused(t *testing.T) {
	// Paused means an operator explicitly stopped — we must not
	// auto-complete out of it even if all findings later become
	// resolved.
	c := newCampaign(t, CampaignStatusPaused)
	c.UpdateProgress(3, 3)
	done, err := c.TryAutoComplete()
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if done {
		t.Fatal("paused campaign must not auto-complete")
	}
	if c.Status() != CampaignStatusPaused {
		t.Fatalf("status = %s, want paused", c.Status())
	}
}

func TestTryAutoComplete_NotEligibleWhenDraft(t *testing.T) {
	c := newCampaign(t, CampaignStatusDraft)
	c.UpdateProgress(3, 3)
	done, err := c.TryAutoComplete()
	if err != nil || done {
		t.Fatalf("draft must not auto-complete: done=%v err=%v", done, err)
	}
}

func TestTryAutoComplete_NotEligibleWhenPartialProgress(t *testing.T) {
	c := newCampaign(t, CampaignStatusActive)
	c.UpdateProgress(10, 8)
	done, err := c.TryAutoComplete()
	if err != nil || done {
		t.Fatal("partial progress must not auto-complete")
	}
}

func TestTryAutoComplete_IdempotentAfterCompletion(t *testing.T) {
	c := newCampaign(t, CampaignStatusActive)
	c.UpdateProgress(3, 3)
	done1, err := c.TryAutoComplete()
	if err != nil || !done1 {
		t.Fatalf("first call: %v", err)
	}
	// Second call on an already-completed campaign must be a no-op
	// (done=false, err=nil) — otherwise a re-running worker would
	// either panic or double-notify.
	done2, err := c.TryAutoComplete()
	if err != nil {
		t.Fatalf("second call err: %v", err)
	}
	if done2 {
		t.Fatal("second call on completed campaign must return done=false")
	}
}

func TestTryAutoComplete_EmptyCampaignDoesNotComplete(t *testing.T) {
	// A zero-finding campaign is almost always a misconfiguration
	// (wrong filter, no matching findings yet). Auto-completing
	// would signal "done" for something that never started.
	c := newCampaign(t, CampaignStatusActive)
	done, err := c.TryAutoComplete()
	if err != nil || done {
		t.Fatal("empty campaign must not auto-complete")
	}
}
