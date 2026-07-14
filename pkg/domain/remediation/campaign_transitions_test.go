package remediation

import (
	"errors"
	"testing"

	"github.com/openctemio/api/pkg/domain/shared"
)

// Transition invariants beyond the happy path — the validation-fail loopback
// and the manual reopen added for CTEM Stage-4 continuity.

func TestActivate_FromValidating_ReworkLoopback(t *testing.T) {
	c := newCampaign(t, CampaignStatusValidating)
	if err := c.Activate(); err != nil {
		t.Fatalf("validating→active (validation failed) should be allowed: %v", err)
	}
	if c.Status() != CampaignStatusActive {
		t.Fatalf("want active, got %s", c.Status())
	}
}

func TestReopen_FromCompleted(t *testing.T) {
	c := newCampaign(t, CampaignStatusCompleted)
	if c.CompletedAt() == nil {
		t.Fatal("completed campaign should have a completion timestamp")
	}
	if err := c.Reopen(); err != nil {
		t.Fatalf("reopen from completed should be allowed: %v", err)
	}
	if c.Status() != CampaignStatusActive {
		t.Fatalf("want active after reopen, got %s", c.Status())
	}
	if c.CompletedAt() != nil {
		t.Fatal("reopen must clear the completion timestamp")
	}
}

func TestReopen_RejectedFromNonCompleted(t *testing.T) {
	for _, st := range []CampaignStatus{
		CampaignStatusDraft, CampaignStatusActive, CampaignStatusPaused,
		CampaignStatusValidating, CampaignStatusCanceled,
	} {
		c := newCampaign(t, st)
		if err := c.Reopen(); !errors.Is(err, shared.ErrValidation) {
			t.Fatalf("reopen from %s should be rejected, got %v", st, err)
		}
	}
}

func TestActivate_RejectedFromCompletedOrCanceled(t *testing.T) {
	for _, st := range []CampaignStatus{CampaignStatusCompleted, CampaignStatusCanceled} {
		c := newCampaign(t, st)
		if err := c.Activate(); !errors.Is(err, shared.ErrValidation) {
			t.Fatalf("activate from %s should be rejected, got %v", st, err)
		}
	}
}
