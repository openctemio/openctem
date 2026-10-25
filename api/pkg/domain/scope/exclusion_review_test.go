package scope

import (
	"errors"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func newTestExclusion(t *testing.T, until *time.Time) *Exclusion {
	t.Helper()
	e, err := NewExclusion(shared.NewID(), ExclusionTypeDomain, "prod.example.com", "fragile", until, "creator")
	if err != nil {
		t.Fatal(err)
	}
	return e
}

// Without review an exclusion takes effect at once, recorded as its
// creator's (or the system's) own approval; only once.
func TestExclusion_TakeEffect(t *testing.T) {
	e := newTestExclusion(t, nil)
	if err := e.TakeEffect("creator"); err != nil {
		t.Fatal(err)
	}
	if !e.InEffect() || e.ApprovedBy() != "creator" || e.ApprovedAt() == nil {
		t.Fatalf("status %s approved by %q", e.Status(), e.ApprovedBy())
	}
	if err := e.TakeEffect("creator"); !errors.Is(err, ErrExclusionNotPending) {
		t.Fatalf("second take effect: %v", err)
	}
	sys := newTestExclusion(t, nil)
	if err := sys.TakeEffect(""); err != nil || sys.ApprovedBy() != SystemReviewer {
		t.Fatalf("system path: %v %q", err, sys.ApprovedBy())
	}
	rejected := newTestExclusion(t, nil)
	_ = rejected.Reject("approver")
	if err := rejected.TakeEffect("creator"); err == nil {
		t.Fatal("a rejected exclusion took effect")
	}
}

// Review decides whether extending drops the approval and whether taking
// the exclusion out of effect needs another approver.
func TestExclusion_ReviewByMode(t *testing.T) {
	week := time.Now().Add(7 * 24 * time.Hour)
	year := time.Now().Add(365 * 24 * time.Hour)
	creator := Reviewer{UserID: "creator"}

	e := newTestExclusion(t, &week)
	_ = e.TakeEffect("creator")
	if err := e.AuthorizeReduction(creator, false); err != nil {
		t.Fatalf("without review the creator may reduce: %v", err)
	}
	e.UpdateExpiresAt(&year, false)
	if !e.InEffect() {
		t.Fatal("without review an extension dropped the approval")
	}

	s := newTestExclusion(t, &week)
	_ = s.Approve("approver")
	if err := s.AuthorizeReduction(creator, true); !errors.Is(err, ErrExclusionReduceNeedsApprover) {
		t.Fatalf("review: member reduce: %v", err)
	}
	if err := s.AuthorizeReduction(Reviewer{UserID: "creator", CanApprove: true}, true); !errors.Is(err, ErrExclusionSelfReduce) {
		t.Fatalf("review: self reduce: %v", err)
	}
	s.UpdateExpiresAt(&year, true)
	if !s.IsPending() {
		t.Fatal("review: an extension kept the approval")
	}
}
