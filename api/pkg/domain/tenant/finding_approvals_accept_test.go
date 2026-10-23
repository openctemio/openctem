package tenant

import (
	"errors"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// The risk acceptance level follows the false-positive level's rule on its
// own: unset is all (two people); lowering waits 24 hours, raising is
// immediate and cancels the wait; CancelPending keeps the level in force;
// an unknown value is refused, stored or pending.
func TestFindingApprovalSettings_SetAcceptApproval(t *testing.T) {
	now := time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)
	var s FindingApprovalSettings
	if got := s.EffectiveAcceptApproval(now); got != FPApprovalAll {
		t.Fatalf("default: %s", got)
	}
	if err := s.SetAcceptApproval("off", now); err != nil {
		t.Fatal(err)
	}
	if s.EffectiveAcceptApproval(now) != FPApprovalAll || s.PendingAcceptApproval != "off" ||
		!s.PendingAcceptApprovalAt.Equal(now.Add(24*time.Hour)) {
		t.Fatalf("lowering applied at once: %+v", s)
	}
	if lvl, at := s.PendingAcceptApprovalIn(now); lvl != "off" || at == nil {
		t.Fatalf("pending: %q %v", lvl, at)
	}
	if got := s.EffectiveAcceptApproval(now.Add(24*time.Hour - time.Second)); got != FPApprovalAll {
		t.Fatalf("a second before 24 hours: %s", got)
	}
	if got := s.EffectiveAcceptApproval(now.Add(24 * time.Hour)); got != "off" {
		t.Fatalf("after 24 hours: %s", got)
	}
	// The false-positive level is untouched.
	if s.EffectiveFPApproval(now.Add(48*time.Hour)) != FPApprovalAll || s.PendingFPApproval != "" {
		t.Fatalf("the false-positive level moved: %+v", s)
	}
	// Raising back within the wait is immediate and cancels the lowering.
	if err := s.SetAcceptApproval("all", now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if s.PendingAcceptApproval != "" || s.EffectiveAcceptApproval(now.Add(48*time.Hour)) != FPApprovalAll {
		t.Fatalf("raising did not cancel: %+v", s)
	}
	// From off in force up to high_and_above: immediate.
	s = FindingApprovalSettings{AcceptApproval: "off"}
	if err := s.SetAcceptApproval("high_and_above", now); err != nil || s.EffectiveAcceptApproval(now) != "high_and_above" {
		t.Fatalf("raising from off: %v %+v", err, s)
	}
	// CancelPending drops a waiting lowering.
	_ = s.SetAcceptApproval("off", now)
	s.CancelPending(now)
	if s.PendingAcceptApproval != "" || s.EffectiveAcceptApproval(now.Add(48*time.Hour)) != "high_and_above" {
		t.Fatalf("cancel: %+v", s)
	}
	if err := s.SetAcceptApproval("sometimes", now); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("unknown level: %v", err)
	}
	for _, bad := range []FindingApprovalSettings{{AcceptApproval: "never"}, {PendingAcceptApproval: "never"}} {
		if _, err := bad.Normalized(); !errors.Is(err, shared.ErrValidation) {
			t.Fatalf("Normalized accepted %+v", bad)
		}
	}
}
