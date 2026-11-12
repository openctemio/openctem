package tenant

import (
	"testing"
	"time"
)

// Raising the false-positive level is immediate; lowering waits 24 hours and
// is canceled by choosing a level at or above the one in force.
func TestFindingApprovalSettings_SetFPApproval(t *testing.T) {
	now := time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)
	var s FindingApprovalSettings
	if got := s.EffectiveFPApproval(now); got != "all" {
		t.Fatalf("default: %s", got)
	}
	if err := s.SetFPApproval("off", now); err != nil {
		t.Fatal(err)
	}
	if s.EffectiveFPApproval(now) != "all" || s.PendingFPApproval != "off" || !s.PendingFPApprovalAt.Equal(now.Add(24*time.Hour)) {
		t.Fatalf("lowering applied at once: %+v", s)
	}
	if got := s.EffectiveFPApproval(now.Add(24 * time.Hour)); got != "off" {
		t.Fatalf("after 24 hours: %s", got)
	}
	// From off (in force) up to high_and_above: immediate.
	later := now.Add(25 * time.Hour)
	if err := s.SetFPApproval("high_and_above", later); err != nil {
		t.Fatal(err)
	}
	if s.EffectiveFPApproval(later) != "high_and_above" || s.PendingFPApproval != "" {
		t.Fatalf("raising: %+v", s)
	}
	if err := s.SetFPApproval("sometimes", later); err == nil {
		t.Fatal("unknown level accepted")
	}
	s.SecondLookPercent = 11
	if _, err := s.Normalized(); err == nil {
		t.Fatal("second_look_percent above 10 accepted")
	}
}

// Lowering the second-look share waits 24 hours; raising it is immediate.
func TestFindingApprovalSettings_SetSecondLookPercent(t *testing.T) {
	now := time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)
	var s FindingApprovalSettings
	if err := s.SetSecondLookPercent(5, now); err != nil || s.EffectiveSecondLookPercent(now) != 5 {
		t.Fatalf("raise: %v %+v", err, s)
	}
	if err := s.SetSecondLookPercent(0, now); err != nil {
		t.Fatal(err)
	}
	if s.EffectiveSecondLookPercent(now) != 5 || s.EffectiveSecondLookPercent(now.Add(24*time.Hour)) != 0 {
		t.Fatalf("lowering applied too early or never: %+v", s)
	}
	if err := s.SetSecondLookPercent(11, now); err == nil {
		t.Fatal("11 accepted")
	}
}
