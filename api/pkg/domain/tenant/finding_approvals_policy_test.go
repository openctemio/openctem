package tenant

import (
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/approvalpolicy"
)

// The false-positive levels are one vocabulary in both packages.
func TestFPLevelsMatchTheEvaluator(t *testing.T) {
	if FPApprovalAll != approvalpolicy.FPLevelAll || FPApprovalHighAndAbove != approvalpolicy.FPLevelHighAndAbove || FPApprovalOff != approvalpolicy.FPLevelOff {
		t.Fatal("false-positive level names differ between tenant settings and the approval policy")
	}
}

func TestSetPolicy_TightenNowRelaxLater(t *testing.T) {
	now := time.Now()
	var s FindingApprovalSettings
	waits, err := s.SetPolicy(approvalpolicy.Policy{ExcludeAssignee: true}, now)
	if err != nil || waits {
		t.Fatalf("tightening: waits=%v err=%v", waits, err)
	}
	if !s.EffectivePolicy(now).ExcludeAssignee {
		t.Fatal("tightening not in force at once")
	}
	// Mixed: drop the assignee rule (relax), add step-up for all tiers (tighten).
	waits, err = s.SetPolicy(approvalpolicy.Policy{StepUpAllTiers: true}, now)
	if err != nil || !waits {
		t.Fatalf("mixed change: waits=%v err=%v", waits, err)
	}
	eff := s.EffectivePolicy(now)
	if !eff.ExcludeAssignee || !eff.StepUpAllTiers {
		t.Fatalf("before the delay the stricter of both applies: %+v", eff)
	}
	later := s.EffectivePolicy(now.Add(approvalpolicy.RelaxationDelay + time.Minute))
	if later.ExcludeAssignee || !later.StepUpAllTiers {
		t.Fatalf("after the delay the new policy applies: %+v", later)
	}
	// Tightening again cancels the pending relaxation.
	if waits, _ := s.SetPolicy(approvalpolicy.Policy{ExcludeAssignee: true, StepUpAllTiers: true}, now); waits || s.PendingPolicy != nil {
		t.Fatal("a tightening did not cancel the pending relaxation")
	}
	// Below the floor is refused and changes nothing.
	before := s
	if _, err := s.SetPolicy(approvalpolicy.Policy{Tiers: map[string]approvalpolicy.Tier{"accepted.critical": approvalpolicy.TierPeer}}, now); err == nil {
		t.Fatal("below-floor policy accepted")
	}
	if s.PendingPolicy != before.PendingPolicy || !s.Policy.ExcludeAssignee {
		t.Fatal("a refused policy changed the settings")
	}
	// Normalized refuses a stored invalid policy.
	bad := FindingApprovalSettings{Policy: approvalpolicy.Policy{DecideWithinDays: 99}}
	if _, err := bad.Normalized(); err == nil {
		t.Fatal("invalid stored policy accepted")
	}
}
