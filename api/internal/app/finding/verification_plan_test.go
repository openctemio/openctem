package finding

import (
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

func planMethod(t *testing.T, p VerificationPlan, kind string) VerificationMethod {
	t.Helper()
	for _, m := range p.Methods {
		if m.Kind == kind {
			return m
		}
	}
	t.Fatalf("plan has no %s method: %+v", kind, p.Methods)
	return VerificationMethod{}
}

func hasMethod(p VerificationPlan, kind string) bool {
	for _, m := range p.Methods {
		if m.Kind == kind {
			return true
		}
	}
	return false
}

func assetTypePtr(t asset.AssetType) *asset.AssetType { return &t }

// The plan per source, finding type, asset type and retest availability.
func TestBuildVerificationPlan_Methods(t *testing.T) {
	host := assetTypePtr(asset.AssetTypeHost)
	repo := assetTypePtr(asset.AssetTypeRepository)

	t.Run("nuclei finding on a host with a sensor: retest recommended", func(t *testing.T) {
		p := buildVerificationPlan(verificationPlanInput{Status: "confirmed", Source: "dast", Severity: vulnerability.SeverityHigh,
			AssetType: host, AssetActive: true, RetestKnown: true, RetestAvailable: true, CoverageMode: "dry_run"})
		if m := planMethod(t, p, VerifyMethodRetest); !m.Available || !m.Recommended || !m.CountsAsProof {
			t.Errorf("retest = %+v", m)
		}
		if m := planMethod(t, p, VerifyMethodSafeCheck); !m.Available || m.CountsAsProof {
			t.Errorf("safe check on a host = %+v, want available and advisory", m)
		}
		if m := planMethod(t, p, VerifyMethodCoveredScan); m.Available || m.Reason != VerifyReasonCoverageReviewOnly {
			t.Errorf("covered scan in dry run = %+v", m)
		}
		if hasMethod(p, VerifyMethodRotationProof) {
			t.Error("rotation proof offered for a non-secret")
		}
		if p.Tier != "high" || p.Requirement != VerifyRequireChecklistOrRetest || p.SecondPersonRequired {
			t.Errorf("tier = %s %s %v", p.Tier, p.Requirement, p.SecondPersonRequired)
		}
	})

	t.Run("secret on a repository: rotation proof or evidence only", func(t *testing.T) {
		p := buildVerificationPlan(verificationPlanInput{Status: "confirmed", Source: "secret", FindingType: vulnerability.FindingTypeSecret,
			Severity: vulnerability.SeverityCritical, AssetType: repo, AssetActive: true, RetestKnown: true, RetestReason: "secret_needs_rotation"})
		if m := planMethod(t, p, VerifyMethodRotationProof); !m.Available || !m.Recommended {
			t.Errorf("rotation proof = %+v", m)
		}
		if m := planMethod(t, p, VerifyMethodEvidenceReview); !m.Available {
			t.Errorf("evidence review = %+v", m)
		}
		for kind, reason := range map[string]string{
			VerifyMethodRetest:      "secret_needs_rotation",
			VerifyMethodCoveredScan: VerifyReasonAbsenceNotProofForSecrets,
			VerifyMethodSafeCheck:   VerifyReasonNotForSecrets,
		} {
			if m := planMethod(t, p, kind); m.Available || m.Reason != reason {
				t.Errorf("%s = %+v, want unavailable %s", kind, m, reason)
			}
		}
		if p.Methods[0].Kind != VerifyMethodRotationProof {
			t.Errorf("first method = %s, want rotation_proof", p.Methods[0].Kind)
		}
		if !p.SecondPersonRequired || p.ProofPresent {
			t.Errorf("critical without proof: second=%v proof=%v", p.SecondPersonRequired, p.ProofPresent)
		}
	})

	t.Run("SCA on a repository: covered scan closes it", func(t *testing.T) {
		p := buildVerificationPlan(verificationPlanInput{Status: "fix_applied", Source: "sca", Severity: vulnerability.SeverityHigh,
			AssetType: repo, AssetActive: true, RetestKnown: true, RetestReason: "no_tool_rule", CoverageMode: "off"})
		if m := planMethod(t, p, VerifyMethodCoveredScan); !m.Available || !m.Automatic || !m.Recommended {
			t.Errorf("covered scan on a repository = %+v", m)
		}
		if m := planMethod(t, p, VerifyMethodRetest); m.Available || m.Reason != "no_tool_rule" {
			t.Errorf("retest = %+v", m)
		}
		if m := planMethod(t, p, VerifyMethodSafeCheck); m.Available || m.Reason != VerifyReasonNotNetworkAddressable {
			t.Errorf("safe check on a repository = %+v", m)
		}
	})

	t.Run("network finding with coverage enforce", func(t *testing.T) {
		p := buildVerificationPlan(verificationPlanInput{Status: "confirmed", Source: "dast", Severity: vulnerability.SeverityLow,
			AssetType: host, AssetActive: true, RetestKnown: true, RetestReason: "no_sensor", CoverageMode: "enforce"})
		if m := planMethod(t, p, VerifyMethodCoveredScan); !m.Available || !m.Recommended {
			t.Errorf("covered scan with enforce = %+v", m)
		}
		if p.Requirement != VerifyRequireNote || !p.ProofPresent {
			t.Errorf("standard tier = %s proof=%v", p.Requirement, p.ProofPresent)
		}
	})

	t.Run("manual finding is never closed by a scan", func(t *testing.T) {
		p := buildVerificationPlan(verificationPlanInput{Status: "confirmed", Source: "manual", Severity: vulnerability.SeverityHigh,
			AssetType: host, AssetActive: true, CoverageMode: "enforce"})
		if m := planMethod(t, p, VerifyMethodCoveredScan); m.Available || m.Reason != VerifyReasonSourceNotScanned {
			t.Errorf("covered scan for a manual finding = %+v", m)
		}
		if m := planMethod(t, p, VerifyMethodEvidenceReview); !m.Available || !m.Recommended {
			t.Errorf("evidence review = %+v", m)
		}
	})

	t.Run("inactive host: no reachability check", func(t *testing.T) {
		p := buildVerificationPlan(verificationPlanInput{Status: "confirmed", Source: "dast", Severity: vulnerability.SeverityHigh,
			AssetType: host, AssetActive: false})
		if m := planMethod(t, p, VerifyMethodSafeCheck); m.Available || m.Reason != VerifyReasonAssetInactive {
			t.Errorf("safe check on an inactive host = %+v", m)
		}
	})

	t.Run("pentest finding: its module verifies it", func(t *testing.T) {
		p := buildVerificationPlan(verificationPlanInput{Status: "confirmed", Source: vulnerability.FindingSourcePentest, Severity: vulnerability.SeverityHigh})
		if p.ExternalWorkflow != "pentest" || len(p.Methods) != 0 {
			t.Errorf("pentest plan = %+v", p)
		}
	})

	t.Run("closed finding: nothing to run", func(t *testing.T) {
		p := buildVerificationPlan(verificationPlanInput{Status: "resolved", Source: "dast", Severity: vulnerability.SeverityHigh,
			AssetType: host, AssetActive: true, RetestKnown: true, RetestAvailable: true})
		for _, m := range p.Methods {
			if m.Available || m.Reason != VerifyReasonClosed {
				t.Errorf("closed finding method %+v", m)
			}
		}
	})
}

// The evidence rule per tier, with the freshness horizon and the second
// person.
func TestBuildVerificationPlan_Evidence(t *testing.T) {
	alice, bob := shared.NewID(), shared.NewID()
	now := time.Now()
	critical := func(ev resolveEvidence, caller shared.ID) VerificationPlan {
		return buildVerificationPlan(verificationPlanInput{Status: "fix_applied", Source: "sca", Severity: vulnerability.SeverityCritical,
			Evidence: ev, CallerID: caller})
	}

	p := critical(resolveEvidence{ChecklistExists: true, ChecklistComplete: true, ChecklistFresh: true, ChecklistCompletedBy: alice, ChecklistCompletedAt: &now}, alice)
	if !p.ProofPresent || !p.SecondPersonRequired || !p.Evidence.Checklist.CompletedByCaller || p.Evidence.Checklist.State != "complete" {
		t.Errorf("completer's view = %+v", p)
	}
	if p := critical(resolveEvidence{ChecklistExists: true, ChecklistComplete: true, ChecklistFresh: true, ChecklistCompletedBy: alice, ChecklistCompletedAt: &now}, bob); p.Evidence.Checklist.CompletedByCaller {
		t.Error("another person's checklist reported as the caller's")
	}
	if p := critical(resolveEvidence{ChecklistExists: true, ChecklistComplete: true, ChecklistFresh: false, ChecklistCompletedBy: alice, ChecklistCompletedAt: &now}, bob); p.ProofPresent {
		t.Error("a checklist older than the last sighting counted")
	}
	if p := critical(resolveEvidence{RetestOutcome: "confirmed_fixed", RetestFresh: true, RetestCompletedAt: &now}, bob); !p.ProofPresent || p.SecondPersonRequired {
		t.Errorf("fresh confirmed retest = proof %v second %v, want proof and no second person", p.ProofPresent, p.SecondPersonRequired)
	}
	if p := critical(resolveEvidence{RetestOutcome: "confirmed_fixed", RetestFresh: false, RetestCompletedAt: &now}, bob); p.ProofPresent {
		t.Error("a stale retest counted")
	}
	if p := critical(resolveEvidence{ChecklistExists: true, ChecklistIncomplete: []string{"evidence_attached"}}, bob); p.Evidence.Checklist.State != "in_progress" ||
		len(p.Evidence.Checklist.Incomplete) != 1 {
		t.Errorf("in-progress checklist = %+v", p.Evidence.Checklist)
	}
}
