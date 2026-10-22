package finding

// Verification plan: how one finding can be verified, computed by the server
// (api/docs/architecture/finding-verification-plan.md).

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/openctemio/openctem/api/internal/app/validation"
	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// Verification method kinds.
const (
	VerifyMethodRetest         = "retest"
	VerifyMethodCoveredScan    = "covered_scan"
	VerifyMethodSafeCheck      = "safe_check"
	VerifyMethodRotationProof  = "rotation_proof"
	VerifyMethodEvidenceReview = "evidence_review"
)

// Reasons a method is not available (besides the retest service's own codes).
const (
	VerifyReasonAbsenceNotProofForSecrets = "absence_not_proof_for_secrets"
	VerifyReasonSourceNotScanned          = "source_not_scanned"
	VerifyReasonCoverageReviewOnly        = "coverage_auto_resolve_review"
	VerifyReasonCoverageOff               = "coverage_auto_resolve_off"
	VerifyReasonNoAsset                   = "no_asset"
	VerifyReasonAssetInactive             = "asset_inactive"
	VerifyReasonNotNetworkAddressable     = "asset_not_network_addressable"
	VerifyReasonNotForSecrets             = "not_for_secrets"
	VerifyReasonClosed                    = "finding_closed"
)

// Requirement of the risk tier for a person's resolve.
const (
	// VerifyRequireSecondPersonOrRetest: critical / P0 / KEV — a fresh
	// confirmed-fixed retest, or the checklist completed by someone other
	// than the person resolving.
	VerifyRequireSecondPersonOrRetest = "second_person_or_retest"
	// VerifyRequireChecklistOrRetest: high / P1 — the checklist or a fresh
	// confirmed-fixed retest.
	VerifyRequireChecklistOrRetest = "checklist_or_retest"
	// VerifyRequireNote: everything else — a note (closure attested).
	VerifyRequireNote = "note"
)

// VerificationMethod is one way the finding could be verified.
type VerificationMethod struct {
	Kind      string `json:"kind"`
	Available bool   `json:"available"`
	// Recommended marks the method to show first.
	Recommended bool `json:"recommended,omitempty"`
	// CountsAsProof: a passing result of this method satisfies the risk
	// tier's evidence rule (a safe-check is advisory and never does).
	CountsAsProof bool `json:"counts_as_proof"`
	// Automatic: the platform closes the finding itself when the method
	// passes (a covered scan); otherwise a person resolves.
	Automatic bool `json:"automatic,omitempty"`
	// Reason is a stable code for why the method is not available.
	Reason string `json:"reason,omitempty"`
}

// VerificationRetestEvidence is the finding's latest completed retest.
type VerificationRetestEvidence struct {
	Outcome     string     `json:"outcome"`
	CompletedAt *time.Time `json:"completed_at,omitempty"`
	// Fresh: newer than the last reopen and the last sighting, so it counts.
	Fresh bool `json:"fresh"`
}

// VerificationChecklistEvidence is the state of the verification checklist.
type VerificationChecklistEvidence struct {
	// State: none (no checklist), in_progress, complete.
	State       string     `json:"state"`
	Incomplete  []string   `json:"incomplete,omitempty"`
	CompletedBy string     `json:"completed_by,omitempty"`
	CompletedAt *time.Time `json:"completed_at,omitempty"`
	// Fresh: completed after the last reopen and the last sighting.
	Fresh bool `json:"fresh"`
	// CompletedByCaller: the caller completed it, so for a critical finding
	// another person must resolve.
	CompletedByCaller bool `json:"completed_by_caller,omitempty"`
}

// VerificationEvidence is the proof recorded so far.
type VerificationEvidence struct {
	Retest    *VerificationRetestEvidence   `json:"retest,omitempty"`
	Checklist VerificationChecklistEvidence `json:"checklist"`
}

// VerificationPlan says how a finding can be verified and what proof exists.
// It is advisory: the transition engine enforces the rule on every resolve.
type VerificationPlan struct {
	FindingID string `json:"finding_id"`
	Status    string `json:"status"`
	// Tier is the risk tier: critical, high or standard.
	Tier string `json:"tier"`
	// Requirement is what a person's resolve needs at this tier.
	Requirement string `json:"requirement"`
	// SecondPersonRequired: critical tier without a fresh confirmed-fixed
	// retest — the checklist must be completed by someone other than the
	// person who resolves.
	SecondPersonRequired bool `json:"second_person_required"`
	// ProofPresent: the tier's evidence is recorded and fresh (for the
	// second-person rule, someone other than the completer may resolve).
	ProofPresent bool `json:"proof_present"`
	// ExternalWorkflow names a module that verifies the finding itself
	// (pentest); Methods is then empty.
	ExternalWorkflow string               `json:"external_workflow,omitempty"`
	Methods          []VerificationMethod `json:"methods"`
	Evidence         VerificationEvidence `json:"evidence"`
}

// RetestAvailability answers whether a retest of the finding would be
// accepted now and, if not, why (implemented by the retest service).
type RetestAvailability interface {
	Availability(ctx context.Context, tenantID, findingID shared.ID) (bool, string, error)
}

// SetRetestAvailability wires the retest service for the verification plan.
func (s *VulnerabilityService) SetRetestAvailability(r RetestAvailability) { s.retestAvailability = r }

// SetCoverageAutoResolveMode records the platform's coverage auto-resolve mode
// for network assets (enforce, dry_run or off) for the verification plan.
func (s *VulnerabilityService) SetCoverageAutoResolveMode(mode string) {
	s.coverageAutoResolveMode = strings.ToLower(strings.TrimSpace(mode))
}

// verificationPlanInput is everything the plan is computed from.
type verificationPlanInput struct {
	Status        vulnerability.FindingStatus
	Source        vulnerability.FindingSource
	FindingType   vulnerability.FindingType
	Severity      vulnerability.Severity
	PriorityClass string
	IsKEV         bool
	// Asset: nil when the finding has none.
	AssetType   *asset.AssetType
	AssetActive bool
	// Retest availability from the retest service; RetestKnown false when
	// it is not wired.
	RetestKnown     bool
	RetestAvailable bool
	RetestReason    string
	CoverageMode    string
	Evidence        resolveEvidence
	CallerID        shared.ID
}

// coverageProtectedSources are never closed by a covered scan (no scanner
// re-runs a person's finding).
var coverageProtectedSources = map[vulnerability.FindingSource]bool{
	vulnerability.FindingSourcePentest: true, "manual": true, "bug_bounty": true, "red_team": true,
}

func isSecretFinding(t vulnerability.FindingType, src vulnerability.FindingSource) bool {
	return t == vulnerability.FindingTypeSecret || src == vulnerability.FindingSourceSecret
}

// buildVerificationPlan computes the plan. Pure; table-tested.
func buildVerificationPlan(in verificationPlanInput) VerificationPlan {
	tier := vulnerability.FindingRiskTier(in.Severity, in.PriorityClass, in.IsKEV)
	p := VerificationPlan{Status: in.Status.String(), Tier: string(tier), Methods: []VerificationMethod{}}
	ev := in.Evidence
	retestProof := ev.RetestOutcome == "confirmed_fixed" && ev.RetestFresh
	checklistProof := ev.ChecklistComplete && ev.ChecklistFresh

	switch tier {
	case vulnerability.RiskTierCritical:
		p.Requirement = VerifyRequireSecondPersonOrRetest
		p.SecondPersonRequired = !retestProof
		p.ProofPresent = retestProof || (checklistProof && !ev.ChecklistCompletedBy.IsZero())
	case vulnerability.RiskTierHigh:
		p.Requirement = VerifyRequireChecklistOrRetest
		p.ProofPresent = retestProof || checklistProof
	default:
		p.Requirement = VerifyRequireNote
		p.ProofPresent = true
	}

	p.Evidence = planEvidence(ev, in.CallerID)

	if in.Source == vulnerability.FindingSourcePentest {
		p.ExternalWorkflow = "pentest"
		return p
	}
	open := vulnerability.IsOpenStatus(in.Status)
	secret := isSecretFinding(in.FindingType, in.Source)
	retest := retestMethod(in, open, secret)
	covered := coveredScanMethod(in, open, secret)
	safe := safeCheckMethod(in, open, secret)

	// Evidence review: the checklist, signed off as the tier requires.
	review := VerificationMethod{Kind: VerifyMethodEvidenceReview, CountsAsProof: true, Available: open}
	if !open {
		review.Reason = VerifyReasonClosed
	}

	if secret {
		rotation := VerificationMethod{Kind: VerifyMethodRotationProof, CountsAsProof: true, Available: open, Recommended: open}
		if !open {
			rotation.Reason = VerifyReasonClosed
		}
		p.Methods = append(p.Methods, rotation, review, retest, covered, safe)
		return p
	}
	switch {
	case retest.Available:
		retest.Recommended = true
	case covered.Available:
		covered.Recommended = true
	case review.Available:
		review.Recommended = true
	}
	p.Methods = append(p.Methods, retest, covered, review, safe)
	return p
}

// retestMethod: the retest service decides, except that a closed finding or
// a secret is never retested.
func retestMethod(in verificationPlanInput, open, secret bool) VerificationMethod {
	m := VerificationMethod{Kind: VerifyMethodRetest, CountsAsProof: true}
	switch {
	case !open:
		m.Reason = VerifyReasonClosed
	case secret:
		m.Reason = "secret_needs_rotation"
	case in.RetestKnown:
		m.Available, m.Reason = in.RetestAvailable, in.RetestReason
	default:
		m.Reason = "no_sensor"
	}
	return m
}

// coveredScanMethod: the platform closes the finding itself when a full scan
// of the same tool and profile covers the asset and no longer reports it
// (a repository's default branch always; other assets when the platform's
// coverage auto-resolve enforces).
func coveredScanMethod(in verificationPlanInput, open, secret bool) VerificationMethod {
	m := VerificationMethod{Kind: VerifyMethodCoveredScan, CountsAsProof: true, Automatic: true}
	switch {
	case !open:
		m.Reason = VerifyReasonClosed
	case secret:
		m.Reason = VerifyReasonAbsenceNotProofForSecrets
	case coverageProtectedSources[in.Source]:
		m.Reason = VerifyReasonSourceNotScanned
	case in.AssetType == nil:
		m.Reason = VerifyReasonNoAsset
	case *in.AssetType == asset.AssetTypeRepository, in.CoverageMode == "enforce":
		m.Available = true
	case in.CoverageMode == "off":
		m.Reason = VerifyReasonCoverageOff
	default:
		m.Reason = VerifyReasonCoverageReviewOnly
	}
	return m
}

// safeCheckMethod: a reachability probe of a network asset; advisory, it
// never counts as proof of a fix.
func safeCheckMethod(in verificationPlanInput, open, secret bool) VerificationMethod {
	m := VerificationMethod{Kind: VerifyMethodSafeCheck}
	switch {
	case !open:
		m.Reason = VerifyReasonClosed
	case secret:
		m.Reason = VerifyReasonNotForSecrets
	case in.AssetType == nil:
		m.Reason = VerifyReasonNoAsset
	case !validation.IsNetworkAddressable(*in.AssetType):
		m.Reason = VerifyReasonNotNetworkAddressable
	case !in.AssetActive:
		m.Reason = VerifyReasonAssetInactive
	default:
		m.Available = true
	}
	return m
}

func planEvidence(ev resolveEvidence, caller shared.ID) VerificationEvidence {
	out := VerificationEvidence{Checklist: VerificationChecklistEvidence{State: "none"}}
	if ev.RetestOutcome != "" {
		out.Retest = &VerificationRetestEvidence{Outcome: ev.RetestOutcome, CompletedAt: ev.RetestCompletedAt, Fresh: ev.RetestFresh}
	}
	if !ev.ChecklistExists {
		return out
	}
	c := &out.Checklist
	c.Incomplete = ev.ChecklistIncomplete
	if ev.ChecklistComplete && ev.ChecklistCompletedAt != nil {
		c.State = "complete"
		c.CompletedAt = ev.ChecklistCompletedAt
		c.Fresh = ev.ChecklistFresh
		if !ev.ChecklistCompletedBy.IsZero() {
			c.CompletedBy = ev.ChecklistCompletedBy.String()
			c.CompletedByCaller = !caller.IsZero() && ev.ChecklistCompletedBy == caller
		}
	} else {
		c.State = "in_progress"
	}
	return out
}

// GetVerificationPlan returns how the finding can be verified and the proof
// recorded so far. The finding must be in the caller's tenant and data scope
// (404 otherwise, never 403). It records nothing.
func (s *VulnerabilityService) GetVerificationPlan(ctx context.Context, tenantID, findingID, callerID string) (*VerificationPlan, error) {
	tid, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}
	fid, err := shared.IDFromString(findingID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid id format", shared.ErrValidation)
	}
	f, err := s.findingRepo.GetByID(ctx, tid, fid)
	if err != nil {
		return nil, err
	}
	if err := s.assertFindingScope(ctx, f); err != nil {
		return nil, err
	}
	in := verificationPlanInput{
		Status: f.Status(), Source: f.Source(), FindingType: f.FindingType(), Severity: f.Severity(),
		PriorityClass: priorityClassString(f), IsKEV: f.IsInKEV(), CoverageMode: s.coverageAutoResolveMode,
	}
	in.CallerID, _ = shared.IDFromString(callerID)
	if !f.AssetID().IsZero() && s.assetRepo != nil {
		a, err := s.assetRepo.GetByID(ctx, tid, f.AssetID())
		switch {
		case err == nil:
			t := a.Type()
			in.AssetType = &t
			in.AssetActive = a.Status() == asset.StatusActive
		case !errors.Is(err, shared.ErrNotFound):
			return nil, fmt.Errorf("verification plan asset: %w", err)
		}
	}
	if s.retestAvailability != nil {
		ok, reason, err := s.retestAvailability.Availability(ctx, tid, fid)
		if err != nil {
			s.logger.Warn("retest availability failed", "finding_id", fid.String(), "error", err)
		} else {
			in.RetestKnown, in.RetestAvailable, in.RetestReason = true, ok, reason
		}
	}
	if s.db != nil {
		ev, err := readResolveEvidence(ctx, s.db, tid, fid)
		if err != nil {
			return nil, err
		}
		in.Evidence = ev
	}
	plan := buildVerificationPlan(in)
	plan.FindingID = fid.String()
	return &plan, nil
}
