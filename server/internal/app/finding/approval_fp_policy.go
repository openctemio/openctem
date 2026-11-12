package finding

// The organization's false-positive and risk acceptance approval levels
// (api/docs/architecture/finding-status-lifecycle.md, "Approval levels").
//
// Threat model: four-eyes on a false positive or an accepted risk stops one
// stolen session or one careless person from hiding a real issue. An
// organization may decide that for some findings this costs more than it
// protects. The relaxation is bounded:
//   - only a holder of findings:approve (someone who could approve anyway)
//     with the finding in their data scope, who does not own its asset, and
//     only through a person's own request on one finding: suppression rules,
//     group and bulk requests, imports and automation (AI triage, VEX,
//     ticket integrations) never decide alone, whatever the level;
//   - under high_and_above, never for a material finding (critical, high,
//     KEV, P0/P1, a validated exploit, a crown-jewel or internet-exposed
//     asset);
//   - a VEX-aligned closure reason and a note are required, as for any
//     request, and an accepted risk always ends within the organization's
//     cap; the decision is marked single_person, audited, on the timeline
//     and in the next approvals digest;
//   - a later material change (severity, priority or exposure up, KEV
//     added, new evidence) raises a review flag (database triggers and the
//     material-change controller, which also ends an accepted risk whose
//     tier now needs a second person), and an optional random share of
//     false positives is flagged for a second look;
//   - lowering the level takes effect only 24 hours later (raising is
//     immediate), the change needs settings:write and a recent
//     re-authentication, is audited and every approver is told.

import (
	"context"
	"crypto/rand"
	"fmt"
	"math/big"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/approvalpolicy"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	tenantdom "github.com/openctemio/openctem/api/pkg/domain/tenant"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// singlePersonStore writes a request decided as it is made and reads the
// facts that decide it (*postgres.FindingApprovalRepository).
type singlePersonStore interface {
	CreateApplied(ctx context.Context, a *vulnerability.Approval, entry *vulnerability.FindingActivity) error
	FalsePositiveFacts(ctx context.Context, tenantID, findingID shared.ID) (vulnerability.FPFacts, error)
}

// decisionReviewRaiser flags a decided finding for review
// (*postgres.FindingRepository).
type decisionReviewRaiser interface {
	RaiseDecisionReview(ctx context.Context, tenantID, findingID shared.ID, reason string, evidence map[string]any) (bool, error)
}

// DecisionReviewSecondLook is the review reason of a single-person false
// positive picked for a second look.
const DecisionReviewSecondLook = "second_look_sample"

// decidedAloneReviewer flags the standing decisions one person made
// (*postgres.FindingApprovalRepository).
type decidedAloneReviewer interface {
	FlagDecidedAlone(ctx context.Context, tenantID shared.ID, status vulnerability.FindingStatus, level string,
		needsSecond func(approvalpolicy.Facts) bool) (int, error)
}

// ReviewDecidedAlone flags for review every standing decision of status
// (false positive or accepted risk) in the tenant that one person made,
// under a level or as the sole member, and that level now gives to a second
// person: all of them under all, the material ones under high_and_above,
// none under off. It runs when a level is raised. The decisions stand (a
// legitimate decision is not undone by a later setting); the review flag
// and a timeline entry ask a person with the approve permission to look
// again. It answers how many decisions are now under review.
func (s *VulnerabilityService) ReviewDecidedAlone(ctx context.Context, tenantID string, status vulnerability.FindingStatus, level string) (int, error) {
	tid, err := shared.IDFromString(tenantID)
	if err != nil {
		return 0, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}
	if status != vulnerability.FindingStatusFalsePositive && status != vulnerability.FindingStatusAccepted {
		return 0, fmt.Errorf("%w: only false positives and accepted risks are decided alone", shared.ErrValidation)
	}
	if !approvalpolicy.LevelNeedsSecond(level, true) {
		return 0, nil // off: nothing needs a second person
	}
	store, ok := s.approvalRepo.(decidedAloneReviewer)
	if !ok {
		return 0, fmt.Errorf("%w: reviewing decisions made alone is not available", shared.ErrNotImplemented)
	}
	op, err := s.orgApprovalPolicy(ctx, tid)
	if err != nil {
		return 0, err
	}
	threshold := op.policy.EPSS()
	return store.FlagDecidedAlone(ctx, tid, status, level, func(f approvalpolicy.Facts) bool {
		return approvalpolicy.LevelNeedsSecond(level, approvalpolicy.MaterialForFalsePositive(f, threshold))
	})
}

// FPPolicyDecision is how a false positive (or, for applySinglePerson, an
// accepted risk) on one finding is decided now.
type FPPolicyDecision struct {
	// Level is the organization's level in force (of the decision's kind).
	Level string
	// SinglePerson: a holder of findings:approve may decide it alone.
	SinglePerson bool
	// Material: the finding is material (it always needs a second person
	// under high_and_above).
	Material bool
	// PendingLevel / PendingAt: a lower level that takes effect later.
	PendingLevel string
	PendingAt    *time.Time
	// SecondLookPercent is the organization's second-look share.
	SecondLookPercent int
}

// FalsePositivePolicy answers how a false positive on the finding would be
// decided now (for the request dialog). The finding must be in the caller's
// data scope.
func (s *VulnerabilityService) FalsePositivePolicy(ctx context.Context, tenantID, findingID string) (FPPolicyDecision, error) {
	tid, err := shared.IDFromString(tenantID)
	if err != nil {
		return FPPolicyDecision{}, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}
	fid, err := shared.IDFromString(findingID)
	if err != nil {
		return FPPolicyDecision{}, fmt.Errorf("%w: invalid finding id", shared.ErrValidation)
	}
	f, err := s.findingRepo.GetByID(ctx, tid, fid)
	if err != nil {
		return FPPolicyDecision{}, err
	}
	if err := s.assertFindingScope(ctx, f); err != nil {
		return FPPolicyDecision{}, err
	}
	return s.falsePositivePolicy(ctx, tid, fid)
}

func (s *VulnerabilityService) falsePositivePolicy(ctx context.Context, tid, fid shared.ID) (FPPolicyDecision, error) {
	d := FPPolicyDecision{Level: tenantdom.FPApprovalAll}
	store, ok := s.approvalRepo.(singlePersonStore)
	if s.approvalSettings == nil || !ok {
		return d, nil // not wired: four-eyes for every false positive
	}
	settings, err := s.approvalSettings.GetFindingApprovalSettings(ctx, tid.String())
	if err != nil {
		return d, fmt.Errorf("read the organization's approval settings: %w", err)
	}
	now := time.Now()
	d.Level = settings.EffectiveFPApproval(now)
	if settings.PendingFPApproval != "" && settings.PendingFPApprovalAt != nil && now.Before(*settings.PendingFPApprovalAt) {
		d.PendingLevel, d.PendingAt = settings.PendingFPApproval, settings.PendingFPApprovalAt
	}
	d.SecondLookPercent = settings.EffectiveSecondLookPercent(now)
	facts, err := store.FalsePositiveFacts(ctx, tid, fid)
	if err != nil {
		return d, err
	}
	d.Material = facts.Material()
	d.SinglePerson = vulnerability.SinglePersonFP(d.Level, facts)
	return d, nil
}

// applySinglePerson decides the requester's false positive or accepted risk
// at once: the request row (approved, single_person), the finding's status
// (and acceptance end) and the timeline entry in one transaction; then, for
// a false positive and by the organization's share, a second-look flag.
func (s *VulnerabilityService) applySinglePerson(ctx context.Context, a *vulnerability.Approval, d FPPolicyDecision) (*vulnerability.Approval, error) {
	store, ok := s.approvalRepo.(singlePersonStore)
	if !ok {
		return nil, fmt.Errorf("%w: single-person decisions are not available", shared.ErrNotImplemented)
	}
	if err := a.ApproveSinglePerson(a.RequestedBy); err != nil {
		return nil, err
	}
	by := a.RequestedBy
	accepted := vulnerability.FindingStatus(a.RequestedStatus) == vulnerability.FindingStatusAccepted
	changes := map[string]any{
		"approval_id":      a.ID.String(),
		"requested_status": a.RequestedStatus,
		"closure_reason":   a.ClosureReason.String(),
		"justification":    a.Justification,
		"approved_by":      by.String(),
		"single_person":    true,
	}
	if accepted {
		changes["accept_approval"] = d.Level
		changes["acceptance_end"] = a.ExpiresAt.UTC().Format(time.RFC3339)
	} else {
		changes["fp_approval"] = d.Level
	}
	entry, err := vulnerability.NewFindingActivity(a.TenantID, a.FindingID, vulnerability.ActivityApprovalApproved,
		&by, vulnerability.ActorTypeUser, changes, vulnerability.SourceAPI, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to build the decision activity: %w", err)
	}
	if err := store.CreateApplied(ctx, a, entry); err != nil {
		return nil, err
	}
	if !accepted && d.SecondLookPercent > 0 && sampled(d.SecondLookPercent) {
		if raiser, ok := s.findingRepo.(decisionReviewRaiser); ok {
			if _, err := raiser.RaiseDecisionReview(ctx, a.TenantID, a.FindingID, DecisionReviewSecondLook,
				map[string]any{"approval_id": a.ID.String(), "second_look_percent": d.SecondLookPercent}); err != nil {
				s.logger.Warn("second look: raise review", "error", logger.SanitizeError(err))
			}
		}
	}
	s.logger.Info("finding decision made by one person under the organization's level",
		"finding_id", a.FindingID.String(), "status", a.RequestedStatus, "level", d.Level)
	return a, nil
}

// sampled answers true with probability percent/100 (crypto/rand: the
// requester cannot predict which decisions get a second look).
func sampled(percent int) bool {
	n, err := rand.Int(rand.Reader, big.NewInt(100))
	if err != nil {
		return true // fail towards a second look
	}
	return n.Int64() < int64(percent)
}
