package finding

// The organization's false-positive approval level
// (api/docs/architecture/finding-status-lifecycle.md, "False-positive
// approval level").
//
// Threat model: four-eyes on a false positive stops one stolen session or
// one careless person from hiding a real issue. An organization may decide
// that for some findings this costs more than it protects. The relaxation is
// bounded:
//   - only a holder of findings:approve (someone who could approve anyway)
//     with the finding in their data scope, and only for a false positive
//     (an accepted risk always needs a second person);
//   - under high_and_above, never for a material finding (critical, high,
//     KEV, P0/P1, a validated exploit, a crown-jewel or internet-exposed
//     asset);
//   - a VEX-aligned closure reason and a note are required, as for any
//     request; the decision is marked single_person, audited and on the
//     timeline;
//   - a later material change (severity up, KEV added, new evidence) raises
//     a review flag (database triggers), and an optional random share is
//     flagged for a second look;
//   - lowering the level takes effect only 24 hours later (raising is
//     immediate), the change needs settings:write and a recent
//     re-authentication, is audited and every approver is told.

import (
	"context"
	"crypto/rand"
	"fmt"
	"math/big"
	"time"

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

// FPPolicyDecision is how a false positive on one finding is decided now.
type FPPolicyDecision struct {
	// Level is the organization's level in force.
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

// applySinglePersonFP decides the requester's false positive at once: the
// request row (approved, single_person), the finding's status and the
// timeline entry in one transaction; then, by the organization's share, a
// second-look flag.
func (s *VulnerabilityService) applySinglePersonFP(ctx context.Context, a *vulnerability.Approval, d FPPolicyDecision) (*vulnerability.Approval, error) {
	store, ok := s.approvalRepo.(singlePersonStore)
	if !ok {
		return nil, fmt.Errorf("%w: single-person decisions are not available", shared.ErrNotImplemented)
	}
	if err := a.ApproveSinglePerson(a.RequestedBy); err != nil {
		return nil, err
	}
	by := a.RequestedBy
	entry, err := vulnerability.NewFindingActivity(a.TenantID, a.FindingID, vulnerability.ActivityApprovalApproved,
		&by, vulnerability.ActorTypeUser, map[string]any{
			"approval_id":      a.ID.String(),
			"requested_status": a.RequestedStatus,
			"closure_reason":   a.ClosureReason.String(),
			"justification":    a.Justification,
			"approved_by":      by.String(),
			"single_person":    true,
			"fp_approval":      d.Level,
		}, vulnerability.SourceAPI, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to build the decision activity: %w", err)
	}
	if err := store.CreateApplied(ctx, a, entry); err != nil {
		return nil, err
	}
	if d.SecondLookPercent > 0 && sampled(d.SecondLookPercent) {
		if raiser, ok := s.findingRepo.(decisionReviewRaiser); ok {
			if _, err := raiser.RaiseDecisionReview(ctx, a.TenantID, a.FindingID, DecisionReviewSecondLook,
				map[string]any{"approval_id": a.ID.String(), "second_look_percent": d.SecondLookPercent}); err != nil {
				s.logger.Warn("second look: raise review", "error", logger.SanitizeError(err))
			}
		}
	}
	s.logger.Info("false positive decided by one person under the organization's level",
		"finding_id", a.FindingID.String(), "level", d.Level)
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
