package suppression

// Suppression rules under the approval policy
// (api/docs/rfcs/RFC-111-approval-policy.md). A rule decides many findings,
// including future ones, so it is never decided by one person: its tier is
// that of the worst open finding it matches (false-positive rules floor at
// peer; accepted-risk and won't-fix rules follow the accepted-risk floors).
// The requester and the owners of the matched findings' assets never sign
// off; security and dual tiers need the approver's recent re-authentication;
// a dual rule needs two approvers, one from the security pool. A rule always
// carries a structured reason code and a note.

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/approvalpolicy"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// PolicySource evaluates a rule under the organization's approval policy
// (wired from the application layer).
type PolicySource interface {
	EvaluateRule(ctx context.Context, rule *Rule) (approvalpolicy.Result, error)
}

// SignoffRecord is one approval of a rule.
type SignoffRecord struct {
	UserID       shared.ID
	SecurityPool bool
	PoolFallback bool
	StepUp       bool
}

// signoffRepository records sign-offs of rules
// (*postgres.SuppressionRepository).
type signoffRepository interface {
	RuleSignoffs(ctx context.Context, tenantID, ruleID shared.ID) ([]approvalpolicy.Signoff, error)
	// ApproveWithSignoff locks the rule (pending, the reviewed version),
	// judges the signer with decide against the sign-offs in, records the
	// sign-off and, when it completes the rule, calls finish (which approves
	// the entity) and approves it as Approve does, in one transaction.
	ApproveWithSignoff(ctx context.Context, rule *Rule, reviewedUpdatedAt time.Time, rec SignoffRecord,
		decide func(prior []approvalpolicy.Signoff) (bool, error), finish func() error,
		details map[string]any, limit int) (res ApplyResult, collected int, complete bool, err error)
}

// SetApprovalPolicy wires the approval policy. Without it, rules keep the
// one-approver rule.
func (s *Service) SetApprovalPolicy(p PolicySource) { s.policy = p }

// SetStepUpGate wires the re-authentication check the policy's security and
// dual tiers need; without it such approvals are refused.
func (s *Service) SetStepUpGate(g shared.RecentAuthGate) { s.stepUp = g }

// ErrStepUpNotWired: a tier needs a recent re-authentication and the check is
// not available; the approval is refused.
var ErrStepUpNotWired = shared.NewDomainError("STEP_UP_UNAVAILABLE",
	"re-authentication is not available; this approval needs it and is refused", shared.ErrForbidden)

// KindOf is the approval-policy kind of a suppression type.
func KindOf(t SuppressionType) approvalpolicy.Kind {
	if t == SuppressionTypeFalsePositive {
		return approvalpolicy.KindRuleFalsePositive
	}
	return approvalpolicy.KindRuleAccepted
}

// closureStatus is the finding status whose reason catalog a rule uses.
func closureStatus(t SuppressionType) vulnerability.FindingStatus {
	if t == SuppressionTypeFalsePositive {
		return vulnerability.FindingStatusFalsePositive
	}
	return vulnerability.FindingStatusAccepted
}

// ParseReasonCode validates a rule's reason code against the closure reason
// catalog of its type (false-positive justifications for a false-positive
// rule; accepted-risk reasons for accepted-risk and won't-fix rules).
func ParseReasonCode(t SuppressionType, code string) (string, error) {
	st := closureStatus(t)
	reason, err := vulnerability.ParseClosureReason(st, strings.TrimSpace(code))
	if err != nil {
		return "", err
	}
	if reason == "" {
		return "", fmt.Errorf("%w: reason_code is required: one of %v", shared.ErrValidation, vulnerability.PersonClosureReasons(st))
	}
	return reason.String(), nil
}

// evaluate stamps a new rule with its tier, and checks its note length.
func (s *Service) stampPolicy(ctx context.Context, rule *Rule) error {
	if s.policy == nil {
		return nil
	}
	res, err := s.policy.EvaluateRule(ctx, rule)
	if err != nil {
		return err
	}
	if n := len([]rune(strings.TrimSpace(rule.Description()))); n < res.MinNoteLength {
		return fmt.Errorf("%w: this rule needs a description of at least %d characters (%s tier)", shared.ErrValidation, res.MinNoteLength, res.Tier)
	}
	rule.SetPolicy(string(res.Tier), res.Required)
	return nil
}

// approveUnderPolicy records approvedBy's sign-off of the rule under the
// policy evaluated now and approves the rule when it is the last one needed.
func (s *Service) approveUnderPolicy(ctx context.Context, rule *Rule, input ApproveRuleInput) (*ApproveResult, error) {
	repo, ok := s.repo.(signoffRepository)
	if !ok {
		return nil, fmt.Errorf("%w: rule sign-offs are not available", shared.ErrNotImplemented)
	}
	res, err := s.policy.EvaluateRule(ctx, rule)
	if err != nil {
		return nil, err
	}
	// An accepted-risk or won't-fix rule ends no later than the cap of the
	// worst finding it matches now.
	if res.MaxAcceptance > 0 && rule.ExpiresAt() != nil && rule.ExpiresAt().After(time.Now().Add(res.MaxAcceptance)) {
		return nil, fmt.Errorf("%w: this rule may accept the risk of what it matches for at most %d days; edit its end date",
			shared.ErrValidation, int(res.MaxAcceptance/(24*time.Hour)))
	}
	prior, err := repo.RuleSignoffs(ctx, input.TenantID, input.RuleID)
	if err != nil {
		return nil, err
	}
	if _, err := res.Sign(input.ApprovedBy, prior); err != nil {
		return nil, err
	}
	if res.StepUp {
		if s.stepUp == nil {
			return nil, ErrStepUpNotWired
		}
		if err := s.stepUp.RequireRecentAuth(ctx, input.ApprovedBy.String()); err != nil {
			return nil, err
		}
	}
	rec := SignoffRecord{UserID: input.ApprovedBy, PoolFallback: res.PoolFallback, StepUp: res.StepUp}
	for _, id := range res.EligiblePool {
		rec.SecurityPool = rec.SecurityPool || id == input.ApprovedBy
	}
	details := map[string]any{"tier": string(res.Tier), "approvals_required": res.Required}
	applied, collected, complete, err := repo.ApproveWithSignoff(ctx, rule, *input.ReviewedUpdatedAt, rec,
		func(prior []approvalpolicy.Signoff) (bool, error) { return res.Sign(input.ApprovedBy, prior) },
		func() error { return rule.Approve(input.ApprovedBy) },
		details, MaxFindingsAppliedOnApprove)
	if err != nil {
		return nil, err
	}
	rule.SetPolicyInfo(rule.ReasonCode(), rule.Tier(), res.Required, collected)
	return &ApproveResult{
		Rule: rule, AppliedFindings: applied.Applied, Capped: applied.Capped,
		Pending: !complete, ApprovalsCollected: collected, ApprovalsRequired: res.Required,
	}, nil
}
