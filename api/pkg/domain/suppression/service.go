package suppression

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// Service provides business logic for suppression rules.
type Service struct {
	repo      Repository
	log       *logger.Logger
	approvers ApproverDirectory
	scope     ScopeFilter
	assetRefs AssetRefChecker
	totp      TOTPVerifier
}

// TOTPVerifier checks a fresh code from the user's authenticator app. It
// answers ErrSelfApprovalNeedsTOTP when the account has no authenticator and
// ErrSelfApprovalBadCode for a wrong or reused code.
type TOTPVerifier interface {
	VerifyFreshTOTP(ctx context.Context, userID, code string) error
}

// SetTOTPVerifier wires the authenticator check of an owner's own approval.
// Without it an own approval is refused (fail closed).
func (s *Service) SetTOTPVerifier(v TOTPVerifier) {
	s.totp = v
}

// AssetRefChecker checks an asset id a caller writes onto a row: a live asset
// of the tenant that the request's caller may see (datascope.Enforcer
// AssertAssetRef). Any refusal is shared.ErrNotFound.
type AssetRefChecker interface {
	AssertAssetRef(ctx context.Context, tenantID, assetID shared.ID) error
}

// ErrRuleAssetNotFound is the one answer for a suppression rule's asset that
// is unknown, deleted, another tenant's or outside the caller's data scope
// (research 21b M-10, RFC-050 W8).
var ErrRuleAssetNotFound = fmt.Errorf("%w: asset not found", shared.ErrNotFound)

// SetAssetRefChecker wires the asset check of asset-bound rules. Without it
// an asset-bound rule is refused (fail closed).
func (s *Service) SetAssetRefChecker(c AssetRefChecker) {
	s.assetRefs = c
}

// ApproverDirectory answers the two questions the four-eyes rule needs
// (owner decision B16). Implemented by *postgres.SuppressionRepository.
type ApproverDirectory interface {
	// CountEligibleApprovers counts the tenant's active members who may
	// approve suppression rules (owners, admins and holders of a role with
	// findings:suppressions:approve).
	CountEligibleApprovers(ctx context.Context, tenantID shared.ID) (int, error)
	// IsTenantOwner reports whether the user is the tenant's active owner.
	IsTenantOwner(ctx context.Context, tenantID, userID shared.ID) (bool, error)
	// RecentMemberRemoval answers the latest member suspension, removal,
	// offboarding or membership expiry in the tenant after since (nil: none).
	RecentMemberRemoval(ctx context.Context, tenantID shared.ID, since time.Time) (*time.Time, error)
}

// SelfApprovalRemovalCooldown: an owner may not approve their own rule
// within this long after any member was suspended or removed (removing the
// only other approver must not open the own-approval path at once).
const SelfApprovalRemovalCooldown = 7 * 24 * time.Hour

// SetApproverDirectory wires the directory the four-eyes rule reads. Without
// it a requester can never approve their own rule (fail closed).
func (s *Service) SetApproverDirectory(d ApproverDirectory) {
	s.approvers = d
}

// NewService creates a new suppression service.
func NewService(repo Repository, log *logger.Logger) *Service {
	return &Service{repo: repo, log: log}
}

// CreateRuleInput contains input for creating a suppression rule.
type CreateRuleInput struct {
	TenantID        shared.ID
	Name            string
	Description     string
	SuppressionType SuppressionType
	RuleID          string     // Tool rule ID pattern
	ToolName        string     // Tool name filter
	PathPattern     string     // File path pattern
	AssetID         *shared.ID // Optional asset filter
	RequestedBy     shared.ID
	ExpiresAt       *string // ISO8601 format
}

// CreateRule creates a new suppression rule.
func (s *Service) CreateRule(ctx context.Context, input CreateRuleInput) (*Rule, error) {
	rule, err := NewRule(
		input.TenantID,
		input.Name,
		input.SuppressionType,
		input.RequestedBy,
	)
	if err != nil {
		return nil, err
	}

	// An asset-bound rule auto-closes that asset's findings: the asset must be
	// one the requester may see, in their own tenant. The column references
	// assets(id) without the tenant, so this is the only tenant check.
	if input.AssetID != nil && !input.AssetID.IsZero() {
		if s.assetRefs == nil || s.assetRefs.AssertAssetRef(ctx, input.TenantID, *input.AssetID) != nil {
			return nil, ErrRuleAssetNotFound
		}
	}

	// Set criteria
	rule.SetRuleIDPattern(input.RuleID)
	rule.SetToolName(input.ToolName)
	rule.SetPathPattern(input.PathPattern)
	rule.SetAssetID(input.AssetID)
	rule.SetDescription(input.Description)

	// Validate criteria
	if err := rule.Validate(); err != nil {
		return nil, err
	}

	// Every rule ends: the default when none is asked, at most a year ahead.
	var requested *time.Time
	if input.ExpiresAt != nil && *input.ExpiresAt != "" {
		expiresAt, err := time.Parse(time.RFC3339, *input.ExpiresAt)
		if err != nil {
			return nil, fmt.Errorf("%w: invalid expires_at format (expected RFC3339)", shared.ErrValidation)
		}
		requested = &expiresAt
	}
	end, err := RuleEnd(requested, time.Now().UTC())
	if err != nil {
		return nil, err
	}
	rule.SetExpiresAt(&end)

	// Save the rule and its audit entry atomically.
	if err := s.repo.SaveWithAudit(ctx, rule, "created", &input.RequestedBy, map[string]any{
		"name":             input.Name,
		"suppression_type": string(input.SuppressionType),
		"rule_id":          input.RuleID,
		"tool_name":        input.ToolName,
		"path_pattern":     input.PathPattern,
	}); err != nil {
		return nil, err
	}

	return rule, nil
}

// ApproveRuleInput contains input for approving a rule.
type ApproveRuleInput struct {
	TenantID   shared.ID
	RuleID     shared.ID
	ApprovedBy shared.ID
	// ReviewedUpdatedAt is the rule's updated_at as the approver saw it. The
	// approval is refused if the rule changed since (the approval pins the
	// reviewed version).
	ReviewedUpdatedAt *time.Time
	// SelfApprovalReason and TOTPCode are required when the approver is the
	// requester (an owner with no other approver): a reason and a fresh code
	// from their authenticator app. Nothing self-approves without them.
	SelfApprovalReason string
	TOTPCode           string
}

// MaxFindingsAppliedOnApprove caps the existing findings one approval
// changes, so a broad rule cannot hold a transaction over a whole tenant's
// findings. Findings beyond the cap stay open; the CI gate and ingest still
// honor the rule for them.
const MaxFindingsAppliedOnApprove = 10000

// ApproveResult tells the caller how the approval was granted and what it did
// to existing findings.
type ApproveResult struct {
	Rule *Rule
	// SelfApproved: the owner approved their own rule because nobody else
	// could (B16). Callers audit this at Critical severity.
	SelfApproved bool
	// AppliedFindings is the number of open findings the approval gave the
	// rule's disposition; Capped says more matched than
	// MaxFindingsAppliedOnApprove.
	AppliedFindings int
	Capped          bool
}

// PreviewSampleSize is the number of findings a preview lists.
const PreviewSampleSize = 10

// SetScopeFilter wires the data-scope filter the preview sample uses. Without
// it a preview lists nothing and counts no finding as in scope (fail closed).
func (s *Service) SetScopeFilter(f ScopeFilter) { s.scope = f }

// Preview is what approving a rule would do to existing findings now.
type Preview struct {
	// MatchingOpenFindings is the number of the tenant's open findings the
	// rule matches and an approval would close, at most Limit.
	MatchingOpenFindings int
	// Capped: more than Limit match; an approval closes Limit of them.
	Capped bool
	Limit  int
	// InScopeFindings is how many of those sit on assets the caller's data
	// scope admits, at most Limit; Sample lists the first PreviewSampleSize
	// of them. Findings outside the caller's scope are only in the
	// organization-wide count, never listed.
	InScopeFindings int
	Sample          []SampleFinding
}

// PreviewRule counts the open findings an approval of the rule would close,
// with the same matcher and status set the approval uses. The count is
// tenant-wide because the approval is; the sample and the in-scope count are
// limited to the caller's data scope.
func (s *Service) PreviewRule(ctx context.Context, tenantID, ruleID shared.ID) (*Preview, error) {
	rule, err := s.repo.FindByID(ctx, tenantID, ruleID)
	if err != nil {
		return nil, err
	}
	if rule == nil {
		return nil, ErrRuleNotFound
	}
	n, err := s.repo.CountMatchingOpenFindings(ctx, rule, MaxFindingsAppliedOnApprove)
	if err != nil {
		return nil, err
	}
	p := &Preview{MatchingOpenFindings: n, Limit: MaxFindingsAppliedOnApprove}
	if n > MaxFindingsAppliedOnApprove {
		p.MatchingOpenFindings = MaxFindingsAppliedOnApprove
		p.Capped = true
	}
	inScope, sample, err := s.repo.SampleMatchingOpenFindings(ctx, rule, s.scope, MaxFindingsAppliedOnApprove, PreviewSampleSize)
	if err != nil {
		return nil, err
	}
	p.InScopeFindings = min(inScope, MaxFindingsAppliedOnApprove)
	p.Sample = sample
	return p, nil
}

// ApproveRule approves a pending suppression rule.
//
// Four-eyes (owner decision B16): the approver must not be the requester when
// the organization has at least two people who can approve. In an
// organization with a single eligible approver, that person may approve their
// own rule only if they are the owner, give a reason and prove presence with
// a fresh authenticator code; the result says so, and the caller records it
// at Critical severity (a refusal at High).
func (s *Service) ApproveRule(ctx context.Context, input ApproveRuleInput) (*ApproveResult, error) {
	if input.ReviewedUpdatedAt == nil {
		return nil, ErrReviewedVersionRequired
	}
	rule, err := s.repo.FindByID(ctx, input.TenantID, input.RuleID)
	if err != nil {
		return nil, err
	}
	if rule == nil {
		return nil, ErrRuleNotFound
	}
	if !rule.UpdatedAt().Equal(*input.ReviewedUpdatedAt) {
		return nil, ErrRuleChangedSinceReview
	}

	selfApproved := false
	if !rule.RequestedBy().IsZero() && rule.RequestedBy() == input.ApprovedBy {
		allowed, err := s.mayApproveOwnRule(ctx, input.TenantID, input.ApprovedBy)
		if err != nil {
			return nil, err
		}
		if !allowed {
			return nil, ErrSelfApproval
		}
		if err := s.verifySelfApproval(ctx, input); err != nil {
			return nil, err
		}
		selfApproved = true
	}

	if err := rule.Approve(input.ApprovedBy); err != nil {
		return nil, err
	}

	details := map[string]any{}
	if selfApproved {
		details["self_approved"] = true
		details["reason"] = strings.TrimSpace(input.SelfApprovalReason)
		details["step_up"] = "totp"
	}
	// Save the rule, give the open findings it matches its disposition and
	// record the audit entry (with the count) in one transaction.
	applied, err := s.repo.Approve(ctx, rule, *input.ReviewedUpdatedAt, input.ApprovedBy, details, MaxFindingsAppliedOnApprove)
	if err != nil {
		return nil, err
	}

	return &ApproveResult{
		Rule:            rule,
		SelfApproved:    selfApproved,
		AppliedFindings: applied.Applied,
		Capped:          applied.Capped,
	}, nil
}

// verifySelfApproval requires the reason and a fresh authenticator code of
// an owner approving their own rule, and no member suspended or removed in
// the last SelfApprovalRemovalCooldown.
func (s *Service) verifySelfApproval(ctx context.Context, input ApproveRuleInput) error {
	at, err := s.approvers.RecentMemberRemoval(ctx, input.TenantID, time.Now().Add(-SelfApprovalRemovalCooldown))
	if err != nil {
		return err
	}
	if at != nil {
		return fmt.Errorf("%w; approving your own rule is possible again from %s",
			ErrSelfApprovalAfterRemoval, at.Add(SelfApprovalRemovalCooldown).UTC().Format(time.RFC3339))
	}
	if strings.TrimSpace(input.SelfApprovalReason) == "" {
		return ErrSelfApprovalNeedsReason
	}
	code := strings.TrimSpace(input.TOTPCode)
	if s.totp == nil || code == "" {
		return ErrSelfApprovalBadCode
	}
	return s.totp.VerifyFreshTOTP(ctx, input.ApprovedBy.String(), code)
}

// IsSelfApprovalRefusal reports whether err refused an own approval (to be
// audited by the caller).
func IsSelfApprovalRefusal(err error) bool {
	return errors.Is(err, ErrSelfApproval) || errors.Is(err, ErrSelfApprovalNeedsReason) || errors.Is(err, ErrSelfApprovalAfterRemoval) ||
		errors.Is(err, ErrSelfApprovalNeedsTOTP) || errors.Is(err, ErrSelfApprovalBadCode)
}

// mayApproveOwnRule: only when the requester is the owner and nobody else in
// the organization can approve.
func (s *Service) mayApproveOwnRule(ctx context.Context, tenantID, userID shared.ID) (bool, error) {
	if s.approvers == nil {
		return false, nil
	}
	n, err := s.approvers.CountEligibleApprovers(ctx, tenantID)
	if err != nil {
		return false, fmt.Errorf("count eligible approvers: %w", err)
	}
	if n >= 2 {
		return false, nil
	}
	return s.approvers.IsTenantOwner(ctx, tenantID, userID)
}

// RejectRuleInput contains input for rejecting a rule.
type RejectRuleInput struct {
	TenantID   shared.ID
	RuleID     shared.ID
	RejectedBy shared.ID
	Reason     string
}

// RejectRule rejects a pending suppression rule.
func (s *Service) RejectRule(ctx context.Context, input RejectRuleInput) (*Rule, error) {
	rule, err := s.repo.FindByID(ctx, input.TenantID, input.RuleID)
	if err != nil {
		return nil, err
	}
	if rule == nil {
		return nil, ErrRuleNotFound
	}

	if err := rule.Reject(input.RejectedBy, input.Reason); err != nil {
		return nil, err
	}

	// Save the rule and its audit entry atomically.
	if err := s.repo.SaveWithAudit(ctx, rule, "rejected", &input.RejectedBy, map[string]any{
		"reason": input.Reason,
	}); err != nil {
		return nil, err
	}

	return rule, nil
}

// UpdateRuleInput contains input for updating a suppression rule.
type UpdateRuleInput struct {
	TenantID    shared.ID
	RuleID      shared.ID
	Name        *string
	Description *string
	RuleIDPat   *string // Rule ID pattern
	ToolName    *string
	PathPattern *string
	ExpiresAt   *string // ISO8601 format, empty string to clear
	UpdatedBy   shared.ID
}

// UpdateRule updates an existing suppression rule.
// Only pending rules can be updated.
func (s *Service) UpdateRule(ctx context.Context, input UpdateRuleInput) (*Rule, error) {
	rule, err := s.repo.FindByID(ctx, input.TenantID, input.RuleID)
	if err != nil {
		return nil, err
	}
	if rule == nil {
		return nil, ErrRuleNotFound
	}

	// Only pending rules can be updated
	if rule.Status() != RuleStatusPending {
		return nil, ErrRuleNotPending
	}

	changes := make(map[string]any)

	if input.Name != nil {
		rule.SetName(*input.Name)
		changes["name"] = *input.Name
	}
	if input.Description != nil {
		rule.SetDescription(*input.Description)
		changes["description"] = *input.Description
	}
	if input.RuleIDPat != nil {
		rule.SetRuleIDPattern(*input.RuleIDPat)
		changes["rule_id"] = *input.RuleIDPat
	}
	if input.ToolName != nil {
		rule.SetToolName(*input.ToolName)
		changes["tool_name"] = *input.ToolName
	}
	if input.PathPattern != nil {
		rule.SetPathPattern(*input.PathPattern)
		changes["path_pattern"] = *input.PathPattern
	}
	if input.ExpiresAt != nil {
		if *input.ExpiresAt == "" {
			return nil, ErrRuleEndRequired
		}
		expiresAt, err := time.Parse(time.RFC3339, *input.ExpiresAt)
		if err != nil {
			return nil, fmt.Errorf("%w: invalid expires_at format (expected RFC3339)", shared.ErrValidation)
		}
		end, err := RuleEnd(&expiresAt, time.Now().UTC())
		if err != nil {
			return nil, err
		}
		rule.SetExpiresAt(&end)
		changes["expires_at"] = *input.ExpiresAt
	}
	// A person reviewed and changed the rule: the review flag is done.
	if rule.ReviewFlaggedAt() != nil && len(changes) > 0 {
		rule.ClearReview()
		changes["review_cleared"] = true
	}

	// Validate after changes
	if err := rule.Validate(); err != nil {
		return nil, err
	}

	// Save the rule and its audit entry atomically.
	if err := s.repo.SaveWithAudit(ctx, rule, "updated", &input.UpdatedBy, changes); err != nil {
		return nil, err
	}

	return rule, nil
}

// MarkReviewed clears the review flag of a rule (an approver looked at a
// rule the platform gave an end it did not have). It changes nothing else:
// the rule keeps its end. Recorded in the rule's own trail with the flag it
// cleared. Returns the flag's time and reason before the change.
func (s *Service) MarkReviewed(ctx context.Context, input MarkReviewedInput) (*Rule, *time.Time, string, error) {
	rule, err := s.repo.FindByID(ctx, input.TenantID, input.RuleID)
	if err != nil {
		return nil, nil, "", err
	}
	if rule == nil {
		return nil, nil, "", ErrRuleNotFound
	}
	flaggedAt, reason := rule.ReviewFlaggedAt(), rule.ReviewReason()
	if flaggedAt == nil {
		return nil, nil, "", ErrRuleNotFlagged
	}
	details := map[string]any{
		"review_cleared":    true,
		"review_flagged_at": flaggedAt.UTC().Format(time.RFC3339),
		"review_reason":     reason,
	}
	// Reviewing one's own rule is not a review: the requester may clear the
	// flag only on the sole-approver path (the owner, nobody else can
	// approve, a reason and a fresh authenticator code), like approving it.
	if !rule.RequestedBy().IsZero() && rule.RequestedBy() == input.By {
		allowed, err := s.mayApproveOwnRule(ctx, input.TenantID, input.By)
		if err != nil {
			return nil, nil, "", err
		}
		if !allowed {
			return nil, nil, "", ErrSelfApproval
		}
		if err := s.verifySelfApproval(ctx, ApproveRuleInput{TenantID: input.TenantID, ApprovedBy: input.By,
			SelfApprovalReason: input.SelfApprovalReason, TOTPCode: input.TOTPCode}); err != nil {
			return nil, nil, "", err
		}
		details["self_reviewed"] = true
		details["reason"] = strings.TrimSpace(input.SelfApprovalReason)
		details["step_up"] = "totp"
	}
	rule.ClearReview()
	if err := s.repo.SaveWithAudit(ctx, rule, "updated", &input.By, details); err != nil {
		return nil, nil, "", err
	}
	return rule, flaggedAt, reason, nil
}

// MarkReviewedInput clears a rule's review flag. SelfApprovalReason and
// TOTPCode are required when the caller requested the rule (the
// sole-approver path).
type MarkReviewedInput struct {
	TenantID           shared.ID
	RuleID             shared.ID
	By                 shared.ID
	SelfApprovalReason string
	TOTPCode           string
}

// GetRule retrieves a suppression rule by ID.
func (s *Service) GetRule(ctx context.Context, tenantID, ruleID shared.ID) (*Rule, error) {
	rule, err := s.repo.FindByID(ctx, tenantID, ruleID)
	if err != nil {
		return nil, err
	}
	if rule == nil {
		return nil, ErrRuleNotFound
	}
	return rule, nil
}

// ListRules lists suppression rules for a tenant.
func (s *Service) ListRules(ctx context.Context, tenantID shared.ID, filter RuleFilter) ([]*Rule, error) {
	return s.repo.FindByTenant(ctx, tenantID, filter)
}

// ListActiveRules lists all active (approved, not expired) rules.
func (s *Service) ListActiveRules(ctx context.Context, tenantID shared.ID) ([]*Rule, error) {
	return s.repo.FindActiveByTenant(ctx, tenantID)
}

// ListPendingRules lists all pending rules awaiting approval.
func (s *Service) ListPendingRules(ctx context.Context, tenantID shared.ID) ([]*Rule, error) {
	return s.repo.FindPendingByTenant(ctx, tenantID)
}

// DeleteRule deletes a suppression rule.
func (s *Service) DeleteRule(ctx context.Context, tenantID, ruleID, deletedBy shared.ID) error {
	rule, err := s.repo.FindByID(ctx, tenantID, ruleID)
	if err != nil {
		return err
	}
	if rule == nil {
		return ErrRuleNotFound
	}

	// Record audit before deletion
	_ = s.repo.RecordAudit(ctx, ruleID, "deleted", &deletedBy, map[string]any{
		"name":   rule.Name(),
		"status": string(rule.Status()),
	})

	// Delete lifts the rule's suppressions in the same transaction: the
	// findings it hid return to the open backlog unless another active rule
	// covers them.
	return s.repo.Delete(ctx, tenantID, ruleID)
}

// CheckSuppression checks if a finding matches any active suppression rules.
func (s *Service) CheckSuppression(ctx context.Context, tenantID shared.ID, match FindingMatch) ([]*Rule, error) {
	return s.repo.FindMatchingRules(ctx, tenantID, match)
}

// ApplySuppression applies a suppression rule to a finding.
func (s *Service) ApplySuppression(ctx context.Context, findingID, ruleID shared.ID) error {
	return s.repo.RecordSuppression(ctx, findingID, ruleID, "system")
}

// ExpireRules expires all rules past their expiration date and lifts the
// suppressions they applied (see Repository.ExpireRules).
func (s *Service) ExpireRules(ctx context.Context) (int64, error) {
	return s.repo.ExpireRules(ctx)
}
