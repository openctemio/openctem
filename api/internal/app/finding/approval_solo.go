package finding

// The sole member of an organization approving their own finding request
// (api/docs/architecture/finding-status-lifecycle.md, "Approvals").
//
// Threat model: four-eyes stops one stolen session or one careless person
// from hiding a risk. An organization with a single person has nobody else to
// ask, and before this path it could not mark anything a false positive or
// accept any risk. The relaxation is as narrow as possible:
//   - only the requester, only an owner, and only while the organization has
//     exactly one active person (checked in the database at decision time, so
//     inviting a second member closes the path at once);
//   - a fresh code from the owner's authenticator app (a stolen cookie or
//     password alone is not enough; a used code cannot be replayed) and a
//     reason;
//   - an accepted risk ends much sooner than one another person approved
//     (vulnerability.SoloAcceptanceLimit);
//   - marked self_approved on the request and the timeline, audited at high
//     severity, announced on the organization's channels and emailed to the
//     backup contact when one is configured.
// Nothing is ever approved automatically.

import (
	"context"
	"errors"
	"fmt"
	"html"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/openctemio/openctem/api/internal/app/outbox"
	"github.com/openctemio/openctem/api/pkg/domain/integration"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	tenantdom "github.com/openctemio/openctem/api/pkg/domain/tenant"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// SoleOwnerChecker answers whether a user is the only active person of the
// organization and its owner, and when a member was last suspended or
// removed (*postgres.ScopeActorRepository).
type SoleOwnerChecker interface {
	IsSoleActiveOwner(ctx context.Context, tenantID shared.ID, userID string) (bool, error)
	RecentMemberRemoval(ctx context.Context, tenantID shared.ID, window time.Duration) (*time.Time, error)
}

// SoloAfterRemovalWait is how long after a member was suspended or removed
// the sole remaining owner must wait before approving their own request: a
// stolen owner session cannot remove the other approver and self-approve.
const SoloAfterRemovalWait = 7 * 24 * time.Hour

// ApprovalTOTPVerifier checks a fresh authenticator code. It answers
// vulnerability.ErrSoloApprovalNeedsTOTP when the account has no
// authenticator and vulnerability.ErrSoloApprovalBadCode for a wrong or
// reused code.
type ApprovalTOTPVerifier interface {
	VerifyFreshTOTP(ctx context.Context, userID, code string) error
}

// ApprovalSettingsReader reads the organization's finding approval settings
// (*tenant.TenantService).
type ApprovalSettingsReader interface {
	GetFindingApprovalSettings(ctx context.Context, tenantID string) (*tenantdom.FindingApprovalSettings, error)
}

// SetSoloApproval wires the sole-member path. Without a checker or a
// verifier, self-approval is refused (fail closed).
func (s *VulnerabilityService) SetSoloApproval(owners SoleOwnerChecker, totp ApprovalTOTPVerifier, settings ApprovalSettingsReader) {
	s.soleOwners, s.approvalTOTP, s.approvalSettings = owners, totp, settings
}

// SelfApproveInput is a sole member's approval of their own request.
type SelfApproveInput struct {
	TenantID   string
	ApprovalID string
	UserID     string
	Reason     string
	Code       string
}

// SelfApproveResult is the approved request; EndShortened is set when the
// acceptance end asked for was beyond the limit of a self-approval and was
// brought forward to it.
type SelfApproveResult struct {
	Approval     *vulnerability.Approval
	EndShortened bool
}

// SelfApprovalAvailable reports whether userID could approve their own
// pending requests now (the sole active person and an owner). False when the
// path is not wired or the check fails.
func (s *VulnerabilityService) SelfApprovalAvailable(ctx context.Context, tenantID, userID string) bool {
	if s.soleOwners == nil || s.approvalTOTP == nil || userID == "" {
		return false
	}
	tid, err := shared.IDFromString(tenantID)
	if err != nil {
		return false
	}
	ok, err := s.soleOwners.IsSoleActiveOwner(ctx, tid, userID)
	if err != nil || !ok {
		return false
	}
	removed, err := s.soleOwners.RecentMemberRemoval(ctx, tid, SoloAfterRemovalWait)
	return err == nil && removed == nil
}

// SelfApproveSolo applies the caller's own pending request when they are
// the organization's only active person and its owner, with a fresh
// authenticator code and a reason. The route requires findings:approve.
func (s *VulnerabilityService) SelfApproveSolo(ctx context.Context, in SelfApproveInput) (*SelfApproveResult, error) {
	if s.approvalRepo == nil {
		return nil, fmt.Errorf("%w: approval workflow not configured", shared.ErrValidation)
	}
	tid, err := shared.IDFromString(in.TenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}
	aid, err := shared.IDFromString(in.ApprovalID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid approval id", shared.ErrValidation)
	}
	uid, err := shared.IDFromString(in.UserID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid user id", shared.ErrValidation)
	}
	a, err := s.approvalRepo.GetByTenantAndID(ctx, tid, aid)
	if err != nil {
		return nil, err
	}
	if a.BatchID != nil {
		return nil, vulnerability.ErrBatchMember
	}
	if err := s.dataScope.AssertFinding(ctx, tid, a.FindingID); err != nil {
		return nil, err
	}
	now := time.Now()
	switch {
	case !a.IsPending():
		return nil, fmt.Errorf("%w: approval is not pending", shared.ErrValidation)
	case a.IsOverdue(now):
		return nil, vulnerability.ErrDecisionOverdue
	case a.IsExpired():
		return nil, fmt.Errorf("%w: the requested acceptance end has passed; submit a new request", shared.ErrValidation)
	case a.RequestedBy.IsZero() || a.RequestedBy != uid:
		return nil, vulnerability.ErrSoloApprovalNotAllowed
	}
	if err := s.checkSoleMember(ctx, tid, in.UserID); err != nil {
		return nil, err
	}
	reason := strings.TrimSpace(in.Reason)
	if reason == "" || len(reason) > vulnerability.MaxSelfApprovalReasonLength {
		return nil, vulnerability.ErrSoloApprovalNeedsReason
	}
	if s.approvalTOTP == nil {
		return nil, vulnerability.ErrSoloApprovalNeedsTOTP
	}
	if strings.TrimSpace(in.Code) == "" {
		return nil, vulnerability.ErrSoloApprovalBadCode
	}
	if err := s.approvalTOTP.VerifyFreshTOTP(ctx, in.UserID, strings.TrimSpace(in.Code)); err != nil {
		return nil, err
	}

	status := vulnerability.FindingStatus(a.RequestedStatus)
	f, err := s.findingRepo.GetByID(ctx, tid, a.FindingID)
	if err != nil {
		return nil, err
	}
	if !f.CanTransitionTo(status) {
		return nil, fmt.Errorf("%w: cannot transition from %s to %s", shared.ErrValidation, f.Status(), status)
	}
	if err := a.SelfApprove(uid, reason); err != nil {
		return nil, err
	}
	shortened := false
	if status == vulnerability.FindingStatusAccepted {
		limit := now.Add(vulnerability.SoloAcceptanceLimit(f))
		if a.ExpiresAt == nil || a.ExpiresAt.After(limit) {
			a.ExpiresAt = &limit
			shortened = true
		}
	}
	changes := map[string]any{
		"approval_id":      a.ID.String(),
		"requested_status": a.RequestedStatus,
		"approved_by":      in.UserID,
		"self_approved":    true,
		"reason":           reason,
	}
	if a.ExpiresAt != nil {
		changes["acceptance_end"] = a.ExpiresAt.UTC().Format(time.RFC3339)
	}
	entry, err := vulnerability.NewFindingActivity(tid, a.FindingID, vulnerability.ActivityApprovalApproved,
		&uid, vulnerability.ActorTypeUser, changes, vulnerability.SourceAPI, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to build approval activity: %w", err)
	}
	if err := s.approvalRepo.ApproveAndApply(s.ticketSyncCtx(ctx, tid, []*vulnerability.Finding{f}), a, entry); err != nil {
		return nil, err
	}
	s.afterApplied(ctx, tid, in.UserID, []*vulnerability.Finding{f}, status)
	s.announceSelfApproval(ctx, a, f.Title(), reason)
	s.logger.Warn("finding request self-approved by the sole member", "approval_id", a.ID.String())
	return &SelfApproveResult{Approval: a, EndShortened: shortened}, nil
}

// announceSelfApproval puts the self-approval on the organization's
// channels and emails the backup contact (best effort; the decision is
// saved and audited already).
func (s *VulnerabilityService) announceSelfApproval(ctx context.Context, a *vulnerability.Approval, findingTitle, reason string) {
	title := "Finding request approved by its own requester (no other member)"
	summary := approvalSummary(a, findingTitle)
	if s.notificationService != nil {
		var agg *uuid.UUID
		if id, err := uuid.Parse(a.ID.String()); err == nil {
			agg = &id
		}
		if err := s.notificationService.Enqueue(ctx, outbox.EnqueueParams{
			TenantID: a.TenantID, EventType: string(integration.EventTypeSecurityAlert), AggregateType: "approval",
			AggregateID: agg, Title: title, Body: summary, Severity: "high", URL: approvalInboxURL,
		}); err != nil {
			s.logger.Warn("self-approval notice: enqueue", "error", logger.SanitizeError(err))
		}
	}
	if s.approvalSettings == nil || s.approvalMail == nil {
		return
	}
	settings, err := s.approvalSettings.GetFindingApprovalSettings(ctx, a.TenantID.String())
	if err != nil {
		if !errors.Is(err, shared.ErrNotFound) {
			s.logger.Warn("self-approval notice: settings", "error", logger.SanitizeError(err))
		}
		return
	}
	if settings == nil || settings.BackupContactEmail == "" {
		return
	}
	body := fmt.Sprintf(`<p>You are the backup contact of an organization on OpenCTEM. Its only member approved their own finding request, because nobody else can.</p>
<p>%s</p>
<p>Reason given: %s</p>
<p>This was confirmed with a code from the member's authenticator app and is recorded in the organization's audit log.</p>`,
		html.EscapeString(summary), html.EscapeString(oneLineTitle(reason)))
	s.approvalMail.SendFindingApprovalMail(ctx, a.TenantID.String(), []string{settings.BackupContactEmail}, "[Findings] "+title, body)
}

// checkSoleMember is the membership rule of a sole member's own approval:
// the only active person and an owner, and no member suspended or removed
// within SoloAfterRemovalWait.
func (s *VulnerabilityService) checkSoleMember(ctx context.Context, tid shared.ID, userID string) error {
	if s.soleOwners == nil {
		return vulnerability.ErrSoloApprovalNotAllowed
	}
	sole, err := s.soleOwners.IsSoleActiveOwner(ctx, tid, userID)
	if err != nil {
		return fmt.Errorf("check the organization's members: %w", err)
	}
	if !sole {
		return vulnerability.ErrSoloApprovalNotAllowed
	}
	removed, err := s.soleOwners.RecentMemberRemoval(ctx, tid, SoloAfterRemovalWait)
	if err != nil {
		return fmt.Errorf("check recent member changes: %w", err)
	}
	if removed != nil {
		return shared.NewDomainError("SELF_APPROVAL_AFTER_MEMBER_REMOVAL",
			fmt.Sprintf("a member was suspended or removed recently; approving your own request is possible again from %s",
				removed.Add(SoloAfterRemovalWait).UTC().Format("2006-01-02 15:04 UTC")), shared.ErrForbidden)
	}
	return nil
}
