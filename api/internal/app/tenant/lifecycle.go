package tenant

// Member lifecycle: disable, re-enable, offboard, erase personal data.
// Design: docs/rfcs/RFC-050-asset-access-model.md.
//
// Threat model. The person being acted on may be hostile (a leaver, a
// compromised account), so every action cuts access first and fails closed:
// the membership leaves the active state in the same transaction that drops
// the materialized scope and suspends or revokes the keys, and every gate
// admits an ACTIVE membership of an ACTIVE user only. The acting
// administrator may also overreach: the target is always loaded within the
// caller's own tenant (anti-enumeration 404), the peer-administrator rule
// applies (only the owner acts on an administrator), the owner can never be
// disabled or offboarded, reassignment targets must be other active members
// of the same tenant, and erasing personal data is owner-only. Every action
// is audited at High (Critical for erase).

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/pkg/domain/audit"
	notificationdom "github.com/openctemio/openctem/api/pkg/domain/notification"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	tenantdom "github.com/openctemio/openctem/api/pkg/domain/tenant"
)

// LifecycleInAppNotifier delivers an in-app notification (the notification
// service satisfies it).
type LifecycleInAppNotifier interface {
	Notify(ctx context.Context, params notificationdom.NotificationParams) error
}

// ErrOwnerRequiredForErase is returned when someone other than the owner
// asks to erase a person's data.
var ErrOwnerRequiredForErase = fmt.Errorf("%w: only the organization owner can erase personal data", shared.ErrForbidden)

// SetLifecycleRepository wires the transactional member-lifecycle store.
// Without it, disable and re-enable fall back to the status update alone and
// offboarding is unavailable (fail closed: it refuses).
func (s *TenantService) SetLifecycleRepository(r tenantdom.LifecycleRepository) {
	s.lifecycle = r
}

// SetLifecycleNotifier wires the in-app notice sent to administrators when a
// disable pauses schedules or a deprovisioning waits for them.
func (s *TenantService) SetLifecycleNotifier(n LifecycleInAppNotifier) {
	s.lifecycleNotifier = n
}

// GetMemberAccessReport lists everything the member holds and owns.
func (s *TenantService) GetMemberAccessReport(ctx context.Context, membershipID string, actx auditapp.AuditContext) (*tenantdom.AccessReport, error) {
	if s.lifecycle == nil {
		return nil, fmt.Errorf("member lifecycle is not configured")
	}
	membership, err := s.getOwnMembership(ctx, membershipID, actx.TenantID)
	if err != nil {
		return nil, err
	}
	return s.lifecycle.AccessReport(ctx, membership)
}

// OffboardMemberInput names who takes over the member's work.
type OffboardMemberInput struct {
	SchedulesTo      string `json:"schedules_to,omitempty"`
	FindingsTo       string `json:"findings_to,omitempty"`
	UnassignFindings bool   `json:"unassign_findings,omitempty"`
	AssetsTo         string `json:"assets_to,omitempty"`
}

func (in OffboardMemberInput) plan() (tenantdom.OffboardPlan, error) {
	var p tenantdom.OffboardPlan
	parse := func(raw string) (*shared.ID, error) {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			return nil, nil
		}
		id, err := shared.IDFromString(raw)
		if err != nil || id.IsZero() {
			return nil, tenantdom.ErrInvalidReassignTarget
		}
		return &id, nil
	}
	var err error
	if p.SchedulesTo, err = parse(in.SchedulesTo); err != nil {
		return p, err
	}
	if p.FindingsTo, err = parse(in.FindingsTo); err != nil {
		return p, err
	}
	if p.AssetsTo, err = parse(in.AssetsTo); err != nil {
		return p, err
	}
	p.UnassignFindings = in.UnassignFindings && p.FindingsTo == nil
	return p, nil
}

// OffboardMember permanently removes a member's access: owned work is
// reassigned (mandatory), keys revoked, groups, grants, engagements and roles
// stripped, and the membership kept as a tombstone so history and foreign
// keys stay valid. A re-invite later starts from zero.
func (s *TenantService) OffboardMember(ctx context.Context, membershipID string, input OffboardMemberInput, actx auditapp.AuditContext) (*tenantdom.OffboardResult, error) {
	if s.lifecycle == nil {
		return nil, fmt.Errorf("member lifecycle is not configured")
	}
	membership, err := s.getOwnMembership(ctx, membershipID, actx.TenantID)
	if err != nil {
		return nil, err
	}
	if membership.IsOwner() {
		return nil, fmt.Errorf("%w: cannot offboard the owner", shared.ErrValidation)
	}
	if err := s.authorizeMemberChange(ctx, membership, actx); err != nil {
		return nil, err
	}
	plan, err := input.plan()
	if err != nil {
		return nil, err
	}
	var actor *shared.ID
	if actx.ActorID != "" {
		id, perr := shared.IDFromString(actx.ActorID)
		if perr != nil {
			return nil, fmt.Errorf("%w: invalid acting user id", shared.ErrValidation)
		}
		actor = &id
	}

	result, err := s.lifecycle.Offboard(ctx, membership, actor, plan)
	if err != nil {
		if re, ok := tenantdom.AsReassignmentError(err); ok {
			actx.TenantID = membership.TenantID().String()
			s.logAudit(ctx, actx, auditapp.NewFailureEvent(audit.ActionMemberOffboarded, audit.ResourceTypeMembership, membershipID, re).
				WithSeverity(audit.SeverityHigh).
				WithMetadata("missing", strings.Join(re.Missing, ",")).
				WithMetadata("user_id", membership.UserID().String()))
		}
		return nil, err
	}

	tenantID := membership.TenantID().String()
	userID := membership.UserID().String()
	s.cutAccess(ctx, tenantID, userID)

	actx.TenantID = tenantID
	event := auditapp.NewSuccessEvent(audit.ActionMemberOffboarded, audit.ResourceTypeMembership, membershipID).
		WithSeverity(audit.SeverityHigh).
		WithMessage("Member offboarded").
		WithMetadata("user_id", userID).
		WithMetadata("revoked_keys", result.RevokedKeys).
		WithMetadata("removed_groups", result.RemovedGroups).
		WithMetadata("removed_grants", result.RemovedGrants).
		WithMetadata("removed_campaigns", result.RemovedCampaigns).
		WithMetadata("reassigned_schedules", result.ReassignedSchedules).
		WithMetadata("reassigned_findings", result.ReassignedFindings).
		WithMetadata("reassigned_assets", result.ReassignedAssets)
	if plan.SchedulesTo != nil {
		event = event.WithMetadata("schedules_to", plan.SchedulesTo.String())
	}
	if plan.FindingsTo != nil {
		event = event.WithMetadata("findings_to", plan.FindingsTo.String())
	}
	if plan.AssetsTo != nil {
		event = event.WithMetadata("assets_to", plan.AssetsTo.String())
	}
	s.logAudit(ctx, actx, event)
	s.logger.Info("member offboarded", "membership_id", membership.ID().String(), "user_id", userID)
	return result, nil
}

// DeprovisionMember is the system (SCIM delete) variant of offboarding: when
// the member owns nothing that needs a new owner they are offboarded; when
// they do, they are disabled (access cut at once) and the administrators are
// asked to finish the offboarding with a reassignment.
func (s *TenantService) DeprovisionMember(ctx context.Context, membershipID string, actx auditapp.AuditContext) error {
	if s.lifecycle == nil {
		return s.SuspendMember(ctx, membershipID, actx)
	}
	_, err := s.OffboardMember(ctx, membershipID, OffboardMemberInput{}, actx)
	if err == nil {
		return nil
	}
	re, ok := tenantdom.AsReassignmentError(err)
	if !ok {
		return err
	}
	membership, gerr := s.getOwnMembership(ctx, membershipID, actx.TenantID)
	if gerr != nil {
		return gerr
	}
	if membership.IsActive() {
		if serr := s.SuspendMember(ctx, membershipID, actx); serr != nil {
			return serr
		}
	}
	s.notifyAdmins(ctx, membership.TenantID(),
		"A deprovisioned member needs an offboarding",
		fmt.Sprintf("Your identity provider removed a member. Their access is cut (disabled), but they still own %s: open Members and offboard them to hand it to someone else.",
			strings.Join(re.Missing, ", ")),
		notificationdom.SeverityHigh)
	return nil
}

// EraseMemberPersonalData anonymises an offboarded person's name and email
// (owner only). The user row and every foreign key to it stay; history shows
// "Deleted user #<hash>".
func (s *TenantService) EraseMemberPersonalData(ctx context.Context, membershipID string, actx auditapp.AuditContext) error {
	if s.lifecycle == nil {
		return fmt.Errorf("member lifecycle is not configured")
	}
	membership, err := s.getOwnMembership(ctx, membershipID, actx.TenantID)
	if err != nil {
		return err
	}
	actorID, err := shared.IDFromString(actx.ActorID)
	if err != nil {
		return ErrOwnerRequiredForErase
	}
	actor, err := s.repo.GetMembership(ctx, actorID, membership.TenantID())
	if err != nil || actor == nil || !actor.IsOwner() || !actor.IsActive() {
		return ErrOwnerRequiredForErase
	}
	if !membership.IsOffboarded() {
		return tenantdom.ErrEraseNotAllowed
	}
	label := ErasedUserLabel(membership.UserID())
	if err := s.lifecycle.ErasePersonalData(ctx, membership.TenantID(), membership.UserID(), label); err != nil {
		return err
	}
	if s.sessionService != nil {
		if err := s.sessionService.RevokeAllSessions(ctx, membership.UserID().String(), ""); err != nil {
			s.logger.Warn("failed to revoke sessions on erase", "error", err)
		}
	}
	actx.TenantID = membership.TenantID().String()
	s.logAudit(ctx, actx, auditapp.NewSuccessEvent(audit.ActionMemberDataErased, audit.ResourceTypeMembership, membershipID).
		WithSeverity(audit.SeverityCritical).
		WithMessage("Member personal data erased").
		WithMetadata("user_id", membership.UserID().String()).
		WithMetadata("label", label))
	return nil
}

// ErasedUserLabel is the display name an erased account keeps: stable per
// user, carries no personal data.
func ErasedUserLabel(userID shared.ID) string {
	sum := sha256.Sum256([]byte(userID.String()))
	return "Deleted user #" + hex.EncodeToString(sum[:4])
}

// cutAccess drops every cache that could still admit the user to this
// tenant, closes their sockets (the permission-version change closes them)
// and ends the sessions this tenant may end (endTenantSessions).
func (s *TenantService) cutAccess(ctx context.Context, tenantID, userID string) {
	s.invalidateUserPermissions(ctx, tenantID, userID)
	s.invalidateMembershipCache(ctx, tenantID, userID)
	s.endTenantSessions(ctx, tenantID, userID)
	if tid, err := shared.IDFromString(tenantID); err == nil {
		if uid, uerr := shared.IDFromString(userID); uerr == nil {
			if _, derr := s.repo.DeletePendingInvitationsByUserID(ctx, tid, uid); derr != nil {
				s.logger.Warn("failed to clean up invitations", "error", derr)
			}
		}
	}
}

// endTenantSessions is the session side of cutting one member's access to
// one tenant. Users are global, so the person's sessions also serve their
// other organizations: a suspension or removal here must not sign them out
// there (an administrator of one organization could otherwise log a member
// of another out at will).
//
//   - The tenant's own access is already closed without touching sessions:
//     every tenant request re-checks the membership (RequireMembership,
//     RequireActiveMembershipFromJWT, the WebSocket upgrade), the caches
//     were just dropped, and token exchange and refresh mint tokens only for
//     active memberships.
//   - Sessions this tenant's identity provider signed in end with it: the
//     organization's assertion was their only proof of identity.
//   - A person with no other organization left has nothing to protect
//     elsewhere: every session ends, as before.
//
// Account-wide actions (password reset, a platform administrator disabling
// the account, erasing personal data) still revoke every session.
func (s *TenantService) endTenantSessions(ctx context.Context, tenantID, userID string) {
	if s.sessionService == nil {
		return
	}
	if !s.hasOtherOrganization(ctx, tenantID, userID) {
		if err := s.sessionService.RevokeAllSessions(ctx, userID, ""); err != nil {
			s.logger.Warn("failed to revoke sessions", "user_id", userID, "error", err)
		}
		return
	}
	n, err := s.sessionService.RevokeSessionsIssuedBy(ctx, userID, tenantID)
	if err != nil {
		s.logger.Warn("failed to revoke the tenant's sessions", "user_id", userID, "tenant_id", tenantID, "error", err)
		return
	}
	s.logger.Info("member access cut in one organization; sessions kept for the others",
		"user_id", userID, "tenant_id", tenantID, "revoked_idp_sessions", n)
}

// hasOtherOrganization reports whether the user still belongs (active or
// suspended, not offboarded) to an organization other than tenantID. On a
// lookup error it answers true: the tenant's own access is cut either way,
// and other organizations' sessions are not this tenant's to end.
func (s *TenantService) hasOtherOrganization(ctx context.Context, tenantID, userID string) bool {
	uid, err := shared.IDFromString(userID)
	if err != nil {
		return true
	}
	tenants, err := s.repo.ListTenantsByUser(ctx, uid)
	if err != nil {
		s.logger.Warn("list organizations of a member", "user_id", userID, "error", err)
		return true
	}
	for _, t := range tenants {
		if t != nil && t.Tenant != nil && t.Tenant.ID().String() != tenantID {
			return true
		}
	}
	return false
}

// notifyAdmins tells every active owner and administrator, in-app. Best
// effort: the action already happened and is audited.
func (s *TenantService) notifyAdmins(ctx context.Context, tenantID shared.ID, title, body, severity string) {
	if s.lifecycle == nil || s.lifecycleNotifier == nil {
		return
	}
	admins, err := s.lifecycle.ActiveAdminIDs(ctx, tenantID)
	if err != nil {
		s.logger.Warn("list admins for lifecycle notice", "error", err)
		return
	}
	for _, id := range admins {
		uid := id
		if err := s.lifecycleNotifier.Notify(ctx, notificationdom.NotificationParams{
			TenantID:         tenantID,
			Audience:         notificationdom.AudienceUser,
			AudienceID:       &uid,
			NotificationType: notificationdom.TypeMemberLifecycle,
			Title:            title,
			Body:             body,
			Severity:         severity,
			ResourceType:     "membership",
			URL:              "/settings/users",
		}); err != nil {
			s.logger.Warn("notify admin of member lifecycle", "error", err)
		}
	}
}

func pausedSummary(r *tenantdom.DisableResult) string {
	var parts []string
	if n := len(r.PausedScans); n > 0 {
		parts = append(parts, fmt.Sprintf("%d scan schedule(s)", n))
	}
	if n := len(r.PausedReports); n > 0 {
		parts = append(parts, fmt.Sprintf("%d report schedule(s)", n))
	}
	if n := len(r.PausedWorkflow); n > 0 {
		parts = append(parts, fmt.Sprintf("%d workflow(s)", n))
	}
	return strings.Join(parts, ", ")
}
