package tenant

// Invitation preview: what will happen if this address is invited with these
// roles (docs/rfcs/RFC-095-role-templates-and-invitations.md §4.3). The
// console calls it while the inviter types, so the rules show up as guidance
// before anything is sent, not as an error after.
//
// It reveals nothing about other organizations: only whether the address is
// inside this organization, outside it, or personal; never whether another
// organization holds the domain, nor which.

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/openctemio/openctem/api/internal/app/accesscontrol"
	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	roledom "github.com/openctemio/openctem/api/pkg/domain/role"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	tenantdom "github.com/openctemio/openctem/api/pkg/domain/tenant"
)

// InvitationPreview answers PreviewInvitation.
type InvitationPreview struct {
	// Allowed: an invitation with these values would be accepted now
	// (step-up aside). Reason is a stable code when not.
	Allowed bool
	Reason  string
	// Outside: the address is outside the organization; Personal: a
	// consumer mail address.
	Outside  bool
	Personal bool
	// Privileged: the roles are above member for an outside person; then
	// StepUpRequired (the inviter re-authenticates) and MFARequired (the
	// member proves a second factor at every sign-in to the organization).
	Privileged     bool
	StepUpRequired bool
	MFARequired    bool
	// AccessEndRequired: the organization requires an end of access for
	// this person (DefaultAccessEndDays when none is given).
	AccessEndRequired    bool
	DefaultAccessEndDays int
	MaxAccessEndDays     int
	// SSOExceptionNeeded: the organization enforces SSO and this person
	// will not sign in through it; an owner must add an SSO exception.
	SSOExceptionNeeded bool
	AlreadyMember      bool
	AlreadyInvited     bool
}

// Preview refusal codes.
const (
	PreviewInvalidEmail       = "INVALID_EMAIL"
	PreviewNotOnVerified      = "INVITEE_NOT_ON_VERIFIED_DOMAIN"
	PreviewDomainNotAllowed   = "INVITEE_DOMAIN_NOT_ALLOWED"
	PreviewPersonalBlocked    = "PERSONAL_ACCOUNTS_BLOCKED"
	PreviewAboveTrustCeiling  = "ABOVE_TRUST_CEILING"
	PreviewAlreadyMember      = "ALREADY_MEMBER"
	PreviewAlreadyInvited     = "ALREADY_INVITED"
	PreviewRoleNotGrantable   = "ROLE_NOT_GRANTABLE"
	PreviewAdminNeedsTheOwner = "ADMIN_NEEDS_OWNER"
	PreviewTeamNotGrantable   = "TEAM_NOT_GRANTABLE"
)

// PreviewInvitation reports what inviting email with roleIDs would do. The
// caller passed the same route gate as creating an invitation.
func (s *TenantService) PreviewInvitation(ctx context.Context, tenantID, email string, roleIDs []string, actx auditapp.AuditContext) (*InvitationPreview, error) {
	return s.PreviewInvitationWithTeams(ctx, tenantID, email, roleIDs, nil, actx)
}

// PreviewInvitationWithTeams is PreviewInvitation with the teams the invitee
// would join (groupIDs).
func (s *TenantService) PreviewInvitationWithTeams(ctx context.Context, tenantID, email string, roleIDs, groupIDs []string, actx auditapp.AuditContext) (*InvitationPreview, error) {
	tid, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid id format", shared.ErrValidation)
	}
	email = strings.TrimSpace(email)
	out := &InvitationPreview{Allowed: true,
		DefaultAccessEndDays: tenantdom.DefaultExternalAccessDays, MaxAccessEndDays: tenantdom.MaxExternalAccessDays}
	at := strings.LastIndex(email, "@")
	if at <= 0 || at == len(email)-1 || len(email) > 254 {
		out.refuse(PreviewInvalidEmail)
		return out, nil
	}
	if !s.previewRoles(ctx, tid, roleIDs, actx, out) {
		return out, nil
	}
	switch err := s.requireInvitable(ctx, tid, email); {
	case err == nil:
	case errors.Is(err, ErrInviteeNotOnVerifiedDomain):
		out.refuse(PreviewNotOnVerified)
	case errors.Is(err, ErrEmailDomainNotAllowed):
		out.refuse(PreviewDomainNotAllowed)
	default:
		return nil, err
	}
	if err := s.previewInvitee(ctx, tid, email, roleIDs, out); err != nil {
		return nil, err
	}
	if err := s.previewTeams(ctx, tid, groupIDs, actx.ActorID, out); err != nil {
		return nil, err
	}
	if err := s.previewExisting(ctx, tid, email, out); err != nil {
		return nil, err
	}
	return out, nil
}

// refuse marks the preview refused; the first reason wins.
func (p *InvitationPreview) refuse(code string) {
	p.Allowed = false
	if p.Reason == "" {
		p.Reason = code
	}
}

// previewRoles checks the roles; false when they alone refuse the invitation.
func (s *TenantService) previewRoles(ctx context.Context, tid shared.ID, roleIDs []string, actx auditapp.AuditContext, out *InvitationPreview) bool {
	if len(roleIDs) == 0 {
		return true
	}
	if err := accesscontrol.ValidateGrantableRoleIDs(roleIDs); err != nil {
		out.refuse(PreviewRoleNotGrantable)
		return false
	}
	if s.roleService != nil {
		if err := s.roleService.ValidateRolesForTenant(ctx, tid.String(), roleIDs); err != nil {
			out.refuse(PreviewRoleNotGrantable)
			return false
		}
	}
	if slices.ContainsFunc(roleIDs, func(r string) bool { return strings.EqualFold(r, roledom.AdminRoleID.String()) }) {
		if err := s.authorizeAdminPromotionNoStepUp(ctx, tid, actx); err != nil {
			out.refuse(PreviewAdminNeedsTheOwner)
			return false
		}
		out.StepUpRequired = true // making anyone an administrator
	}
	return true
}

// previewInvitee classifies the address and applies the outside-member rules.
func (s *TenantService) previewInvitee(ctx context.Context, tid shared.ID, email string, roleIDs []string, out *InvitationPreview) error {
	class, _, err := s.classifyInvitee(ctx, tid, email, tenantdom.ExternalAccess{}, time.Now().UTC())
	if err != nil {
		return err
	}
	out.Outside = class.Kind == tenantdom.MemberKindExternal
	out.Personal = class.Personal
	if err := s.requirePersonalAllowed(ctx, tid, class); err != nil {
		if !errors.Is(err, ErrPersonalAccountsBlocked) {
			return err
		}
		out.refuse(PreviewPersonalBlocked)
	}
	if !out.Outside {
		return nil
	}
	out.AccessEndRequired = class.ExpiryRequired()
	if len(roleIDs) > 0 {
		if err := s.requireWithinTrustCeiling(ctx, tid, class, roleIDs); err != nil {
			if !errors.Is(err, accesscontrol.ErrGrantForbidden) {
				return err
			}
			out.refuse(PreviewAboveTrustCeiling)
		}
		privileged, err := s.privilegedRoleSet(ctx, tid, roleIDs)
		if err != nil {
			return err
		}
		out.Privileged, out.MFARequired = privileged, privileged
		out.StepUpRequired = out.StepUpRequired || privileged
	}
	if t, err := s.repo.GetByID(ctx, tid); err == nil {
		if sec, serr := t.SecuritySettingsStrict(); serr == nil && sec.SSOEnforced {
			out.SSOExceptionNeeded = true
		}
	}
	return nil
}

// previewExisting reports an existing membership or pending invitation.
func (s *TenantService) previewExisting(ctx context.Context, tid shared.ID, email string, out *InvitationPreview) error {
	m, err := s.repo.GetMemberByEmail(ctx, tid, email)
	switch {
	case err == nil && m != nil && m.Status != string(tenantdom.MemberStatusOffboarded):
		out.AlreadyMember = true
		out.refuse(PreviewAlreadyMember)
	case err != nil && !errors.Is(err, shared.ErrNotFound):
		return err
	}
	inv, err := s.repo.GetPendingInvitationByEmail(ctx, tid, email)
	switch {
	case err == nil && inv != nil:
		out.AlreadyInvited = true
		out.refuse(PreviewAlreadyInvited)
	case err != nil && !errors.Is(err, shared.ErrNotFound):
		return err
	}
	return nil
}
