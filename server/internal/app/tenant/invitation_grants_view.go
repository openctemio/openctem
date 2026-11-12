package tenant

// What an invitation will give, for the acceptance page (RFC-095 §5, docs/
// rfcs/RFC-095-role-templates-and-invitations.md): the roles with their risk,
// the teams, the end of access, whether the person is outside the
// organization and whether two-factor authentication will be required.
//
// The lookup is readable with the invitation token alone (before sign-in).
// It shows only what the invitation itself grants in the invitation's own
// organization: role names and risk, team names. Nothing about other members
// or other organizations.

import (
	"context"

	"github.com/openctemio/openctem/api/pkg/domain/permission"
	roledom "github.com/openctemio/openctem/api/pkg/domain/role"
	tenantdom "github.com/openctemio/openctem/api/pkg/domain/tenant"
)

// InvitationGrantRole is one role of an invitation as the invitee sees it.
type InvitationGrantRole struct {
	ID       string             `json:"id"`
	Name     string             `json:"name"`
	Slug     string             `json:"slug"`
	IsSystem bool               `json:"is_system"`
	Summary  permission.Summary `json:"summary"`
}

// InvitationGrantTeam is one team of an invitation.
type InvitationGrantTeam struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// MFA reasons on the acceptance page.
const (
	MFAReasonOutsidePrivileged = "outside_privileged"
	MFAReasonOrganization      = "organization_policy"
)

// InvitationGrants is what accepting the invitation gives.
type InvitationGrants struct {
	Roles []InvitationGrantRole `json:"roles"`
	Teams []InvitationGrantTeam `json:"teams"`
	// MemberKind: internal or external (outside the organization).
	MemberKind string `json:"member_kind"`
	// MFARequired: the person will set up or prove two-factor
	// authentication to open the organization; MFAReason says why.
	MFARequired bool   `json:"mfa_required"`
	MFAReason   string `json:"mfa_reason,omitempty"`
}

// InvitationGrants describes what accepting inv gives. Best effort: a role or
// team that cannot be read is left out rather than failing the page.
func (s *TenantService) InvitationGrants(ctx context.Context, inv *tenantdom.Invitation) InvitationGrants {
	out := InvitationGrants{Roles: []InvitationGrantRole{}, Teams: []InvitationGrantTeam{},
		MemberKind: string(inv.InviteeInfo().Kind)}
	if out.MemberKind == "" {
		out.MemberKind = string(tenantdom.MemberKindInternal)
	}
	if s.roleService != nil {
		for _, id := range inv.RoleIDs() {
			r, err := s.roleService.GetRole(ctx, inv.TenantID().String(), id)
			if err != nil {
				continue
			}
			bypass := r.ID() == roledom.OwnerRoleID || r.ID() == roledom.AdminRoleID
			out.Roles = append(out.Roles, InvitationGrantRole{
				ID: r.ID().String(), Name: r.Name(), Slug: r.Slug(), IsSystem: r.IsSystem(),
				Summary: permission.Summarize(r.Permissions(), r.HasFullDataAccess(), bypass),
			})
		}
	}
	if ids := inv.GroupIDs(); len(ids) > 0 && s.invitationTeams != nil {
		for _, t := range s.invitationTeams.InvitationTeamNames(ctx, inv.TenantID().String(), ids) {
			out.Teams = append(out.Teams, InvitationGrantTeam{ID: t.ID, Name: t.Name})
		}
	}
	switch {
	case inv.InviteeInfo().Privileged:
		out.MFARequired, out.MFAReason = true, MFAReasonOutsidePrivileged
	case s.organizationRequiresMFA(ctx, inv):
		out.MFARequired, out.MFAReason = true, MFAReasonOrganization
	}
	return out
}

// organizationRequiresMFA reports whether the organization's two-factor
// policy covers the invitee's membership role.
func (s *TenantService) organizationRequiresMFA(ctx context.Context, inv *tenantdom.Invitation) bool {
	t, err := s.repo.GetByID(ctx, inv.TenantID())
	if err != nil || t == nil {
		return false
	}
	sec, err := t.SecuritySettingsStrict()
	if err != nil {
		return false
	}
	return sec.MFARequired || sec.MFARequiredFor(inv.Role().String())
}
