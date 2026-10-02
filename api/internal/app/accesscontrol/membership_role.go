package accesscontrol

import (
	"context"
	"fmt"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	roledom "github.com/openctemio/openctem/api/pkg/domain/role"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	tenantdom "github.com/openctemio/openctem/api/pkg/domain/tenant"
)

// MembershipRoleForRoleIDs derives the coarse tenant_members.role for a user
// who is granted exactly roleIDs (RBAC roles) by an invitation or by an
// administrator creating the account.
//
// The membership role matters beyond display: a trigger on tenant_members
// copies it into user_roles as the matching system role. So it must never
// exceed what the granted roles imply. Only the system member/admin roles
// imply write access; anything else (viewer, custom roles) maps to viewer, the
// least-privileged membership. The system admin RBAC role keeps a 'member'
// membership: team administration (owner/admin membership) is a separate,
// explicit promotion and is not granted through an invitation.
func MembershipRoleForRoleIDs(roleIDs []string) tenantdom.Role {
	for _, raw := range roleIDs {
		id, err := roledom.ParseID(raw)
		if err != nil {
			continue
		}
		if id == roledom.MemberRoleID || id == roledom.AdminRoleID {
			return tenantdom.RoleMember
		}
	}
	return tenantdom.RoleViewer
}

// ValidateGrantableRoleIDs checks a role set granted by an invitation or by an
// administrator creating a user: at least one well-formed role id, and never
// the system owner role (ownership is not transferable that way).
func ValidateGrantableRoleIDs(roleIDs []string) error {
	if len(roleIDs) == 0 {
		return fmt.Errorf("%w: at least one role is required", shared.ErrValidation)
	}
	for _, raw := range roleIDs {
		id, err := roledom.ParseID(raw)
		if err != nil || raw == "" {
			return fmt.Errorf("%w: invalid role id", shared.ErrValidation)
		}
		if id == roledom.OwnerRoleID {
			return fmt.Errorf("%w: the owner role cannot be granted here", shared.ErrValidation)
		}
	}
	return nil
}

// GrantExactRoles makes roleIDs the user's complete RBAC role set in the
// tenant. Used right after a membership is created from an invitation or by an
// administrator, to remove the system role that the tenant_members trigger
// inserted from the coarse membership role, so the user ends up with exactly
// the roles they were granted and nothing more.
func (s *RoleService) GrantExactRoles(ctx context.Context, tenantID, userID string, roleIDs []string, grantedBy string, actx auditapp.AuditContext) error {
	return s.SetUserRoles(ctx, SetUserRolesInput{
		TenantID: tenantID,
		UserID:   userID,
		RoleIDs:  roleIDs,
	}, grantedBy, actx)
}

// InvitationMembershipRole is the membership role an accepted invitation
// creates: derived from the invitation's RBAC roles (see
// MembershipRoleForRoleIDs), so invitations stored before this rule existed,
// which always carried 'member', are also accepted with the right role.
// Legacy invitations without role ids keep their stored role.
func InvitationMembershipRole(inv *tenantdom.Invitation) tenantdom.Role {
	if len(inv.RoleIDs()) == 0 {
		return inv.Role()
	}
	return MembershipRoleForRoleIDs(inv.RoleIDs())
}
