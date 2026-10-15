package tenant

import (
	"context"
	"errors"
	"fmt"

	"github.com/openctemio/openctem/api/internal/app/accesscontrol"
	roledom "github.com/openctemio/openctem/api/pkg/domain/role"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	tenantdom "github.com/openctemio/openctem/api/pkg/domain/tenant"
)

// authorizeInvitationGrant re-authorizes an invitation at acceptance
// (docs/rfcs/RFC-095-role-templates-and-invitations.md §3.2). An invitation
// grants its roles as the inviter, so the inviter must still be an active
// owner or administrator of the organization who could grant every role now.
// Otherwise the acceptance is refused and nothing is granted: a removed,
// suspended or demoted administrator's pending invitations stop working.
func (s *TenantService) authorizeInvitationGrant(ctx context.Context, inv *tenantdom.Invitation) error {
	return s.authorizeInvitationRoles(ctx, inv)
}

// authorizeInvitationRoles is the role half of authorizeInvitationGrant.
func (s *TenantService) authorizeInvitationRoles(ctx context.Context, inv *tenantdom.Invitation) error {
	m, err := s.repo.GetMembership(ctx, inv.InvitedBy(), inv.TenantID())
	if err != nil {
		if errors.Is(err, shared.ErrNotFound) {
			return ErrInvitationNoLongerValid
		}
		return fmt.Errorf("load the inviter's membership: %w", err)
	}
	if m == nil || !m.IsActive() {
		return ErrInvitationNoLongerValid
	}
	if s.roleService == nil || len(inv.RoleIDs()) == 0 {
		// Without the role service (or for a legacy invitation without role
		// ids) only the membership role can be read.
		if !m.IsOwner() && m.Role() != tenantdom.RoleAdmin {
			return ErrInvitationNoLongerValid
		}
		for _, raw := range inv.RoleIDs() {
			if raw == roledom.AdminRoleID.String() && !m.IsOwner() {
				return ErrInvitationNoLongerValid
			}
		}
		return nil
	}
	err = s.roleService.AuthorizeDeferredGrant(ctx, inv.TenantID().String(), inv.InvitedBy().String(), inv.RoleIDs())
	switch {
	case err == nil:
		return nil
	case errors.Is(err, accesscontrol.ErrGrantForbidden), errors.Is(err, roledom.ErrRoleNotFound):
		s.logger.Info("invitation acceptance refused: the inviter can no longer grant its roles",
			"invitation_id", inv.ID().String(), "reason", err.Error())
		return ErrInvitationNoLongerValid
	default:
		return err
	}
}
