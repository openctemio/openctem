package apikey

import (
	"context"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	tenantdom "github.com/openctemio/openctem/api/pkg/domain/tenant"
	userdom "github.com/openctemio/openctem/api/pkg/domain/user"
)

// MembershipSource reads a user's membership in a tenant (tenant.Repository).
type MembershipSource interface {
	GetMembership(ctx context.Context, userID, tenantID shared.ID) (*tenantdom.Membership, error)
}

// UserSource reads a user account (user.Repository).
type UserSource interface {
	GetByID(ctx context.Context, id shared.ID) (*userdom.User, error)
}

// PermissionSource returns a user's current permissions in a tenant
// (PermissionCacheService: Redis, then the role tables).
type PermissionSource interface {
	GetPermissionsWithFallback(ctx context.Context, tenantID, userID string) ([]string, error)
}

// NewMembershipChecker returns the MembershipChecker production wires: the
// key's user must be an ACTIVE member of the key's tenant and, when users is
// non-nil, an active account. A lookup error is returned and the key rejected.
func NewMembershipChecker(memberships MembershipSource, users UserSource) MembershipChecker {
	return membershipChecker{memberships: memberships, users: users}
}

type membershipChecker struct {
	memberships MembershipSource
	users       UserSource
}

func (c membershipChecker) IsActiveMember(ctx context.Context, tenantID, userID shared.ID) (bool, error) {
	m, err := c.memberships.GetMembership(ctx, userID, tenantID)
	if err != nil {
		return false, err
	}
	if m.Status() != tenantdom.MemberStatusActive {
		return false, nil
	}
	if c.users != nil {
		u, err := c.users.GetByID(ctx, userID)
		if err != nil {
			return false, err
		}
		if !u.IsActive() {
			return false, nil
		}
	}
	return true, nil
}

// NewHolderPermissions returns the HolderPermissions production wires. Owners
// and admins bypass permission checks on the JWT path, so they hold every
// permission; anyone else holds the permissions of their current roles.
func NewHolderPermissions(memberships MembershipSource, perms PermissionSource) HolderPermissions {
	return holderPermissions{memberships: memberships, perms: perms}
}

type holderPermissions struct {
	memberships MembershipSource
	perms       PermissionSource
}

func (h holderPermissions) HeldPermissions(ctx context.Context, tenantID, userID shared.ID) (bool, []string, error) {
	m, err := h.memberships.GetMembership(ctx, userID, tenantID)
	if err != nil {
		return false, nil, err
	}
	if r := m.Role(); r == tenantdom.RoleOwner || r == tenantdom.RoleAdmin {
		return true, nil, nil
	}
	perms, err := h.perms.GetPermissionsWithFallback(ctx, tenantID.String(), userID.String())
	if err != nil {
		return false, nil, err
	}
	return false, perms, nil
}
