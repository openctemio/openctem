package accesscontrol

import (
	"context"
	"fmt"
	"strings"

	roledom "github.com/openctemio/openctem/api/pkg/domain/role"
)

// ErrDeferredGrantVoid refuses a grant authorized earlier (an invitation)
// whose grantor can no longer make it.
var ErrDeferredGrantVoid = fmt.Errorf("%w: the person who offered these roles can no longer grant them", ErrGrantForbidden)

// AuthorizeDeferredGrant checks, at the moment a grant authorized earlier is
// carried out (an invitation being accepted), that the grantor could still
// make it now: they hold the owner or admin role in the tenant, the admin role
// is granted only by an owner, and every role passes their grant ceiling.
// The caller checks the grantor's membership is active.
func (s *RoleService) AuthorizeDeferredGrant(ctx context.Context, tenantID, grantorID string, roleIDs []string) error {
	tid, err := roledom.ParseID(tenantID)
	if err != nil {
		return fmt.Errorf("invalid tenant id: %w", err)
	}
	actor, err := s.loadGrantActor(ctx, tid, grantorID)
	if err != nil {
		return err
	}
	if actor.system {
		return ErrDeferredGrantVoid
	}
	uid, _ := roledom.ParseID(grantorID)
	roles, err := s.roleRepo.GetUserRoles(ctx, tid, uid)
	if err != nil {
		return fmt.Errorf("load grantor roles: %w", err)
	}
	admin := false
	for _, r := range roles {
		if r.ID() == roledom.OwnerRoleID || r.ID() == roledom.AdminRoleID {
			admin = true
		}
	}
	if !admin {
		return ErrDeferredGrantVoid
	}
	for _, raw := range roleIDs {
		if strings.EqualFold(raw, roledom.AdminRoleID.String()) && !actor.owner {
			return ErrDeferredGrantVoid
		}
		id, err := roledom.ParseID(raw)
		if err != nil {
			return fmt.Errorf("invalid role id: %w", err)
		}
		r, err := s.roleForTenant(ctx, tenantID, id)
		if err != nil {
			return err
		}
		if err := actor.mayGrant(r); err != nil {
			return fmt.Errorf("%w: %w", ErrDeferredGrantVoid, err)
		}
	}
	return nil
}
