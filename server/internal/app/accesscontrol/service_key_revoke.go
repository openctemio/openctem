package accesscontrol

import (
	"context"
	"fmt"

	roledom "github.com/openctemio/openctem/api/pkg/domain/role"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// manageServiceAccountsPermission is the permission whose loss ends a member's
// accountability for the service-account keys they minted.
const manageServiceAccountsPermission = "service_accounts:manage"

type serviceKeyRevoker interface {
	RevokeServiceAccountKeys(ctx context.Context, tenantID, userID shared.ID, revokedBy *shared.ID) (int, error)
}

// SetServiceKeyRevoker wires the revoke of the service-account keys a member
// minted, run when a role change takes service_accounts:manage from them.
func (s *RoleService) SetServiceKeyRevoker(r serviceKeyRevoker) { s.keyRevoker = r }

// holdsServiceAccountsManage reports whether the user holds the permission now
// (through any role or team). A lookup error counts as held: before a change
// that errs toward revoking, and after it the caller treats an error as lost.
func (s *RoleService) holdsServiceAccountsManage(ctx context.Context, tid, uid roledom.ID) bool {
	held, err := s.lookupServiceAccountsManage(ctx, tid, uid)
	return held || err != nil
}

func (s *RoleService) lookupServiceAccountsManage(ctx context.Context, tid, uid roledom.ID) (bool, error) {
	if s.keyRevoker == nil {
		return false, nil
	}
	perms, err := s.roleRepo.GetUserPermissions(ctx, tid, uid)
	if err != nil {
		return false, err
	}
	for _, p := range perms {
		if p == manageServiceAccountsPermission {
			return true, nil
		}
	}
	return false, nil
}

// revokeKeysIfManageLost revokes the keys the user minted when they held
// service_accounts:manage before a role change and no longer do. A failure
// fails the request: the role change is already stored, so the caller sees an
// error and the keys are never silently left live (running the change again
// is refused, so the revoke is retried by a demotion or offboarding).
func (s *RoleService) revokeKeysIfManageLost(ctx context.Context, tid, uid roledom.ID, hadManage bool, actorID string) (int, error) {
	if !hadManage || s.keyRevoker == nil {
		return 0, nil
	}
	// An unreadable permission set revokes: the safe side.
	if held, err := s.lookupServiceAccountsManage(ctx, tid, uid); err == nil && held {
		return 0, nil
	}
	var by *shared.ID
	if id, err := shared.IDFromString(actorID); err == nil {
		by = &id
	}
	n, err := s.keyRevoker.RevokeServiceAccountKeys(ctx, asSharedID(tid), asSharedID(uid), by)
	if err != nil {
		s.logger.Error("failed to revoke service account keys after a role change", "error", err)
		return 0, fmt.Errorf("the role change is stored but revoking the member's service-account keys failed: %w", err)
	}
	return n, nil
}
