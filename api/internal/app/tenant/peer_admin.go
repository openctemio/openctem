package tenant

import (
	"context"
	"fmt"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	tenantdom "github.com/openctemio/openctem/api/pkg/domain/tenant"
)

// ErrOwnerRequiredForAdminChange is returned when someone other than the
// organization's owner tries to change the role of, suspend, reactivate or
// remove an administrator. Administrators manage members and viewers; their
// peers are managed by the owner (owner decision 2026-10-02, AUTHZ B3).
var ErrOwnerRequiredForAdminChange = fmt.Errorf(
	"%w: only the organization owner can change, suspend, reactivate or remove an administrator", shared.ErrForbidden)

// authorizeMemberChange enforces the peer-administrator rule for a change to
// target made by actx.ActorID.
//
//   - A target that is not an administrator (or owner) is not affected: the
//     route gate (team admin) already decided.
//   - A change to oneself is not a peer change.
//   - An empty actor is a system path (SCIM provisioning), which is bounded by
//     its own rules and never acts as a peer.
//   - Otherwise the actor must be the owner. A failure to read the actor's
//     membership refuses the change.
//
// The owner target keeps its stricter, older rules (it can never be demoted,
// suspended or removed); this only adds the administrator case.
func (s *TenantService) authorizeMemberChange(ctx context.Context, target *tenantdom.Membership, actx auditapp.AuditContext) error {
	if actx.ActorID == "" {
		return nil
	}
	if !target.IsOwner() && target.Role() != tenantdom.RoleAdmin {
		return nil
	}
	if target.UserID().String() == actx.ActorID {
		return nil
	}
	actorID, err := shared.IDFromString(actx.ActorID)
	if err != nil {
		return fmt.Errorf("%w: invalid acting user id", shared.ErrValidation)
	}
	actor, err := s.repo.GetMembership(ctx, actorID, target.TenantID())
	if err != nil || actor == nil || !actor.IsOwner() || !actor.IsActive() {
		return ErrOwnerRequiredForAdminChange
	}
	return nil
}

// ErrOwnerRequiredForAdminPromotion is returned when someone other than the
// organization's owner tries to make a user an administrator (settings
// decision B2, 2026-10-04): by adding them as admin, changing their role to
// admin or inviting them with the admin role. Step-up re-authentication for
// this action follows with the step-up primitive (settings plan P1-01).
var ErrOwnerRequiredForAdminPromotion = fmt.Errorf(
	"%w: only the organization owner can make someone an administrator", shared.ErrForbidden)

// authorizeAdminPromotion refuses to give the admin role unless the actor is
// the organization's active owner. An empty actor is a system path (SCIM,
// SSO), bounded by its own rules.
func (s *TenantService) authorizeAdminPromotion(ctx context.Context, tenantID shared.ID, actx auditapp.AuditContext) error {
	if actx.ActorID == "" {
		return nil
	}
	actorID, err := shared.IDFromString(actx.ActorID)
	if err != nil {
		return fmt.Errorf("%w: invalid acting user id", shared.ErrValidation)
	}
	actor, err := s.repo.GetMembership(ctx, actorID, tenantID)
	if err != nil || actor == nil || !actor.IsOwner() || actor.IsSuspended() {
		return ErrOwnerRequiredForAdminPromotion
	}
	return nil
}
