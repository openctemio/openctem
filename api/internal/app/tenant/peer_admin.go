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
// admin or inviting them with the admin role.
var ErrOwnerRequiredForAdminPromotion = fmt.Errorf(
	"%w: only the organization owner can make someone an administrator", shared.ErrForbidden)

// authorizeAdminPromotion refuses to give the admin role unless the actor is
// the organization's active owner who re-authenticated recently (step-up).
// An empty actor is a system path (SCIM, SSO), bounded by its own rules.
func (s *TenantService) authorizeAdminPromotion(ctx context.Context, tenantID shared.ID, actx auditapp.AuditContext) error {
	if err := s.authorizeAdminPromotionNoStepUp(ctx, tenantID, actx); err != nil {
		return err
	}
	if actx.ActorID == "" {
		return nil
	}
	return s.requireStepUp(ctx, actx.ActorID)
}

// authorizeAdminPromotionNoStepUp is the owner check of authorizeAdminPromotion.
func (s *TenantService) authorizeAdminPromotionNoStepUp(ctx context.Context, tenantID shared.ID, actx auditapp.AuditContext) error {
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

// requireStepUp asks the step-up gate, when one is wired, for the acting
// user's recent re-authentication.
func (s *TenantService) requireStepUp(ctx context.Context, actorID string) error {
	if s.stepUp == nil {
		return nil
	}
	return s.stepUp.RequireRecentAuth(ctx, actorID)
}

// SetStepUpGate wires step-up re-authentication for making someone an
// administrator and renaming the organization's slug
// (docs/architecture/step-up-reauth.md). Without it (a service built outside
// the HTTP server, such as the bootstrap CLI) the check is skipped.
func (s *TenantService) SetStepUpGate(g shared.RecentAuthGate) { s.stepUp = g }

// OwnerRoleDriftReader reads the raw membership label, which the effective
// role (owner role row) can differ from for a co-owner planted before system
// roles were limited to the membership routes.
type OwnerRoleDriftReader interface {
	MembershipLabel(ctx context.Context, tenantID, userID shared.ID) (string, error)
}

// ErrOwnerRoleDriftRemoval is returned when an owner role row without the
// owner membership is targeted by someone who may not remove it.
var ErrOwnerRoleDriftRemoval = fmt.Errorf(
	"%w: only the organization owner, with a recent re-authentication, can remove an owner role held without the owner membership", shared.ErrForbidden)

// authorizeOwnerDriftRemoval decides whether an effective owner target is in
// drift (owner role row, membership label not owner) and, if so, whether the
// actor may remove it: the actor holds the owner LABEL, is active, is not the
// target and passed a fresh step-up. A target whose label is owner is no drift
// (false, nil: the caller keeps its transfer-only rule). A drift target the
// actor may not touch returns an error.
func (s *TenantService) authorizeOwnerDriftRemoval(ctx context.Context, target *tenantdom.Membership, actx auditapp.AuditContext) (bool, error) {
	reader, ok := s.repo.(OwnerRoleDriftReader)
	if !ok {
		return false, nil
	}
	label, err := reader.MembershipLabel(ctx, target.TenantID(), target.UserID())
	if err != nil {
		return false, err
	}
	if label == tenantdom.RoleOwner.String() {
		return false, nil
	}
	// A system path (no human actor) never removes an owner role.
	if actx.ActorID == "" || actx.ActorID == target.UserID().String() {
		return false, ErrOwnerRoleDriftRemoval
	}
	actorID, err := shared.IDFromString(actx.ActorID)
	if err != nil {
		return false, fmt.Errorf("%w: invalid acting user id", shared.ErrValidation)
	}
	actor, err := s.repo.GetMembership(ctx, actorID, target.TenantID())
	if err != nil || actor == nil || !actor.IsActive() {
		return false, ErrOwnerRoleDriftRemoval
	}
	actorLabel, err := reader.MembershipLabel(ctx, target.TenantID(), actorID)
	if err != nil || actorLabel != tenantdom.RoleOwner.String() {
		return false, ErrOwnerRoleDriftRemoval
	}
	if err := s.requireStepUp(ctx, actx.ActorID); err != nil {
		return false, err
	}
	return true, nil
}
