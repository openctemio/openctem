package auth

// Administrator reset of a member's two-factor authentication, for a member
// who lost their authenticator and their recovery codes.
//
// The factor belongs to the user account, not to one organization: turning it
// off weakens the account everywhere the user signs in. The rules below keep
// an administrator of one organization from weakening an account they have no
// authority over:
//
//   - The target must be a member of the caller's organization (else not found).
//   - The caller must be an active owner or administrator there.
//   - Nobody resets their own factor here: that is the self-service disable,
//     which needs the password and a current code, so a hijacked admin session
//     cannot strip its own second factor.
//   - An owner or administrator target needs an owner caller (the peer
//     administrator rule used for every other member change).
//   - The same authority is required in EVERY other organization the target
//     belongs to (active or suspended). An administrator of organization A
//     therefore cannot weaken the account of someone who is also a member,
//     administrator or owner of organization B, unless they hold the same
//     authority in B.
//
// A reset removes the factor and its recovery codes, signs the user out of
// every session, writes a high-severity audit event in the caller's
// organization, and e-mails the user when e-mail is configured. If the
// organization requires 2FA, the user's next password sign-in asks them to
// enroll again.

import (
	"context"
	"errors"
	"fmt"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	auditdom "github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/mfa"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	tenantdom "github.com/openctemio/openctem/api/pkg/domain/tenant"
)

var (
	// ErrMFAResetSelf: the caller targeted their own membership.
	ErrMFAResetSelf = fmt.Errorf("%w: you cannot reset your own two-factor authentication here; turn it off from your account security settings", shared.ErrValidation)
	// ErrMFAResetOwnerRequired: an owner or administrator target needs an owner.
	ErrMFAResetOwnerRequired = fmt.Errorf("%w: only the organization owner can reset the two-factor authentication of an owner or administrator", shared.ErrForbidden)
	// ErrMFAResetOtherOrganization: the target belongs to another organization
	// where the caller lacks the same authority.
	ErrMFAResetOtherOrganization = fmt.Errorf("%w: this user also belongs to another organization where you cannot manage them; ask an administrator of that organization", shared.ErrForbidden)
)

// ResetMemberMFA turns off the second factor of the member with membershipID
// in tenantID, on behalf of actx.ActorID. See the file comment for the rules.
func (s *AuthService) ResetMemberMFA(ctx context.Context, actx auditapp.AuditContext, tenantID, membershipID string) error {
	if !s.mfaEnabled() || s.tenantRepo == nil {
		return ErrMFAUnavailable
	}
	tid, err := shared.IDFromString(tenantID)
	if err != nil {
		return fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}
	mid, err := shared.IDFromString(membershipID)
	if err != nil {
		return fmt.Errorf("%w: invalid membership id", shared.ErrValidation)
	}
	actorID, err := shared.IDFromString(actx.ActorID)
	if err != nil || actorID.IsZero() {
		return fmt.Errorf("%w: an acting user is required", shared.ErrForbidden)
	}

	target, err := s.tenantRepo.GetMembershipByID(ctx, mid)
	if err != nil {
		if errors.Is(err, shared.ErrNotFound) {
			return shared.ErrNotFound
		}
		return fmt.Errorf("get membership: %w", err)
	}
	// Another tenant's membership is indistinguishable from a missing one.
	if target.TenantID() != tid {
		return shared.ErrNotFound
	}
	if target.UserID() == actorID {
		return ErrMFAResetSelf
	}
	if err := s.mayResetIn(ctx, actorID, tid, target.Role()); err != nil {
		return err
	}

	others, err := s.tenantRepo.GetUserMembershipsWithStatus(ctx, target.UserID())
	if err != nil {
		return fmt.Errorf("list the user's organizations: %w", err)
	}
	for _, list := range [][]tenantdom.UserMembership{others.Active, others.Suspended} {
		for _, m := range list {
			otherID, perr := shared.IDFromString(m.TenantID)
			if perr != nil {
				return ErrMFAResetOtherOrganization
			}
			if otherID == tid {
				continue
			}
			role, _ := tenantdom.ParseRole(m.Role)
			if err := s.mayResetIn(ctx, actorID, otherID, role); err != nil {
				return ErrMFAResetOtherOrganization
			}
		}
	}

	u, err := s.userRepo.GetByID(ctx, target.UserID())
	if err != nil {
		return fmt.Errorf("failed to get user: %w", err)
	}
	if !isPasswordAccount(u) {
		return ErrMFANotSupported
	}
	f, err := s.mfaRepo.GetFactor(ctx, u.ID())
	if errors.Is(err, mfa.ErrFactorNotFound) || (err == nil && !f.Enabled) {
		return ErrMFANotEnabled
	}
	if err != nil {
		return err
	}
	if err := s.mfaRepo.Disable(ctx, u.ID()); err != nil {
		return err
	}

	// Every session goes: whoever holds one may have opened it while the
	// account was protected, and the user re-authenticates (and re-enrolls if
	// the organization requires it) on their next sign-in.
	s.revokeUserSessions(ctx, u.ID(), shared.ID{})

	actx.TenantID = tid.String()
	s.audit(ctx, actx, auditapp.NewSuccessEvent(auditdom.ActionAuthMFAReset, auditdom.ResourceTypeUser, u.ID().String()).
		WithResourceName(u.Email()).
		WithSeverity(auditdom.SeverityHigh).
		WithMessage("Two-factor authentication reset by an administrator").
		WithMetadata("membership_id", target.ID().String()).
		WithMetadata("target_role", target.Role().String()))

	if s.securityNotifier != nil {
		s.securityNotifier.NotifyMFADisabled(ctx, u.Email(), u.Name(), actx.ActorIP)
	}
	return nil
}

// mayResetIn reports whether actorID may reset the factor of a member holding
// targetRole in tenantID: the actor must be an active owner or administrator
// there, and an owner or administrator target needs an owner.
func (s *AuthService) mayResetIn(ctx context.Context, actorID, tenantID shared.ID, targetRole tenantdom.Role) error {
	actor, err := s.tenantRepo.GetMembership(ctx, actorID, tenantID)
	if err != nil || actor == nil || actor.IsSuspended() {
		return fmt.Errorf("%w: you are not an administrator of this organization", shared.ErrForbidden)
	}
	switch actor.Role() {
	case tenantdom.RoleOwner:
		return nil
	case tenantdom.RoleAdmin:
		if targetRole == tenantdom.RoleOwner || targetRole == tenantdom.RoleAdmin {
			return ErrMFAResetOwnerRequired
		}
		return nil
	default:
		return fmt.Errorf("%w: you are not an administrator of this organization", shared.ErrForbidden)
	}
}
