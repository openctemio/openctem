package auth

// The platform's two-factor floor (setting auth.mfa) in the sign-in gate and
// in credential creation. Design: research 308, decision D16;
// docs/architecture/two-factor-floor.md.
//
// A member needs 2FA in an organization when the organization requires it
// for them (everyone, or administrators) or the platform floor covers them.
// "Administrator" is effective privilege: the owner or admin role, or a
// privileged role granted to the member directly or through a team.

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/openctemio/openctem/api/internal/app/platformmfa"
	"github.com/openctemio/openctem/api/pkg/domain/permission"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/tenant"
)

// MFAFloorSource gives the platform floor policy (platformmfa.Service).
type MFAFloorSource interface {
	Policy(ctx context.Context) (platformmfa.Policy, error)
}

// PrivilegeSource tells what a member can do in an organization through all
// grants (accesscontrol.RoleService).
type PrivilegeSource interface {
	GetUserPermissions(ctx context.Context, tenantID, userID string) ([]string, error)
	HasFullDataAccess(ctx context.Context, tenantID, userID string) (bool, error)
}

// SetMFAFloor wires the platform floor and the privilege lookup. Without a
// floor source only the organizations' own requirements apply; without a
// privilege source "administrator" means the owner and admin roles.
func (s *AuthService) SetMFAFloor(floor MFAFloorSource, priv PrivilegeSource) {
	s.mfaFloor, s.privilege = floor, priv
}

// mfaRequirement is what an organization asks of one member.
type mfaRequirement struct {
	// Required: the member needs 2FA (by the organization or the floor).
	Required bool
	// ByOrganization: the organization's own settings require it, which has
	// no grace period.
	ByOrganization bool
	// DueAt is when a floor-only requirement starts to gate the member.
	DueAt time.Time
}

// mfaRequirementFor loads the member's role and decides the requirement.
func (s *AuthService) mfaRequirementFor(ctx context.Context, userID, tid shared.ID, sec tenant.SecuritySettings) (mfaRequirement, error) {
	if sec.MFARequired {
		return mfaRequirement{Required: true, ByOrganization: true}, nil
	}
	floor, err := s.mfaFloorPolicy(ctx)
	if err != nil {
		return mfaRequirement{}, err
	}
	if !sec.MFARequiredForAdmins && floor.Floor == tenant.MFAFloorNone {
		return mfaRequirement{}, nil
	}
	m, err := s.tenantRepo.GetMembership(ctx, userID, tid)
	if err != nil || m == nil {
		return mfaRequirement{}, fmt.Errorf("failed to load membership for 2FA policy: %w", err)
	}
	return s.mfaRequirementForRole(ctx, userID, tid, m.Role().String(), sec)
}

// mfaRequirementForRole decides the requirement of a member with a known role.
func (s *AuthService) mfaRequirementForRole(ctx context.Context, userID, tid shared.ID, role string, sec tenant.SecuritySettings) (mfaRequirement, error) {
	if sec.MFARequired {
		return mfaRequirement{Required: true, ByOrganization: true}, nil
	}
	floor, err := s.mfaFloorPolicy(ctx)
	if err != nil {
		return mfaRequirement{}, err
	}
	if !sec.MFARequiredForAdmins && floor.Floor == tenant.MFAFloorNone {
		return mfaRequirement{}, nil
	}
	privileged := tenant.IsAdminBaseRole(role)
	if !privileged && floor.Floor != tenant.MFAFloorEveryone {
		privileged, err = s.hasPrivilegedGrant(ctx, tid, userID)
		if err != nil {
			return mfaRequirement{}, err
		}
	}
	if sec.RequiresMFAByOrganization(role, privileged) {
		return mfaRequirement{Required: true, ByOrganization: true}, nil
	}
	if !floor.Floor.AppliesTo(role, privileged) {
		return mfaRequirement{}, nil
	}
	u, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return mfaRequirement{}, fmt.Errorf("failed to load user for 2FA policy: %w", err)
	}
	return mfaRequirement{Required: true, DueAt: floor.DueAt(u.CreatedAt())}, nil
}

func (s *AuthService) mfaFloorPolicy(ctx context.Context) (platformmfa.Policy, error) {
	if s.mfaFloor == nil {
		return platformmfa.Policy{Floor: tenant.MFAFloorNone}, nil
	}
	p, err := s.mfaFloor.Policy(ctx)
	if err != nil {
		// Fail closed: never decide on an unreadable platform policy.
		return platformmfa.Policy{}, fmt.Errorf("failed to read the platform 2FA floor: %w", err)
	}
	return p, nil
}

// hasPrivilegedGrant reports whether the member holds a privileged role
// through any grant in the organization.
func (s *AuthService) hasPrivilegedGrant(ctx context.Context, tid, userID shared.ID) (bool, error) {
	if s.privilege == nil {
		return false, nil
	}
	perms, err := s.privilege.GetUserPermissions(ctx, tid.String(), userID.String())
	if err != nil {
		return false, fmt.Errorf("failed to load permissions for 2FA policy: %w", err)
	}
	full, err := s.privilege.HasFullDataAccess(ctx, tid.String(), userID.String())
	if err != nil {
		return false, fmt.Errorf("failed to load data access for 2FA policy: %w", err)
	}
	return permission.IsPrivilegedRole(perms, full), nil
}

// CheckCredentialFactor gates creating a credential (API key, sensor
// enrolment, integration secret): when the organization or the platform floor
// covers the user, they must already hold a second factor, even while their
// grace period for sign-in has not ended. The sign-in rules apply as at token
// mint: a session from the organization's own identity provider counts unless
// the organization requires that provider to prove 2FA, a social or foreign
// provider session never counts. A caller with no platform session (an
// external OIDC token, whose provider owns 2FA) is not asked. It returns
// ErrMFAEnrollmentRequired or ErrSSOMFAEvidenceRequired.
func (s *AuthService) CheckCredentialFactor(ctx context.Context, userID, tenantID, sessionID string) error {
	if !s.mfaEnabled() || sessionID == "" {
		return nil
	}
	uid, err := shared.IDFromString(userID)
	if err != nil {
		return fmt.Errorf("%w: invalid user id", shared.ErrValidation)
	}
	tid, err := shared.IDFromString(tenantID)
	if err != nil {
		return fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}
	t, err := s.tenantRepo.GetByID(ctx, tid)
	if err != nil {
		return fmt.Errorf("failed to load tenant for 2FA policy: %w", err)
	}
	sec, err := t.SecuritySettingsStrict()
	if err != nil {
		return fmt.Errorf("failed to read 2FA policy: %w", err)
	}
	req, err := s.mfaRequirementFor(ctx, uid, tid, sec)
	if err != nil {
		return err
	}
	if !req.Required {
		return nil
	}
	sid, err := shared.IDFromString(sessionID)
	if err != nil {
		return errors.New("2FA check needs a valid session")
	}
	sess, err := s.sessionRepo.GetByID(ctx, sid)
	if err != nil || sess == nil {
		return fmt.Errorf("failed to load session for 2FA policy: %w", err)
	}
	return s.mfaSatisfied(ctx, sess, uid, tid, sec)
}
