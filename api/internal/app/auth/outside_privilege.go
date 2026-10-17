package auth

// Two-factor for privileged outside members at token mint
// (docs/rfcs/RFC-095-role-templates-and-invitations.md §4.2).
//
// Someone outside the organization signs in with a mailbox the organization
// does not control. When such a member holds a privileged role (owner or
// admin, full data access, or a privileged permission: members, teams, roles,
// API keys, secret store, settings), every token minted for the organization
// needs a session that proved a second factor: a password session of a user
// with 2FA on, or a federated session whose provider proved one. Fail closed:
// a lookup error refuses the token; a server without 2FA support cannot
// mint one for such a member.

import (
	"context"
	"errors"
	"fmt"

	sessiondom "github.com/openctemio/openctem/api/pkg/domain/session"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	tenantdom "github.com/openctemio/openctem/api/pkg/domain/tenant"
)

func (s *AuthService) enforceOutsidePrivilegePolicy(ctx context.Context, sess *sessiondom.Session, userID shared.ID, tenantID string) error {
	tid, err := shared.IDFromString(tenantID)
	if err != nil {
		return fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}
	m, err := s.tenantRepo.GetMembership(ctx, userID, tid)
	if err != nil {
		if errors.Is(err, shared.ErrNotFound) {
			return nil // no membership is refused elsewhere
		}
		return fmt.Errorf("failed to load membership for the outside member policy: %w", err)
	}
	if m == nil || !m.IsExternal() {
		return nil
	}
	privileged, err := s.outsideMemberPrivileged(ctx, m, tid, userID)
	if err != nil {
		return err
	}
	if !privileged {
		return nil
	}
	ok, err := s.secondFactorProven(ctx, sess, userID)
	if err != nil {
		return err
	}
	if !ok {
		s.logger.Warn("blocked privileged outside member without a second factor",
			"tenant_id", tid.String(), "user_id", userID.String())
		return ErrMFAEnrollmentRequired
	}
	return nil
}

// outsideMemberPrivileged reports whether the member holds a privileged role.
func (s *AuthService) outsideMemberPrivileged(ctx context.Context, m *tenantdom.Membership, tid, userID shared.ID) (bool, error) {
	if m.Role() == tenantdom.RoleOwner || m.Role() == tenantdom.RoleAdmin {
		return true, nil
	}
	if s.roleService == nil {
		return false, nil
	}
	// Effective grants: direct roles and team role bindings alike.
	above, err := s.roleService.HoldsAboveMember(ctx, tid.String(), userID.String())
	if err != nil {
		return false, fmt.Errorf("failed to load grants for the outside member policy: %w", err)
	}
	return above, nil
}
