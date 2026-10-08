package tenant

import (
	"fmt"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Approval-required just-in-time provisioning (RFC-058): an organization may
// hold everyone its SSO admits for the first time until an administrator
// approves them. The membership exists (so the request is visible and the
// person keeps one row) but is suspended with this reason; approving is
// re-enabling it, rejecting is offboarding it.

// SuspendedReasonAwaitingApproval marks a membership created by SSO
// just-in-time provisioning that waits for an administrator's approval.
const SuspendedReasonAwaitingApproval = "awaiting_approval"

// HoldForApproval suspends a new membership until an administrator approves
// it. Only an active, never-suspended membership can be held, and never an
// owner.
func (m *Membership) HoldForApproval() error {
	if !m.IsActive() {
		return fmt.Errorf("%w: only a new, active membership can wait for approval", shared.ErrValidation)
	}
	if err := m.Suspend(shared.ID{}); err != nil {
		return err
	}
	m.suspendedReason = SuspendedReasonAwaitingApproval
	return nil
}

// AwaitsApproval reports whether the membership waits for an administrator's
// approval.
func (m *Membership) AwaitsApproval() bool {
	return m.IsSuspended() && m.suspendedReason == SuspendedReasonAwaitingApproval
}

// PrivilegeRank orders membership roles for privilege-increase checks:
// viewer < member < admin < owner.
func PrivilegeRank(r Role) int {
	switch r {
	case RoleViewer:
		return 1
	case RoleMember:
		return 2
	case RoleAdmin:
		return 3
	case RoleOwner:
		return 4
	}
	return 0
}
