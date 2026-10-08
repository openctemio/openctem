package auth

import (
	"context"
	"errors"
	"fmt"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	tenantdom "github.com/openctemio/openctem/api/pkg/domain/tenant"
)

// Approval-required just-in-time provisioning (RFC-058): when the
// organization asks for it, a person SSO admits for the first time gets a
// membership that waits, suspended, until an administrator approves it.

// ErrSSOAwaitingApproval: the organization admitted the person through SSO,
// and an administrator has not approved them yet.
var ErrSSOAwaitingApproval = errors.New("access to this organization awaits an administrator's approval")

// JITApprovalNotifier tells an organization's administrators that someone
// waits for their approval (TenantService.NotifyAdmins).
type JITApprovalNotifier interface {
	NotifyAdmins(ctx context.Context, tenantID shared.ID, title, body, severity string)
}

// SetJITApprovalNotifier wires the administrators' notification.
func (s *SSOService) SetJITApprovalNotifier(n JITApprovalNotifier) { s.jitApprovals = n }

// holdIfApprovalRequired holds a new just-in-time membership for approval
// when the organization asks for it. Returns whether it was held.
func holdIfApprovalRequired(t *tenantdom.Tenant, m *tenantdom.Membership) (bool, error) {
	if t == nil || !t.TypedSettings().Security.JITRequiresApproval {
		return false, nil
	}
	if err := m.HoldForApproval(); err != nil {
		return false, fmt.Errorf("hold membership for approval: %w", err)
	}
	return true, nil
}

func (s *SSOService) notifyAwaitingApproval(ctx context.Context, t *tenantdom.Tenant, email string) {
	if s.jitApprovals == nil {
		return
	}
	s.jitApprovals.NotifyAdmins(ctx, t.ID(), "Someone waits for your approval",
		fmt.Sprintf("%s signed in through your SSO for the first time. They have no access until an administrator approves them in Members.", email),
		"medium")
}
