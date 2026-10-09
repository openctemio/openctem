package tenant

// The platform policy for scope-widening approvals (RFC-054 §12.6): a
// platform administrator's setting, as a platform default and per
// organization. It decides how much of the second-person approval of a
// widening the organization gets to relax. It never turns scope off: step-up,
// the dry run, ownership proof, the platform deny list, audit and the
// notification of every administrator stay in every mode.

import (
	"fmt"
	"strings"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// ScopeApprovalMode is how widening approvals work for an organization.
type ScopeApprovalMode string

// Modes.
const (
	// ScopeApprovalRequired: the organization's 0/1/2, at least 1 with two
	// or more administrators and for t2 (the default).
	ScopeApprovalRequired ScopeApprovalMode = "required"
	// ScopeApprovalTenantControlled: the organization's owner sets 0, 1 or 2
	// for every tier, t2 included.
	ScopeApprovalTenantControlled ScopeApprovalMode = "tenant_controlled"
	// ScopeApprovalDisabled: no approval for any tier (a member's request
	// still needs an approver).
	ScopeApprovalDisabled ScopeApprovalMode = "disabled"
)

// ScopeApprovalPolicyKey is the platform_settings key of the platform
// default.
const ScopeApprovalPolicyKey = "scope_approval_policy"

// ParseScopeApprovalMode reads a mode.
func ParseScopeApprovalMode(s string) (ScopeApprovalMode, error) {
	switch m := ScopeApprovalMode(strings.TrimSpace(s)); m {
	case ScopeApprovalRequired, ScopeApprovalTenantControlled, ScopeApprovalDisabled:
		return m, nil
	}
	return "", fmt.Errorf("%w: mode must be required, tenant_controlled or disabled", shared.ErrValidation)
}

// Valid reports whether m is a known mode.
func (m ScopeApprovalMode) Valid() bool {
	_, err := ParseScopeApprovalMode(string(m))
	return err == nil
}

// EffectiveApprovalsUnder is EffectiveApprovals under the platform policy:
//
//   - required (and anything unknown, fail closed): EffectiveApprovals;
//   - tenant_controlled: the organization's explicit 0, 1 or 2 for every
//     tier; unset keeps the required default;
//   - disabled: none.
func (s ScopeSettings) EffectiveApprovalsUnder(mode ScopeApprovalMode, admins int, intrusive bool) int {
	switch mode {
	case ScopeApprovalDisabled:
		return 0
	case ScopeApprovalTenantControlled:
		if s.WideningApprovals != nil {
			return min(max(0, *s.WideningApprovals), MaxScopeApprovals)
		}
	}
	return s.EffectiveApprovals(admins, intrusive)
}
