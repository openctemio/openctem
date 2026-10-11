// Package scangov is scan approval governance (RFC-073,
// docs/rfcs/RFC-073-scan-approval-governance.md): an organization's opt-in
// rules for which scans need a person's approval before they run, the
// approval requests on scan definitions, and the platform policy that can
// force the setting for an organization.
//
// Off (the default) changes nothing: members with scan permission create and
// run scans directly. On applies the organization's approval rules. Strict
// applies them with two distinct approvers, a justification on every
// request, and keeps the scope-entry approvals of RFC-054 (and with them the
// job signer ledger's approval check, RFC-040 §11.5).
package scangov

import (
	"fmt"
	"strings"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Mode is an organization's scan approval setting.
type Mode string

// Modes.
const (
	// ModeOff: no scan needs approval (the default).
	ModeOff Mode = "off"
	// ModeOn: the organization's approval rules decide.
	ModeOn Mode = "on"
	// ModeStrict: the rules decide, every matched scan needs two distinct
	// approvers and a justification, and scope entries keep their
	// approvals (RFC-054 §7).
	ModeStrict Mode = "strict"
)

// ParseMode reads off, on or strict.
func ParseMode(s string) (Mode, error) {
	switch m := Mode(strings.ToLower(strings.TrimSpace(s))); m {
	case ModeOff, ModeOn, ModeStrict:
		return m, nil
	}
	return "", fmt.Errorf("%w: scan approval must be off, on or strict", shared.ErrValidation)
}

// Valid reports whether m is a known mode.
func (m Mode) Valid() bool {
	switch m {
	case ModeOff, ModeOn, ModeStrict:
		return true
	}
	return false
}

// Normalized is m, or off when m is empty (an organization that never set it).
func (m Mode) Normalized() Mode {
	if m.Valid() {
		return m
	}
	return ModeOff
}

// rank orders the modes from the least to the most governance.
func (m Mode) rank() int {
	switch m {
	case ModeOn:
		return 1
	case ModeStrict:
		return 2
	}
	return 0
}

// PlatformPolicy is a platform administrator's setting for an organization's
// scan approval: let the organization choose, or force a mode.
type PlatformPolicy string

// Platform policies.
const (
	// PolicyTenantControlled: the organization's owner chooses (default).
	PolicyTenantControlled PlatformPolicy = "tenant_controlled"
	// PolicyOff forces Off: no scan approval, and no scope-entry approvals.
	PolicyOff PlatformPolicy = "off"
	// PolicyOn forces at least On: the owner may still choose Strict.
	PolicyOn PlatformPolicy = "on"
	// PolicyStrict forces Strict.
	PolicyStrict PlatformPolicy = "strict"
)

// PlatformPolicyKey is the platform_settings key of the platform default.
const PlatformPolicyKey = "scan_approval_policy"

// ParsePlatformPolicy reads a platform policy.
func ParsePlatformPolicy(s string) (PlatformPolicy, error) {
	switch p := PlatformPolicy(strings.ToLower(strings.TrimSpace(s))); p {
	case PolicyTenantControlled, PolicyOff, PolicyOn, PolicyStrict:
		return p, nil
	}
	return "", fmt.Errorf("%w: policy must be tenant_controlled, off, on or strict", shared.ErrValidation)
}

// Valid reports whether p is a known policy.
func (p PlatformPolicy) Valid() bool {
	_, err := ParsePlatformPolicy(string(p))
	return err == nil && string(p) == strings.ToLower(strings.TrimSpace(string(p)))
}

// Sources of an effective mode.
const (
	SourceOrganization = "organization"
	SourcePlatform     = "platform"
)

// Effective is the mode in force for an organization whose owner chose
// tenant under platform policy p, and who decided it. An unknown policy is
// tenant_controlled (the platform reads fail closed upstream: they answer
// the stored value or refuse).
func Effective(tenant Mode, p PlatformPolicy) (Mode, string) {
	tenant = tenant.Normalized()
	switch p {
	case PolicyOff:
		return ModeOff, SourcePlatform
	case PolicyStrict:
		return ModeStrict, SourcePlatform
	case PolicyOn:
		if tenant.rank() < ModeOn.rank() {
			return ModeOn, SourcePlatform
		}
	}
	return tenant, SourceOrganization
}

// TenantMayChoose reports whether the organization's owner may set m under
// policy p (a forced policy refuses a change it would override).
func TenantMayChoose(m Mode, p PlatformPolicy) bool {
	switch p {
	case PolicyOff, PolicyStrict:
		return false
	case PolicyOn:
		return m.rank() >= ModeOn.rank()
	}
	return true
}

// ScopeEntriesNeedApproval reports whether scope entries keep their RFC-054
// approvals under mode m: only Strict. In Off and On a scope entry is a
// target list item; scans are what people approve. An unknown mode keeps
// them (fail closed, as EffectiveApprovalsUnder counts it).
func ScopeEntriesNeedApproval(m Mode) bool { return m != ModeOff && m != ModeOn }

// TierCeilingsEnforced reports whether scope entries' tier ceilings
// (max_tier) limit what probes their targets may get. Only in Strict: in
// Off and On an entry names targets, and the scan approval rules decide
// how hard they may be probed (RFC-073 §6).
func TierCeilingsEnforced(m Mode) bool { return m == ModeStrict }

// CeilingsChange reports whether moving from mode prev to next turns the
// tier ceilings on or off, and whether they are enforced after it.
func CeilingsChange(prev, next Mode) (changed, enforced bool) {
	enforced = TierCeilingsEnforced(next)
	return TierCeilingsEnforced(prev) != enforced, enforced
}

// ErrModeForced refuses an owner's choice the platform policy overrides.
var ErrModeForced = shared.NewDomainError("SCAN_APPROVAL_FORCED",
	"your platform administrator sets scan approval for this organization", shared.ErrForbidden)
