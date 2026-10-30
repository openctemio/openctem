package platformauthz

import (
	"slices"
	"strings"
)

// RoleKey names a platform role.
type RoleKey string

// Built-in platform roles.
const (
	RoleOwner           RoleKey = "platform_owner"
	RoleAdmin           RoleKey = "platform_admin"
	RoleViewer          RoleKey = "platform_viewer"
	RoleOperator        RoleKey = "operator"
	RoleSupport         RoleKey = "support"
	RoleSecurityAuditor RoleKey = "security_auditor"
	RoleBilling         RoleKey = "billing"
)

// Tier is the administrator's base level kept in admin_users.role while the
// console moves to roles: the value of that column, never a role of its own.
// Exactly one base role (owner, admin or viewer) stands for it; the other
// roles are held in addition.
type Tier string

// Tiers, equal to the admin_users.role values.
const (
	TierSuper    Tier = "super_admin"
	TierOps      Tier = "ops_admin"
	TierReadonly Tier = "readonly"
)

// RoleDefinition describes a built-in role.
type RoleDefinition struct {
	Key         RoleKey
	Name        string
	Description string
	// Base roles stand for a tier; an administrator holds exactly one.
	Base bool
	Tier Tier
	// Permissions; nil for the owner, who holds the whole catalog.
	Permissions []Permission
}

var baseline = []Permission{ConsoleRead, TenantsRead, RolesRead, SettingsRead, SensorsRead, AuditRead}

func with(extra ...Permission) []Permission { return append(slices.Clone(baseline), extra...) }

var builtins = []RoleDefinition{
	{RoleOwner, "Platform owner", "Every platform permission. Keep at least two named owners and a break-glass account.", true, TierSuper, nil},
	{RoleAdmin, "Platform admin", "Day-to-day administration of organizations and accounts; no platform settings, administrators or identity.", true, TierOps, with(
		TenantsMembersRead, TenantsCreate, TenantsLifecycle, TenantsOwnerBootstrap, TenantsLimitsWrite,
		UsersRead, UsersSupport, AnnouncementsWrite, SensorsJobsRead, FeedsManage, AIClientsManage, SupportAccess)},
	{RoleViewer, "Read-only", "Reads the console: counts, settings and the audit log, without people's details.", true, TierReadonly, with()},
	{RoleOperator, "Operator", "Runs the shared sensor fleet and the feeds; suspends an organization for abuse.", false, TierReadonly, with(
		SensorsManage, SensorsJobsRead, FeedsManage, TenantsLifecycle)},
	{RoleSupport, "Support", "Helps people sign in and reads inside support grants organizations give.", false, TierReadonly, with(
		TenantsMembersRead, UsersRead, UsersSupport, SupportAccess)},
	{RoleSecurityAuditor, "Security auditor", "Reads the audit log, administrators and approvals for reviews; changes nothing.", false, TierReadonly, with(
		AdminsRead, ApprovalsRead)},
	{RoleBilling, "Billing", "Sets organizations' limits and plans.", false, TierReadonly, with(TenantsLimitsWrite)},
}

// BuiltinRoles returns the built-in roles with their resolved permissions.
func BuiltinRoles() []RoleDefinition {
	out := make([]RoleDefinition, len(builtins))
	for i, r := range builtins {
		r.Permissions = RolePermissions(r.Key).Slice()
		out[i] = r
	}
	return out
}

// Builtin returns the built-in role with key k.
func Builtin(k RoleKey) (RoleDefinition, bool) {
	for _, r := range builtins {
		if r.Key == k {
			return r, true
		}
	}
	return RoleDefinition{}, false
}

// RolePermissions is the permission set of a built-in role (empty for an
// unknown key).
func RolePermissions(k RoleKey) Set {
	r, ok := Builtin(k)
	if !ok {
		return Set{}
	}
	if r.Key == RoleOwner {
		all := make(Set, len(catalog))
		for _, d := range catalog {
			all[d.Key] = struct{}{}
		}
		return all
	}
	return NewSet(r.Permissions...)
}

// Slice returns the set as a sorted permission slice.
func (s Set) Slice() []Permission {
	keys := s.Sorted()
	out := make([]Permission, len(keys))
	for i, k := range keys {
		out[i] = Permission(k)
	}
	return out
}

// BaseRoleFor is the base role standing for a tier (the viewer for anything
// unknown: least privilege).
func BaseRoleFor(t Tier) RoleKey {
	switch t {
	case TierSuper:
		return RoleOwner
	case TierOps:
		return RoleAdmin
	default:
		return RoleViewer
	}
}

// TierOf is the tier a role acts at: the owner super, the admin ops,
// everything else read-only.
func TierOf(k RoleKey) Tier {
	if r, ok := Builtin(k); ok {
		return r.Tier
	}
	return TierReadonly
}

// ElevationTarget maps what an elevation request names to a role: the legacy
// tier names (super_admin, ops_admin) or a role key.
func ElevationTarget(name string) (RoleKey, bool) {
	switch strings.TrimSpace(name) {
	case string(TierSuper):
		return RoleOwner, true
	case string(TierOps):
		return RoleAdmin, true
	}
	k := RoleKey(strings.TrimSpace(name))
	if _, ok := Builtin(k); ok && k != RoleViewer {
		return k, true
	}
	return "", false
}

// Held is the union of the permissions of the roles an administrator holds.
func Held(roles []RoleKey) Set {
	out := Set{}
	for _, k := range roles {
		for p := range RolePermissions(k) {
			out[p] = struct{}{}
		}
	}
	return out
}

// CanElevateTo reports whether a holder of roles may act as target: never
// above what they hold.
func CanElevateTo(roles []RoleKey, target RoleKey) bool {
	if _, ok := Builtin(target); !ok || target == RoleViewer {
		return false
	}
	return RolePermissions(target).SubsetOf(Held(roles))
}

// Acting resolves the permissions a console request acts with.
//
//   - elevation not required: everything the held roles grant;
//   - required, not elevated: only the baseline part of it (the reads);
//   - required and elevated as target: the baseline part plus the target
//     role's permissions, never more than the held roles grant (a role taken
//     away during the elevation stops counting at once).
func Acting(roles []RoleKey, elevationRequired bool, elevated RoleKey) Set {
	held := Held(roles)
	if !elevationRequired {
		return held
	}
	out := Set{}
	for p := range held {
		if Baseline(p) {
			out[p] = struct{}{}
		}
	}
	if elevated != "" {
		for p := range RolePermissions(elevated) {
			if held.Has(p) {
				out[p] = struct{}{}
			}
		}
	}
	return out
}
