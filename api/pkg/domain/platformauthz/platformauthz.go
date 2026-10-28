// Package platformauthz is the console's authorization model (RFC-134): the
// platform permission catalog, the built-in platform roles and how a console
// session's acting permissions are resolved.
//
// It is separate from the tenant permission catalog (pkg/domain/permission)
// by design: every key here starts with "platform.", no tenant key does, the
// two are stored in different tables with no foreign key between them, and no
// tenant route, token or response ever reads this package.
package platformauthz

import (
	"slices"
	"sort"
	"strings"
)

// Prefix starts every platform permission key, and no tenant permission key.
const Prefix = "platform."

// Permission is one platform permission key.
type Permission string

// The catalog. Baseline permissions (the reads) are usable by a console
// session that has not elevated; the others need an elevated session acting as
// a role that holds them (when elevation is required, the default).
const (
	ConsoleRead Permission = "platform.console.read"

	TenantsRead            Permission = "platform.tenants.read"
	TenantsMembersRead     Permission = "platform.tenants.members.read"
	TenantsCreate          Permission = "platform.tenants.create"
	TenantsLifecycle       Permission = "platform.tenants.lifecycle"
	TenantsPurge           Permission = "platform.tenants.purge"
	TenantsOwnerBootstrap  Permission = "platform.tenants.owner_bootstrap"
	TenantsOwnerRecovery   Permission = "platform.tenants.owner_recovery"
	TenantsSSOWrite        Permission = "platform.tenants.sso.write"
	TenantsLimitsWrite     Permission = "platform.tenants.limits.write"
	TenantsScanPolicyWrite Permission = "platform.tenants.scan_policy.write"
	TenantsAuditChainWrite Permission = "platform.tenants.audit_chain.write"

	UsersRead    Permission = "platform.users.read"
	UsersSupport Permission = "platform.users.support"

	AdminsRead   Permission = "platform.admins.read"
	AdminsManage Permission = "platform.admins.manage"

	RolesRead   Permission = "platform.roles.read"
	RolesAssign Permission = "platform.roles.assign"

	ApprovalsRead   Permission = "platform.approvals.read"
	ApprovalsDecide Permission = "platform.approvals.decide"

	IdentityManage Permission = "platform.identity.manage"

	SettingsRead         Permission = "platform.settings.read"
	SettingsSignupWrite  Permission = "platform.settings.signup.write"
	SettingsEmailWrite   Permission = "platform.settings.email.write"
	SettingsLegalWrite   Permission = "platform.settings.legal.write"
	SettingsLimitsWrite  Permission = "platform.settings.limits.write"
	SettingsGeneralWrite Permission = "platform.settings.general.write"
	SettingsAIWrite      Permission = "platform.settings.ai.write"

	AnnouncementsWrite Permission = "platform.announcements.write"

	SensorsRead     Permission = "platform.sensors.read"
	SensorsJobsRead Permission = "platform.sensors.jobs.read"
	SensorsManage   Permission = "platform.sensors.manage"

	FeedsManage     Permission = "platform.feeds.manage"
	ContentManage   Permission = "platform.content.manage"
	AIClientsManage Permission = "platform.ai_clients.manage"

	AuditRead Permission = "platform.audit.read"

	SupportAccess Permission = "platform.support.access"
)

// Definition describes one catalog entry.
type Definition struct {
	Key Permission
	// Baseline: usable without elevation (the reads every console role had).
	Baseline    bool
	Description string
}

var catalog = []Definition{
	{ConsoleRead, true, "Overview, operations, system health, version, configuration and the console API reference"},
	{TenantsRead, true, "Organizations: list, details, limits, modules, single sign-on, audit chain state, access requests and the sign-up feed"},
	{TenantsMembersRead, false, "An organization's member list with names and e-mail addresses (otherwise counts only)"},
	{TenantsCreate, false, "Create an organization; approve or reject an access request"},
	{TenantsLifecycle, false, "Suspend or reactivate an organization; rebuild its dashboard figures"},
	{TenantsPurge, false, "Delete an organization at once (also needs a second owner's approval)"},
	{TenantsOwnerBootstrap, false, "Create the first owner of an organization that has none"},
	{TenantsOwnerRecovery, false, "Create an owner for an organization whose owners are all suspended"},
	{TenantsSSOWrite, false, "Change an organization's SAML, identity providers, verified domains and SSO enforcement"},
	{TenantsLimitsWrite, false, "Change an organization's limits, module denies and idle policy"},
	{TenantsScanPolicyWrite, false, "Change an organization's scan-approval policy and shared sensors"},
	{TenantsAuditChainWrite, false, "Re-sign an organization's audit chain (also needs a second owner's approval)"},
	{UsersRead, false, "Find any account and view its sign-in state, organizations and sessions"},
	{UsersSupport, false, "Account support: end sessions, unlock, send password-reset or verification mail, block or unblock"},
	{AdminsRead, false, "List platform administrators and console sessions"},
	{AdminsManage, false, "Add, change, remove or reset platform administrators; end their console sessions"},
	{RolesRead, true, "List platform roles and who holds them"},
	{RolesAssign, false, "Give or take a platform role (never above your own; owner grants need a second owner)"},
	{ApprovalsRead, false, "List four-eyes approval requests"},
	{ApprovalsDecide, false, "Request, approve, reject or withdraw a four-eyes approval"},
	{IdentityManage, false, "The administrators' identity provider and the console security-key policy"},
	{SettingsRead, true, "Read every platform setting, announcements, content packs, catalog, target mappings, feeds and AI clients"},
	{SettingsSignupWrite, false, "Sign-up policy and sign-up alert thresholds"},
	{SettingsEmailWrite, false, "Platform e-mail relay and its test message"},
	{SettingsLegalWrite, false, "Legal pages"},
	{SettingsLimitsWrite, false, "Default limits of self-service organizations"},
	{SettingsGeneralWrite, false, "CAPTCHA, region, alerts, storage quota and the version check"},
	{SettingsAIWrite, false, "Platform AI and the organizations' AI policy"},
	{AnnouncementsWrite, false, "Publish or end an announcement"},
	{SensorsRead, true, "Shared sensors, scan zones, the job queue and the scanning settings"},
	{SensorsJobsRead, false, "Open one shared-sensor job's details"},
	{SensorsManage, false, "Pause, resume or retire shared sensors, enrollment tokens, instance scan zones and the shared-sensor settings"},
	{FeedsManage, false, "Run or switch threat-intelligence feeds"},
	{ContentManage, false, "Content packs, the content catalog and scanner target mappings"},
	{AIClientsManage, false, "Block or unblock an AI client"},
	{AuditRead, true, "The administrators' audit log and its chain state"},
	{SupportAccess, false, "Open support sessions inside a grant an organization gave you, and read through them"},
}

// Catalog returns every platform permission, sorted by key.
func Catalog() []Definition {
	out := slices.Clone(catalog)
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out
}

var known = func() map[Permission]Definition {
	m := make(map[Permission]Definition, len(catalog))
	for _, d := range catalog {
		m[d.Key] = d
	}
	return m
}()

// Known reports whether p is in the catalog.
func Known(p Permission) bool { _, ok := known[p]; return ok }

// IsPlatformKey reports whether a permission key belongs to the platform
// namespace. A tenant role never holds such a key, and a platform role holds
// nothing else.
func IsPlatformKey(key string) bool { return strings.HasPrefix(key, Prefix) }

// Baseline reports whether p is usable without elevation.
func Baseline(p Permission) bool { return known[p].Baseline }

// Set is a set of platform permissions.
type Set map[Permission]struct{}

// NewSet builds a set of known permissions; unknown keys are dropped.
func NewSet(ps ...Permission) Set {
	s := make(Set, len(ps))
	for _, p := range ps {
		if Known(p) {
			s[p] = struct{}{}
		}
	}
	return s
}

// Has reports whether p is in the set. A nil set holds nothing.
func (s Set) Has(p Permission) bool { _, ok := s[p]; return ok }

// SubsetOf reports whether every permission of s is in o.
func (s Set) SubsetOf(o Set) bool {
	for p := range s {
		if !o.Has(p) {
			return false
		}
	}
	return true
}

// Sorted returns the keys in order (for responses and audit rows).
func (s Set) Sorted() []string {
	out := make([]string, 0, len(s))
	for p := range s {
		out = append(out, string(p))
	}
	sort.Strings(out)
	return out
}
