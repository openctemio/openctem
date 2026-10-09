package permission

import "github.com/openctemio/openctem/api/pkg/domain/tenant"

// SystemRole is a built-in role as the database seeds it (roles.is_system,
// tenant_id NULL) with the permissions it carries.
//
// SystemRoles is the single list the documentation generator, the role
// templates and the tests read. The database seed is checked against it
// (TestSystemRolePermissions_MatchSeed in internal/infra/postgres), so a
// migration that changes a system role's grants must change this list too.
type SystemRole struct {
	ID                string
	Slug              string
	Name              string
	Description       string
	HasFullDataAccess bool
	// AdminBypass: the role passes every permission check (owner and admin).
	// Its permission list is informative only.
	AdminBypass bool
	Permissions []Permission
}

// systemRoles lists every built-in role, in display order. A new built-in
// role is appended here and seeded by a migration in the same change.
var systemRoles = []SystemRole{
	{
		ID: "00000000-0000-0000-0000-000000000001", Slug: "owner", Name: "Owner",
		Description:       "Full access to everything, including deleting the organization and changing administrators.",
		HasFullDataAccess: true, AdminBypass: true,
		Permissions: RolePermissions[tenant.RoleOwner],
	},
	{
		ID: "00000000-0000-0000-0000-000000000002", Slug: "admin", Name: "Administrator",
		Description:       "Administrative access to every feature except deleting the organization; only the owner manages other administrators.",
		HasFullDataAccess: true, AdminBypass: true,
		Permissions: RolePermissions[tenant.RoleAdmin],
	},
	{
		ID: "00000000-0000-0000-0000-000000000003", Slug: "member", Name: "Member",
		Description: "Works with assets, findings, scans and remediation inside their data scope; no deletes, no administration.",
		Permissions: RolePermissions[tenant.RoleMember],
	},
	{
		ID: "00000000-0000-0000-0000-000000000004", Slug: "viewer", Name: "Viewer",
		Description: "Read-only access inside their data scope. Every new member starts here.",
		Permissions: RolePermissions[tenant.RoleViewer],
	},
	{
		// RFC-065: tests the programs the organization follows. Sees only the
		// assets of the programs whose group has them; never changes the
		// organization's own scope or approves anything.
		ID: "00000000-0000-0000-0000-000000000005", Slug: "researcher", Name: "Researcher",
		Description: "Tests programs the organization follows: programs, scans and findings of the programs they belong to; cannot change the organization's own scope or approve anything",
		Permissions: ResearcherPermissions,
	},
}

// ResearcherPermissions are the grants of the built-in Researcher role
// (migration bounty_programs, RFC-065 §7).
var ResearcherPermissions = []Permission{
	DashboardRead, AssetsRead,
	// No FindingsSeverity: researchers report and discuss, triage owns severity.
	FindingsRead, FindingsWrite, FindingsComment, FindingsStatus, FindingsTriage, FindingsExport,
	ScansRead, ScansWrite, ScansExecute,
	ScanProfilesRead, ScannerTemplatesRead, ScanWorkflowsRead,
	SensorsRead,
	ProgramsRead, ProgramsWrite,
}

// SystemRoles returns the built-in roles (a fresh copy).
func SystemRoles() []SystemRole {
	out := make([]SystemRole, len(systemRoles))
	for i, r := range systemRoles {
		r.Permissions = append([]Permission(nil), r.Permissions...)
		out[i] = r
	}
	return out
}
