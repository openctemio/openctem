package permission_test

import (
	"regexp"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/permission"
	"github.com/openctemio/openctem/api/pkg/domain/role"
)

func hasPerm(t permission.RoleTemplate, p permission.Permission) bool {
	return permission.Contains(t.Permissions, p)
}

var templateIDPattern = regexp.MustCompile(`^[a-z][a-z0-9-]{1,48}[a-z0-9]$`)

// Every template is something the role editor can create: a valid, unique,
// non-reserved id usable as a slug, permissions from the catalog, and none of
// the admin-only permissions a custom role may never carry.
func TestRoleTemplates_AreCreatableCustomRoles(t *testing.T) {
	all := permission.AllPermissions()
	seen := map[string]bool{}
	templates := permission.RoleTemplates()
	if len(templates) < 8 {
		t.Fatalf("only %d templates", len(templates))
	}
	for _, tpl := range templates {
		if !templateIDPattern.MatchString(tpl.ID) || role.IsReservedSlug(tpl.ID) {
			t.Errorf("template id %q is not a usable custom-role slug", tpl.ID)
		}
		if seen[tpl.ID] {
			t.Errorf("duplicate template %q", tpl.ID)
		}
		seen[tpl.ID] = true
		if tpl.Name == "" || tpl.Description == "" || len(tpl.Personas) == 0 {
			t.Errorf("template %q needs a name, a description and personas", tpl.ID)
		}
		dup := map[permission.Permission]bool{}
		for _, p := range tpl.Permissions {
			if dup[p] {
				t.Errorf("template %q lists %s twice", tpl.ID, p)
			}
			dup[p] = true
			if !permission.Contains(all, p) {
				t.Errorf("template %q carries %s, which is not in the catalog", tpl.ID, p)
			}
			if permission.IsAdminOnly(string(p)) {
				t.Errorf("template %q carries admin-only %s", tpl.ID, p)
			}
		}
	}
}

// Separation of duties: whoever can ask for something cannot also approve it.
func TestRoleTemplates_SeparationOfDuties(t *testing.T) {
	for _, tpl := range permission.RoleTemplates() {
		// The person who applies a fix never verifies it.
		if hasPerm(tpl, permission.FindingsFixApply) && hasPerm(tpl, permission.FindingsVerify) {
			t.Errorf("%s: fix_apply and verify together", tpl.ID)
		}
		// Risk acceptance and false positives: requester (status) is not approver.
		if hasPerm(tpl, permission.FindingsApprove) {
			for _, p := range []permission.Permission{permission.FindingsStatus, permission.FindingsFixApply, permission.FindingsTriage, permission.FindingsBulkUpdate} {
				if hasPerm(tpl, p) {
					t.Errorf("%s: findings:approve together with %s", tpl.ID, p)
				}
			}
		}
		// Suppression rules: author is not approver.
		if hasPerm(tpl, permission.SuppressionsApprove) && hasPerm(tpl, permission.SuppressionsWrite) {
			t.Errorf("%s: writes and approves suppression rules", tpl.ID)
		}
		// Scope: whoever widens scope does not approve it.
		if hasPerm(tpl, permission.ScopeApprove) && hasPerm(tpl, permission.ScopeWrite) {
			t.Errorf("%s: writes and approves scope", tpl.ID)
		}
	}
}

// Templates describe program work. Administering the organization (members,
// roles, teams, settings, keys, integrations, sensors, trusted scanner code)
// stays with the owner and administrators.
func TestRoleTemplates_NoAdministration(t *testing.T) {
	admin := []permission.Permission{
		permission.TeamUpdate, permission.TeamDelete, permission.SettingsWrite,
		permission.MembersInvite, permission.MembersWrite,
		permission.RolesWrite, permission.RolesDelete, permission.RolesAssign,
		permission.GroupsWrite, permission.GroupsDelete, permission.GroupsMembers, permission.GroupsAssets,
		permission.APIKeysWrite, permission.APIKeysDelete, permission.IntegrationsManage,
		permission.SCMConnectionsWrite, permission.SCMConnectionsDelete,
		permission.NotificationsWrite, permission.NotificationsDelete,
		permission.SecretStoreWrite, permission.SecretStoreDelete,
		permission.ScannerTemplatesWrite, permission.TemplateSourcesWrite, permission.ContentPacksWrite,
		permission.ContentInstall,
		permission.ToolsWrite, permission.TenantToolsWrite, permission.ScanWindowsManage, permission.ScanWindowsOverride,
		permission.CredentialsReveal, permission.EvidenceReveal,
	}
	for _, tpl := range permission.RoleTemplates() {
		for _, p := range admin {
			if hasPerm(tpl, p) {
				t.Errorf("%s carries administrative %s", tpl.ID, p)
			}
		}
		for _, p := range tpl.Permissions {
			if strings.HasSuffix(string(p), ":delete") {
				t.Errorf("%s carries delete permission %s", tpl.ID, p)
			}
		}
	}
}

// Full data access bypasses team scope, so only the templates whose job is to
// see everything carry it.
func TestRoleTemplates_FullDataOnlyWhereNeeded(t *testing.T) {
	want := map[string]bool{"program-lead": true, "auditor": true}
	for _, tpl := range permission.RoleTemplates() {
		if tpl.HasFullDataAccess != want[tpl.ID] {
			t.Errorf("%s: has_full_data_access %v, want %v", tpl.ID, tpl.HasFullDataAccess, want[tpl.ID])
		}
	}
}

// Read-only templates change nothing.
func TestRoleTemplates_ReadOnlyTemplates(t *testing.T) {
	readOnly := map[string]map[permission.Permission]bool{
		"auditor":   {permission.FindingsExport: true, permission.AuditRead: true},
		"executive": {},
	}
	for _, tpl := range permission.RoleTemplates() {
		allowed, ok := readOnly[tpl.ID]
		if !ok {
			continue
		}
		for _, p := range tpl.Permissions {
			if !strings.HasSuffix(string(p), ":read") && !allowed[p] {
				t.Errorf("read-only template %s carries %s", tpl.ID, p)
			}
		}
	}
}

// The executive viewer holds less than the built-in viewer, and the external
// tester sees nothing outside its campaigns: no organization-wide findings,
// exposures, members or configuration.
func TestRoleTemplates_NarrowTemplates(t *testing.T) {
	viewer := systemRoleBySlug(t, "viewer")
	exec, _ := permission.RoleTemplateByID("executive")
	for _, p := range exec.Permissions {
		if !permission.Contains(viewer.Permissions, p) {
			t.Errorf("executive holds %s, which the viewer does not", p)
		}
	}
	ext, ok := permission.RoleTemplateByID("external-tester")
	if !ok {
		t.Fatal("no external-tester template")
	}
	for _, p := range []permission.Permission{
		permission.FindingsRead, permission.ExposuresRead, permission.CredentialsRead, permission.MembersRead,
		permission.SettingsRead, permission.ScansRead, permission.ScansExecute, permission.AuditRead,
		permission.PentestCampaignsWrite, permission.FindingsWrite,
	} {
		if permission.Contains(ext.Permissions, p) {
			t.Errorf("external-tester holds %s", p)
		}
	}
}

// The remediation owner works only on fixes: no triage, assignment, bulk
// changes, verification, approval, export or scanning.
func TestRoleTemplates_RemediationOwnerIsNarrow(t *testing.T) {
	ro, ok := permission.RoleTemplateByID("remediation-owner")
	if !ok {
		t.Fatal("no remediation-owner template")
	}
	for _, p := range []permission.Permission{
		permission.FindingsTriage, permission.FindingsAssign, permission.FindingsBulkUpdate,
		permission.FindingsVerify, permission.FindingsApprove, permission.FindingsExport,
		permission.ScansWrite, permission.ScansExecute, permission.RemediationWrite,
		// Whoever fixes a finding does not re-score it.
		permission.FindingsSeverity,
	} {
		if permission.Contains(ro.Permissions, p) {
			t.Errorf("remediation-owner holds %s", p)
		}
	}
	for _, p := range []permission.Permission{permission.FindingsFixApply, permission.FindingsStatus, permission.FindingsWrite, permission.FindingsComment} {
		if !permission.Contains(ro.Permissions, p) {
			t.Errorf("remediation-owner lacks %s", p)
		}
	}
}

// RoleTemplates hands out copies.
func TestRoleTemplates_ReturnsCopies(t *testing.T) {
	a := permission.RoleTemplates()
	a[0].Permissions[0] = "tampered"
	a[0].Personas[0] = "tampered"
	b := permission.RoleTemplates()
	if b[0].Permissions[0] == "tampered" || b[0].Personas[0] == "tampered" {
		t.Error("RoleTemplates shares its backing arrays")
	}
}

// The AppSec engineer runs the CI gate: policies and break-glass. Both stay
// out of every other template: letting a commit past the gate is the AppSec
// engineer's call (with step-up), not a by-product of another job. CI trust
// (scans:ci:write) is admin-only and in no template.
func TestRoleTemplates_CIGateOwnedByAppSec(t *testing.T) {
	for _, tpl := range permission.RoleTemplates() {
		isAppSec := tpl.ID == "appsec-engineer"
		if hasPerm(tpl, permission.CIWrite) {
			t.Errorf("%s carries admin-only %s", tpl.ID, permission.CIWrite)
		}
		for _, p := range []permission.Permission{permission.CIPolicy, permission.CIOverride} {
			if hasPerm(tpl, p) != isAppSec {
				t.Errorf("%s: %s = %v", tpl.ID, p, hasPerm(tpl, p))
			}
		}
	}
}

// Researchers report and discuss findings; triage owns severity.
func TestRoleTemplates_ResearcherCommentsButDoesNotRescore(t *testing.T) {
	r, ok := permission.RoleTemplateByID("researcher")
	if !ok {
		t.Fatal("no researcher template")
	}
	if !hasPerm(r, permission.FindingsComment) {
		t.Error("researcher cannot comment on findings")
	}
	if hasPerm(r, permission.FindingsSeverity) || hasPerm(r, permission.FindingsApprove) {
		t.Error("researcher can re-score or approve")
	}
}

// templateVersions pins each template's version to its grants. Changing a
// template's permissions or full data access changes its digest: bump
// Version and record the new digest here. Roles created from the template
// keep what they took and show "update available".
var templateVersions = map[string]struct {
	version int
	digest  string
}{
	"program-lead":          {1, "04049ff1fdc99496"},
	"security-analyst":      {1, "8d919973833731a8"},
	"vulnerability-manager": {1, "20cadb3f924a1193"},
	"remediation-owner":     {1, "e7a6827cedd735f8"},
	"appsec-engineer":       {1, "c3b74d6a1883f9ea"},
	"ci-integrator":         {1, "bbc336f2d9c23728"},
	"scan-operator":         {1, "1e92419c24534f7d"},
	"sensor-operator":       {1, "dad7da0b5236b92c"},
	"validation-engineer":   {1, "9c76467fedf3eac0"},
	"external-tester":       {1, "8861f6f0f788e217"},
	"researcher":            {1, "efe5d28a21f69cdc"},
	"bounty-triager":        {1, "3701f9612e54d123"},
	"threat-intel-analyst":  {1, "8dc68d55c347021f"},
	"risk-approver":         {1, "41e9f0ffdc676549"},
	"auditor":               {1, "b6f9f10b55df98eb"},
	"executive":             {1, "e76d59c68e5ca7ad"},
}

func TestRoleTemplates_VersionPinned(t *testing.T) {
	for _, tpl := range permission.RoleTemplates() {
		got := permission.TemplateDigest(tpl)
		want, ok := templateVersions[tpl.ID]
		if !ok {
			t.Errorf("%s: pin it: {version: %d, digest: %q}", tpl.ID, tpl.Version, got)
			continue
		}
		if tpl.Version != want.version || got != want.digest {
			t.Errorf("%s: version %d digest %s, pinned version %d digest %s: a change to the grants needs a new version",
				tpl.ID, tpl.Version, got, want.version, want.digest)
		}
		if tpl.Version < 1 {
			t.Errorf("%s: version must start at 1", tpl.ID)
		}
	}
}
