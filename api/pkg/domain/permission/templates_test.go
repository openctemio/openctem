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
