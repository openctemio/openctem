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
		// Scope: whoever widens scope does not approve it, nor the
		// exclusions they request.
		if hasPerm(tpl, permission.ScopeWrite) && (hasPerm(tpl, permission.ScopeApprove) || hasPerm(tpl, permission.ScopeExclusionsApprove)) {
			t.Errorf("%s: writes and approves scope", tpl.ID)
		}
		// Scan approvals: whoever creates or changes a scan does not approve
		// its run.
		if hasPerm(tpl, permission.ScansApprove) && hasPerm(tpl, permission.ScansWrite) {
			t.Errorf("%s: writes scans and approves their runs", tpl.ID)
		}
		// Whoever re-scores a finding does not mark it fixed.
		if hasPerm(tpl, permission.FindingsFixApply) && hasPerm(tpl, permission.FindingsSeverity) {
			t.Errorf("%s: fix_apply and severity together", tpl.ID)
		}
	}
}

// A run needs scans:write and scans:execute together (and execute is added on
// top of write): a template with execute alone holds a permission that opens
// nothing.
func TestRoleTemplates_NoExecuteWithoutWrite(t *testing.T) {
	for _, tpl := range permission.RoleTemplates() {
		if hasPerm(tpl, permission.ScansExecute) && !hasPerm(tpl, permission.ScansWrite) && !hasPerm(tpl, permission.AssetsWrite) {
			t.Errorf("%s: scans:execute without scans:write or assets:write opens no route", tpl.ID)
		}
	}
}

// The remediation lead plans the team's fixes; like the remediation owner it
// never re-scores, verifies, approves or triages what its team fixes.
func TestRoleTemplates_RemediationLeadIsBounded(t *testing.T) {
	rl, ok := permission.RoleTemplateByID("remediation-lead")
	if !ok {
		t.Fatal("no remediation-lead template")
	}
	for _, p := range []permission.Permission{
		permission.FindingsSeverity, permission.FindingsVerify, permission.FindingsApprove, permission.FindingsTriage,
		permission.SuppressionsWrite, permission.ScansWrite, permission.ScansExecute, permission.FindingsExport,
	} {
		if hasPerm(rl, p) {
			t.Errorf("remediation-lead holds %s", p)
		}
	}
	ro, _ := permission.RoleTemplateByID("remediation-owner")
	for _, p := range ro.Permissions {
		if !hasPerm(rl, p) {
			t.Errorf("remediation-lead lacks %s, which the remediation owner holds", p)
		}
	}
	for _, p := range []permission.Permission{permission.RemediationWrite, permission.FindingsAssign} {
		if !hasPerm(rl, p) {
			t.Errorf("remediation-lead lacks %s", p)
		}
	}
}

// The validation lead is a validation engineer who also curates methodology
// and requests engagement scope; the detection engineer reads validation
// results and records controls but never runs attacks or scans.
func TestRoleTemplates_ValidationLeadAndDetectionEngineer(t *testing.T) {
	ve, _ := permission.RoleTemplateByID("validation-engineer")
	vl, ok := permission.RoleTemplateByID("validation-lead")
	if !ok {
		t.Fatal("no validation-lead template")
	}
	for _, p := range ve.Permissions {
		if !hasPerm(vl, p) {
			t.Errorf("validation-lead lacks %s, which the validation engineer holds", p)
		}
	}
	for _, p := range []permission.Permission{permission.PentestChecklistsManage, permission.AttackerProfilesWrite, permission.ScopeWrite} {
		if !hasPerm(vl, p) {
			t.Errorf("validation-lead lacks %s", p)
		}
	}
	de, ok := permission.RoleTemplateByID("detection-engineer")
	if !ok {
		t.Fatal("no detection-engineer template")
	}
	for _, p := range []permission.Permission{
		permission.PentestWrite, permission.PentestFindingsWrite, permission.PentestCampaignsWrite,
		permission.ScansWrite, permission.ScansExecute, permission.FindingsWrite, permission.FindingsStatus,
	} {
		if hasPerm(de, p) {
			t.Errorf("detection-engineer holds %s", p)
		}
	}
	if !hasPerm(de, permission.CompensatingControlsWrite) || !hasPerm(de, permission.PentestRead) {
		t.Error("detection-engineer cannot read validation results or record controls")
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
		permission.ScannerTemplatesWrite, permission.ContentSourcesWrite, permission.ContentPacksWrite,
		permission.ContentInstall, permission.ContentPublish,
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
	"program-lead":          {3, "0325b974228208b8"},
	"security-analyst":      {4, "21f193fd530f795b"},
	"vulnerability-manager": {4, "9a6df8c9d7573175"},
	"remediation-owner":     {2, "d8be6e04c6911814"},
	"remediation-lead":      {1, "75ae33b525c394cb"},
	"appsec-engineer":       {3, "77b455a340ace578"},
	"ci-integrator":         {2, "e12bf49f4beef986"},
	"scan-operator":         {2, "e662a3285d8959e5"},
	"sensor-operator":       {1, "dad7da0b5236b92c"},
	"validation-engineer":   {3, "0fc8039a4875f41c"},
	"validation-lead":       {1, "5c0c66116fc17ad6"},
	"detection-engineer":    {1, "caa70fbad545b9ce"},
	"external-tester":       {1, "8861f6f0f788e217"},
	"researcher":            {2, "3db22d24b0d4ef59"},
	"bounty-triager":        {1, "3701f9612e54d123"},
	"threat-intel-analyst":  {1, "8dc68d55c347021f"},
	"risk-approver":         {2, "dad878aa7a082145"},
	"auditor":               {2, "abeb3aaa8907df58"},
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

// The Researcher persona sees programs, not the organization's sensor fleet.
func TestResearcherTemplate_NoSensorAccess(t *testing.T) {
	r, ok := permission.RoleTemplateByID("researcher")
	if !ok {
		t.Fatal("no researcher template")
	}
	for _, p := range r.Permissions {
		if strings.HasPrefix(string(p), "sensors:") {
			t.Errorf("researcher holds %s", p)
		}
	}
}
