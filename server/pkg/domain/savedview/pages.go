package savedview

import (
	"regexp"
	"sort"

	"github.com/openctemio/openctem/server/pkg/domain/permission"
)

// The registry of list pages that have saved views
// (docs/architecture/saved-views.md). It is the one place a page key is
// defined: the service refuses a key that is not here, the database only
// checks the key's shape, and tests/unit/saved_view_pages_coverage_test.go
// fails when a console list route has neither a key nor an entry in
// PagesWithoutViews.
//
// A key is stable: it is stored in every view of the page. Renaming a route
// keeps its key; removing a page keeps its key reserved (views of a key that
// is no longer registered are not found).

// Page is one list page that has saved views.
type Page struct {
	// Key is the page key a view is stored under: the web route without its
	// leading slash and with "/" written as ".", lower-case.
	Key string
	// Route is the web route of the list.
	Route string
	// Permission is the permission needed to read the list. Listing, saving
	// and opening a view of the page needs it.
	Permission permission.Permission
}

// Limits of a view and of the number of views.
const (
	// MaxPageKeyLen bounds a page key (saved_views.page is varchar(64)).
	MaxPageKeyLen = 64
	// MaxPerOwnerPerPage caps one person's views of one page in an
	// organization.
	MaxPerOwnerPerPage = 50
	// MaxStateParams caps the number of page params a view of a page
	// without a filter registry keeps (its filters, sort and search as the
	// page's own URL params).
	MaxStateParams = 32
	// MaxStateParamValueLen caps one such param value, in bytes.
	MaxStateParamValueLen = 1024
	// MaxStateParamsBytes caps the keys and values of such params together,
	// in bytes. It keeps the stored jsonb under the 4096 bytes the table
	// allows for page_params (chk_saved_views_page_params).
	MaxStateParamsBytes = 3072
)

var pageKeyRE = regexp.MustCompile(`^[a-z][a-z0-9-]*(\.[a-z0-9][a-z0-9-]*)*$`)

// ValidPageKey reports whether s has the shape of a page key.
func ValidPageKey(s string) bool {
	return len(s) <= MaxPageKeyLen && pageKeyRE.MatchString(s)
}

func page(route string, perm permission.Permission) Page {
	return Page{Key: KeyOfRoute(route), Route: route, Permission: perm}
}

// KeyOfRoute is the page key a new list at route registers under.
func KeyOfRoute(route string) string {
	b := []byte(route)
	if len(b) > 0 && b[0] == '/' {
		b = b[1:]
	}
	for i, c := range b {
		if c == '/' {
			b[i] = '.'
		}
	}
	return string(b)
}

// pages is the registry. To give a new list saved views, add its line here
// (route and the permission its list endpoint needs); nothing else on the
// server changes.
var pages = []Page{
	// Findings and exposure lists.
	page("/findings", permission.FindingsRead),
	page("/findings/triage", permission.FindingsStatus),
	page("/findings/approvals", permission.FindingsRead),
	page("/findings/imports", permission.FindingsRead),
	page("/findings/ready-to-close", permission.FindingsRead),
	page("/vulnerabilities", permission.VulnerabilitiesRead),
	page("/exposures/vulnerabilities", permission.FindingsRead),
	page("/exposures/secrets", permission.FindingsRead),
	page("/exposures/code", permission.FindingsRead),
	page("/exposures/misconfigurations", permission.FindingsRead),
	page("/credentials", permission.CredentialsRead),
	page("/exceptions", permission.SuppressionsRead),
	page("/emerging-threats", permission.VulnerabilitiesRead),
	page("/threat-intel", permission.VulnerabilitiesRead),
	page("/threat-intel/iocs", permission.ThreatIntelRead),
	page("/threat-intel/detections", permission.ThreatIntelRead),
	page("/priority-rules", permission.PriorityRulesRead),

	// Assets and attack surface.
	page("/assets", permission.AssetsRead),
	page("/assets/attention", permission.AssetsRead),
	page("/assets/changes", permission.AssetsRead),
	page("/assets/duplicates", permission.AssetsRead),
	page("/assets/groups", permission.AssetGroupsRead),
	page("/assets/suggestions", permission.AssetsRead),
	page("/components", permission.ComponentsRead),
	page("/attack-surface/certificates", permission.AssetsRead),
	page("/attack-surface/changes", permission.AssetsRead),
	page("/attack-surface/discovery", permission.ScansRead),
	page("/attack-surface/exposures", permission.ExposuresRead),
	page("/attack-surface/external", permission.AssetsRead),
	page("/attack-surface/lookalikes", permission.ScopeRead),
	page("/attack-surface/pages", permission.AssetsRead),
	page("/attack-surface/review", permission.AssetsRead),
	page("/attack-surface/technologies", permission.AssetsRead),
	page("/attack-surface/web", permission.AssetsRead),

	// Scoping and business context.
	page("/scope", permission.ScopeRead),
	page("/scope/domain-proof", permission.ScopeRead),
	page("/scope/letters", permission.ScopeRead),
	page("/scope/networks", permission.ScopeRead),
	page("/programs", permission.ProgramsRead),
	page("/business-services", permission.BusinessServicesRead),
	page("/business-units", permission.AssetsRead),
	page("/crown-jewels", permission.AssetsRead),
	page("/cycles", permission.CTEMCyclesRead),
	page("/attacker-profiles", permission.AttackerProfilesRead),
	page("/threat-model", permission.AssetsRead),

	// Scans and sensors.
	page("/scans", permission.ScansRead),
	page("/scans/runs", permission.ScansRead),
	page("/scans/approvals", permission.ScansRead),
	page("/scans/workflows", permission.ScanWorkflowsRead),
	page("/sensors", permission.SensorsRead),
	page("/ci-cd", permission.CIRead),

	// Validation.
	page("/pentest/campaigns", permission.PentestCampaignsRead),
	page("/validation/retests", permission.PentestRead),
	page("/attack-simulation", permission.PentestRead),
	page("/control-testing", permission.PentestRead),
	page("/controls", permission.CompensatingControlsRead),
	page("/compliance", permission.ComplianceFrameworksRead),

	// Remediation and automation.
	page("/remediation/tasks", permission.RemediationRead),
	page("/remediation/campaigns", permission.RemediationRead),
	page("/remediation/suggestions", permission.RemediationRead),
	page("/automations", permission.AutomationsRead),

	// Settings lists.
	page("/settings/members", permission.MembersRead),
	page("/settings/roles", permission.RolesRead),
	page("/settings/teams", permission.GroupsRead),
	page("/settings/service-accounts", permission.MembersRead),
	page("/settings/api-keys", permission.APIKeysRead),
	page("/settings/audit-log", permission.AuditRead),
	page("/settings/domains", permission.TeamUpdate),
	page("/settings/sso-approvals", permission.TeamUpdate),
	page("/settings/trusted-organizations", permission.TeamUpdate),
	page("/settings/asset-sources", permission.TeamUpdate),
	page("/settings/sla-policies", permission.SLARead),
	page("/settings/integrations/import-mappings", permission.IntegrationsRead),
	page("/settings/integrations/notifications", permission.IntegrationsRead),
	page("/settings/integrations/notifications/history", permission.IntegrationsManage),
	page("/settings/integrations/notifications/outbox", permission.IntegrationsManage),
	page("/settings/integrations/scanners", permission.IntegrationsRead),
	page("/settings/integrations/scm", permission.IntegrationsRead),
	page("/settings/integrations/siem", permission.IntegrationsRead),
	page("/settings/integrations/ticketing", permission.IntegrationsRead),
	page("/settings/integrations/ticketing/mappings", permission.IntegrationsRead),
	page("/settings/pentest/templates", permission.PentestRead),
	page("/settings/pentest/checklists", permission.PentestRead),
	page("/settings/scanning/capabilities", permission.ToolsRead),
	page("/settings/scanning/credentials", permission.SecretStoreRead),
	page("/settings/scanning/detection-rules", permission.ContentPacksRead),
	page("/settings/scanning/profiles", permission.ScanProfilesRead),
	page("/settings/scanning/proxies", permission.SensorEgressRead),
	page("/settings/scanning/scan-windows", permission.ScansRead),
	page("/settings/scanning/sensor-products", permission.SensorsRead),
	page("/settings/scanning/templates", permission.ScannerTemplatesRead),
	page("/settings/scanning/tool-sources", permission.SecretStoreRead),
	page("/settings/scanning/tools", permission.ToolsRead),
	page("/settings/scanning/wordlists", permission.ContentPacksRead),
}

// Keys of the pages whose views carry a validated filter document and run on
// the server (GET <list>?view=<id>).
const (
	PageFindings        = "findings"
	PageVulnerabilities = "vulnerabilities"
	PageAssets          = "assets"
)

var pageByKey = func() map[string]Page {
	m := make(map[string]Page, len(pages))
	for _, p := range pages {
		m[p.Key] = p
	}
	return m
}()

// LookupPage returns the registered page of a key.
func LookupPage(key string) (Page, bool) {
	p, ok := pageByKey[key]
	return p, ok
}

// Pages returns the registry, by key.
func Pages() []Page {
	out := make([]Page, len(pages))
	copy(out, pages)
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out
}

// ReadPermissions are the distinct permissions the registry names, sorted:
// holding one of them is the least a caller of the saved views API needs.
func ReadPermissions() []permission.Permission {
	seen := make(map[permission.Permission]bool, len(pages))
	out := make([]permission.Permission, 0, len(pages))
	for _, p := range pages {
		if !seen[p.Permission] {
			seen[p.Permission] = true
			out = append(out, p.Permission)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// Reasons a console route has no saved views.
const (
	noViewsDashboard = "dashboard or hub: no list of records to filter"
	noViewsForm      = "settings form: no list of records to filter"
	noViewsGraph     = "graph or map: its state is not a list query"
	noViewsEditor    = "form, wizard or editor"
	noViewsPreset    = "a fixed preset of the Needs attention list (assets.attention holds its views)"
	noViewsEntry     = "entry or account step outside the lists"
	noViewsAccount   = "the member's own account page"
	// noViewsPersonal: every view is gated by the read permission of its
	// page's list, and these pages have none (any member opens them).
	noViewsPersonal = "personal page with no list read permission to gate its views by"
	// noViewsAdmin: a saved view belongs to an organization and to a member
	// of it; an administrator of the installation signs in to no
	// organization, so the admin console lists need a store of their own
	// before they can have views.
	noViewsAdmin = "admin console: an administrator belongs to no organization, and a saved view is stored per organization"
)

// PagesWithoutViews are the console routes that deliberately have no saved
// views, each with its reason. Routes with a dynamic segment ([id]) are
// detail or edit pages and need no entry. A route of the admin console is
// written "console:<route>".
var PagesWithoutViews = map[string]string{
	"/":                           noViewsDashboard,
	"/about/licenses":             noViewsEntry,
	"/activate":                   noViewsEntry,
	"/ci-cd/github-app/callback":  noViewsEntry,
	"/my-work":                    noViewsPersonal,
	"/notifications":              noViewsPersonal,
	"/dashboards":                 noViewsDashboard,
	"/reports":                    noViewsDashboard,
	"/scoping":                    noViewsDashboard,
	"/attack-surface":             noViewsDashboard,
	"/attack-surface/posture":     noViewsDashboard,
	"/exposures":                  noViewsDashboard,
	"/remediation":                noViewsDashboard,
	"/validation":                 noViewsDashboard,
	"/validation/attack-coverage": noViewsDashboard,
	"/sla":                        noViewsDashboard,
	"/business-impact":            noViewsDashboard,
	"/insights/ctem-maturity":     noViewsDashboard,
	"/insights/data-quality":      noViewsDashboard,
	"/insights/executive":         noViewsDashboard,
	"/insights/program-health":    noViewsDashboard,
	"/attack-paths":               noViewsGraph,
	"/exposure-chains":            noViewsGraph,
	"/exploration":                noViewsGraph,
	"/programs/new":               noViewsEditor,
	"/pentest/findings/new":       noViewsEditor,

	"/assets/attention/context":           noViewsPreset,
	"/assets/attention/decide-monitoring": noViewsPreset,
	"/assets/attention/no-owner":          noViewsPreset,
	"/assets/attention/unscanned":         noViewsPreset,
	"/assets/attention/validate-primary":  noViewsPreset,

	"/account":                noViewsAccount,
	"/account/activity":       noViewsAccount,
	"/account/connected-apps": noViewsAccount,
	"/account/notifications":  noViewsAccount,
	"/account/preferences":    noViewsAccount,
	"/account/security":       noViewsAccount,

	"/settings":                                  noViewsDashboard,
	"/settings/ai":                               noViewsForm,
	"/settings/asset-lifecycle":                  noViewsForm,
	"/settings/authentication":                   noViewsForm,
	"/settings/content":                          noViewsForm,
	"/settings/emerging-threats":                 noViewsForm,
	"/settings/finding-approvals":                noViewsForm,
	"/settings/finding-lifecycle":                noViewsForm,
	"/settings/general":                          noViewsForm,
	"/settings/integrations":                     noViewsDashboard,
	"/settings/integrations/import-mappings/new": noViewsEditor,
	"/settings/leaked-credentials":               noViewsForm,
	"/settings/license-policy":                   noViewsForm,
	"/settings/limits":                           noViewsForm,
	"/settings/mcp":                              noViewsForm,
	"/settings/modules":                          noViewsForm,
	"/settings/pentest":                          noViewsDashboard,
	"/settings/pentest/report-templates":         noViewsForm,
	"/settings/pentest/templates/new":            noViewsEditor,
	"/settings/risk-scoring":                     noViewsForm,
	"/settings/scanning/content":                 noViewsForm,
	"/settings/scanning/identification":          noViewsForm,
	"/settings/scanning/scan-approval":           noViewsForm,
	"/settings/scanning/sensor-safety":           noViewsForm,
	"/settings/scanning/tool-defaults":           noViewsForm,
	"/settings/scim":                             noViewsForm,
	"/settings/scope":                            noViewsForm,
	"/settings/security":                         noViewsForm,
	"/settings/support-access":                   noViewsForm,
	"/settings/tenant/create":                    noViewsEditor,
	"/settings/vulnerability-matching":           noViewsForm,

	"console:/":                           noViewsAdmin,
	"console:/about/licenses":             noViewsAdmin,
	"console:/health":                     noViewsAdmin,
	"console:/organizations":              noViewsAdmin,
	"console:/requests":                   noViewsAdmin,
	"console:/requests/sign-ups":          noViewsAdmin,
	"console:/scanning/content-catalog":   noViewsAdmin,
	"console:/scanning/platform":          noViewsAdmin,
	"console:/scanning/target-mappings":   noViewsAdmin,
	"console:/security/activity":          noViewsAdmin,
	"console:/security/administrators":    noViewsAdmin,
	"console:/security/approvals":         noViewsAdmin,
	"console:/security/keys":              noViewsAdmin,
	"console:/security/roles":             noViewsAdmin,
	"console:/security/sessions":          noViewsAdmin,
	"console:/sensors":                    noViewsAdmin,
	"console:/support":                    noViewsAdmin,
	"console:/system/admin-sign-in":       noViewsAdmin,
	"console:/system/ai-applications":     noViewsAdmin,
	"console:/system/ai-provider":         noViewsAdmin,
	"console:/system/alerts":              noViewsAdmin,
	"console:/system/announcements":       noViewsAdmin,
	"console:/system/captcha":             noViewsAdmin,
	"console:/system/configuration":       noViewsAdmin,
	"console:/system/content-packs":       noViewsAdmin,
	"console:/system/email":               noViewsAdmin,
	"console:/system/leaked-credentials":  noViewsAdmin,
	"console:/system/legal":               noViewsAdmin,
	"console:/system/limits":              noViewsAdmin,
	"console:/system/private-networks":    noViewsAdmin,
	"console:/system/scan-approval":       noViewsAdmin,
	"console:/system/scan-identification": noViewsAdmin,
	"console:/system/sign-up":             noViewsAdmin,
	"console:/system/social-login":        noViewsAdmin,
	"console:/system/software-updates":    noViewsAdmin,
	"console:/system/threat-intel":        noViewsAdmin,
	"console:/system/two-factor":          noViewsAdmin,
	"console:/users":                      noViewsAdmin,
}
