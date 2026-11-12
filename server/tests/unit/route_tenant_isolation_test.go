package unit

import (
	"bufio"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// The tenant-isolation registry: every route with a path id says how it keeps
// one organization's id from reaching another organization's row. The route
// coverage gate (route_authz_coverage_test.go) asks who may call a route; the
// data-scope registry (route_scope_classification_test.go) asks which of the
// caller's own assets it may reach; this one asks the cross-organization
// question: an id of organization A, sent with a token of organization B,
// answers as an unknown id (404, or "not found" per item) and changes nothing.
//
// Two levels, so that a new route cannot ship without deciding:
//
//  1. tenantIsolationRegistry names, per path prefix, the mechanism (kind):
//
//     - tested: cross-organization negative tests exist and are named. They
//     run the real router, services and a migrated database with a token of
//     B and the ids of A (server/internal/server/xorg_*_db_test.go), compare
//     B's answer with the answer for an unknown id and prove A's rows did not
//     change. The listed tests must exist.
//     - sql: declared. The tenant comes from the authenticated context and
//     every by-id statement of the store behind the route carries a tenant
//     predicate (tools/lint/tenantsql, decision D-11). Not yet exercised by a
//     cross-organization test; the log lists these prefixes as the burn-down.
//     - none: not organization data (platform realm, sensor protocol, global
//     catalog, the caller's own account, a token that carries the tenant).
//     The note says which.
//
//  2. tenantIsolationBaseline (testdata/tenant_isolation_baseline.txt) is the
//     list of id routes that existed when this guard was added; they inherit
//     their prefix's declaration. The list only shrinks (a removed route must
//     leave it). A route that is NOT in it needs its own entry in
//     tenantIsolationRoutes with a cross-organization test (test: TestName,
//     which must exist) or a stated scope (scope: why an id alone is safe).
//
// isolationFile is named in every failure so whoever added a route knows what
// to edit.
const isolationFile = "server/tests/unit/route_tenant_isolation_test.go"

type isolationKind string

const (
	isoTested isolationKind = "tested"
	isoSQL    isolationKind = "sql"
	isoNone   isolationKind = "none"
)

type isolationDecl struct {
	kind  isolationKind
	tests []string // isoTested: the cross-organization tests that exist
	note  string   // how the tenant is enforced, or why the route is not tenant data
}

const sqlHow = "tenant from the token chain; by-id statements of the store carry a tenant predicate (tenantsql, D-11)"

var tenantIsolationRegistry = map[string]isolationDecl{ //nolint:gochecknoglobals // registry
	// --- tested: the real router, a token of B, the ids of A ------------------------
	"/api/v1/findings": {isoTested, []string{"TestCrossOrg_Matrix_Detail", "TestCrossOrg_Matrix_Bulk", "TestCrossOrg_Matrix_FindingBulkByFilter",
		"TestCrossOrg_Matrix_Untraced", "TestCrossOrg_WebSocket_BoundToItsOrganization"}, "detail, status, assign, severity, delete, bulk by id and by filter, evidence items, live channels"},
	"/api/v1/assets": {isoTested, []string{"TestCrossOrg_Matrix_Detail", "TestCrossOrg_Matrix_Bulk", "TestCrossOrg_Matrix_Untraced"},
		"detail, update, archive, delete, bulk status and sync, scan-window evaluation of asset ids"},
	"/api/v1/scans":                 {isoTested, []string{"TestCrossOrg_Matrix_Bulk", "TestCrossOrg_Matrix_Detail", "TestCrossOrg_Matrix_RunsApprovalsWebhooks"}, "detail, bulk lifecycle, runs of a scan"},
	"/api/v1/scan-runs":             {isoTested, []string{"TestCrossOrg_Matrix_RunsApprovalsWebhooks"}, "run detail, tasks, stages, events, map, outputs, cancel"},
	"/api/v1/asset-groups":          {isoTested, []string{"TestCrossOrg_Matrix_Bulk", "TestCrossOrg_Matrix_Detail"}, "detail, bulk update and delete"},
	"/api/v1/scope":                 {isoTested, []string{"TestCrossOrg_Matrix_Bulk"}, "bulk delete of targets and exclusions"},
	"/api/v1/remediation":           {isoTested, []string{"TestCrossOrg_Matrix_Detail", "TestCrossOrg_Matrix_Bulk", "TestCrossOrg_Matrix_RunsApprovalsWebhooks"}, "tasks, suggestions (approve, bulk approve), exception preview"},
	"/api/v1/views":                 {isoTested, []string{"TestCrossOrg_Matrix_Detail"}, "saved views"},
	"/api/v1/me":                    {isoTested, []string{"TestCrossOrg_Matrix_Detail"}, "personal dashboards"},
	"/api/v1/api-keys":              {isoTested, []string{"TestCrossOrg_Matrix_Detail"}, "get, revoke, delete"},
	"/api/v1/integrations":          {isoTested, []string{"TestCrossOrg_Matrix_RunsApprovalsWebhooks", "TestCrossOrg_Matrix_Untraced"}, "detail, webhook secrets, signing secret, connector scan now"},
	"/api/v1/exploration":           {isoTested, []string{"TestCrossOrg_Matrix_Untraced"}, "leads: get, approve, dismiss"},
	"/api/v1/scan-window-policies":  {isoTested, []string{"TestCrossOrg_Matrix_Untraced"}, "policies, selector references"},
	"/api/v1/scan-window-overrides": {isoTested, []string{"TestCrossOrg_Matrix_Untraced"}, "revoke, create on a policy"},
	"/api/v1/approvals":             {isoTested, []string{"TestCrossOrg_Matrix_RunsApprovalsWebhooks"}, "finding approvals and group exceptions"},
	"/api/v1/roles":                 {isoTested, []string{"TestCrossOrg_Matrix_RunsApprovalsWebhooks"}, "role detail, bulk member assignment"},
	"/api/v1/groups":                {isoTested, []string{"TestCrossOrg_Matrix_RunsApprovalsWebhooks", "TestAccessGroup_BulkAssignForeignTenantAsset_Skipped"}, "team detail, asset assignment"},
	"/api/v1/repositories":          {isoTested, []string{"TestCrossOrg_Matrix_Branches"}, "branches (keyed by repository, not tenant)"},

	// --- sql: declared (burn-down: add a cross-organization test) ------------------
	"/api/v1/ai":                      {isoSQL, nil, sqlHow},
	"/api/v1/api-specs":               {isoSQL, nil, sqlHow},
	"/api/v1/asset-types":             {isoSQL, nil, sqlHow + "; platform types are shared, own types are tenant rows"},
	"/api/v1/assignment-rules":        {isoSQL, nil, sqlHow},
	"/api/v1/attachments":             {isoSQL, nil, sqlHow},
	"/api/v1/attacker-profiles":       {isoSQL, nil, sqlHow},
	"/api/v1/attack-surface":          {isoSQL, nil, sqlHow},
	"/api/v1/audit-logs":              {isoSQL, nil, sqlHow},
	"/api/v1/business-services":       {isoSQL, nil, sqlHow},
	"/api/v1/business-units":          {isoSQL, nil, sqlHow},
	"/api/v1/capabilities":            {isoSQL, nil, sqlHow + "; platform capabilities are shared"},
	"/api/v1/ci":                      {isoSQL, nil, sqlHow + "; run tokens carry the tenant of the run"},
	"/api/v1/commands":                {isoSQL, nil, sqlHow},
	"/api/v1/comments":                {isoSQL, nil, sqlHow},
	"/api/v1/compensating-controls":   {isoSQL, nil, sqlHow},
	"/api/v1/compliance":              {isoSQL, nil, sqlHow + "; framework catalog is shared"},
	"/api/v1/components":              {isoSQL, nil, sqlHow},
	"/api/v1/content":                 {isoSQL, nil, sqlHow + "; instance catalog is shared"},
	"/api/v1/content-packs":           {isoSQL, nil, sqlHow},
	"/api/v1/content-rules":           {isoSQL, nil, sqlHow},
	"/api/v1/content-sources":         {isoSQL, nil, sqlHow},
	"/api/v1/control-tests":           {isoSQL, nil, sqlHow},
	"/api/v1/credentials":             {isoSQL, nil, sqlHow},
	"/api/v1/ctem-cycles":             {isoSQL, nil, sqlHow},
	"/api/v1/easm":                    {isoSQL, nil, sqlHow},
	"/api/v1/emerging-threats":        {isoSQL, nil, sqlHow},
	"/api/v1/exposures":               {isoSQL, nil, sqlHow},
	"/api/v1/import-mappings":         {isoSQL, nil, sqlHow},
	"/api/v1/iocs":                    {isoSQL, nil, sqlHow},
	"/api/v1/lifecycles":              {isoSQL, nil, sqlHow},
	"/api/v1/lifecycle-sub-statuses":  {isoSQL, nil, sqlHow},
	"/api/v1/mcp-access":              {isoSQL, nil, sqlHow + "; the caller's own connections"},
	"/api/v1/notification-outbox":     {isoSQL, nil, sqlHow},
	"/api/v1/notifications":           {isoSQL, nil, sqlHow + "; the caller's own notices"},
	"/api/v1/operations":              {isoSQL, nil, sqlHow + "; read by its creator only"},
	"/api/v1/organization":            {isoSQL, nil, sqlHow + "; the token's organization is the only one addressable"},
	"/api/v1/pentest":                 {isoSQL, nil, sqlHow + "; campaign membership applies on top"},
	"/api/v1/priority-rules":          {isoSQL, nil, sqlHow},
	"/api/v1/programs":                {isoSQL, nil, sqlHow},
	"/api/v1/proxy-pools":             {isoSQL, nil, sqlHow},
	"/api/v1/relationships":           {isoSQL, nil, sqlHow},
	"/api/v1/reports":                 {isoSQL, nil, sqlHow},
	"/api/v1/scan-approvals":          {isoSQL, nil, sqlHow},
	"/api/v1/scanner-templates":       {isoSQL, nil, sqlHow},
	"/api/v1/scan-profiles":           {isoSQL, nil, sqlHow},
	"/api/v1/scan-workflows":          {isoSQL, nil, "tenant from the token chain; the service answers not found for another tenant's workflow (GetTemplateWithSteps carries the tenant); system workflows are shared"},
	"/api/v1/scan-zones":              {isoSQL, nil, sqlHow},
	"/api/v1/scim-tokens":             {isoSQL, nil, sqlHow},
	"/api/v1/secret-store":            {isoSQL, nil, sqlHow},
	"/api/v1/sensor-pairings":         {isoSQL, nil, sqlHow + "; a pending request has no tenant until its approver's tenant binds it"},
	"/api/v1/sensors":                 {isoSQL, nil, sqlHow},
	"/api/v1/service-accounts":        {isoSQL, nil, sqlHow},
	"/api/v1/simulations":             {isoSQL, nil, sqlHow},
	"/api/v1/sla-policies":            {isoSQL, nil, sqlHow},
	"/api/v1/suppressions":            {isoSQL, nil, sqlHow},
	"/api/v1/tenants":                 {isoSQL, nil, "the {tenant} URL id must be an organization the caller is an active member of (membership middleware); ids below it are resolved inside it"},
	"/api/v1/threat-models":           {isoSQL, nil, sqlHow},
	"/api/v1/tools":                   {isoSQL, nil, sqlHow + "; platform tools are shared, a tenant manages only its own custom tools"},
	"/api/v1/tool-categories":         {isoSQL, nil, sqlHow + "; platform categories are shared"},
	"/api/v1/tool-sources":            {isoSQL, nil, sqlHow},
	"/api/v1/verification-checklists": {isoSQL, nil, sqlHow},
	"/api/v1/vex-statements":          {isoSQL, nil, sqlHow},
	"/api/v1/vulnerability-exposures": {isoSQL, nil, sqlHow},
	"/api/v1/web-endpoints":           {isoSQL, nil, sqlHow},
	"/api/v1/wordlists":               {isoSQL, nil, sqlHow},
	"/api/v1/workflow-runs":           {isoSQL, nil, sqlHow},
	"/api/v1/workflows":               {isoSQL, nil, sqlHow},

	// --- none: not organization data -------------------------------------------------
	"/api/v1/admin":                  {isoNone, nil, "platform-admin realm (RFC-022): accounts in no organization; it addresses organizations by id by design"},
	"/api/v1/auth":                   {isoNone, nil, "authentication flows of the caller's own account and sessions"},
	"/api/v1/brand":                  {isoNone, nil, "instance brand, no tenant data"},
	"/api/v1/invitations":            {isoNone, nil, "an invitation token names the one organization"},
	"/api/v1/oauth":                  {isoNone, nil, "the caller's own MCP consent requests"},
	"/api/v1/platform-content-packs": {isoNone, nil, "platform catalog, read-only"},
	"/api/v1/proxy-test-echoes":      {isoNone, nil, "the token of one live proxy test"},
	"/api/v1/threat-actors":          {isoNone, nil, "global threat actor catalog"},
	"/api/v1/threat-intel":           {isoNone, nil, "global EPSS and KEV feeds"},
	"/api/v1/users":                  {isoNone, nil, "the caller's own account (users are not organization rows)"},
	"/api/v1/vulnerabilities":        {isoNone, nil, "global CVE catalog; the affected-assets lists are filtered by tenant and scope in SQL"},
	"/api/v2/sensor":                 {isoNone, nil, "sensor protocol: the tenant comes from the sensor key, never from the request"},
	"/hooks/content-sources":         {isoNone, nil, "the source named in the URL and its own secret decide the one tenant"},
	"/hooks/github-integrations":     {isoNone, nil, "the integration named in the URL and its own HMAC secret decide the one tenant"},
	"/hooks/jira-integrations":       {isoNone, nil, "the integration named in the URL and its own HMAC secret decide the one tenant"},
	"/scim/v2":                       {isoNone, nil, "SCIM provisioning: the per-tenant bearer token decides the tenant"},
}

// tenantIsolationRoutes holds the routes that are not in the baseline: one
// entry per new route with a path id, as "METHOD /full/path" -> "test:
// TestName" (a cross-organization test that exists) or "scope: <why an id
// alone is safe>". Empty today: the baseline covers what existed.
var tenantIsolationRoutes = map[string]string{} //nolint:gochecknoglobals // registry

// baselineCap is the number of id routes the baseline held when the guard was
// added. It only goes down: raise it and the guard has stopped guarding.
const baselineCap = 1019

func readIsolationBaseline(t *testing.T) map[string]bool {
	t.Helper()
	f, err := os.Open(filepath.Join(repoRoot(t), "tests", "unit", "testdata", "tenant_isolation_baseline.txt"))
	if err != nil {
		t.Fatalf("read the baseline: %v", err)
	}
	defer f.Close()
	out := map[string]bool{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if line := strings.TrimSpace(sc.Text()); line != "" && !strings.HasPrefix(line, "#") {
			out[line] = true
		}
	}
	return out
}

// lookupIsolation returns the registry entry whose key is the longest path
// prefix of the route (at a segment boundary).
func lookupIsolation(path string) (string, isolationDecl, bool) {
	best, found := "", isolationDecl{}
	for key, d := range tenantIsolationRegistry {
		if (path == key || strings.HasPrefix(path, key+"/")) && len(key) > len(best) {
			best, found = key, d
		}
	}
	return best, found, best != ""
}

var testFuncRe = regexp.MustCompile(`(?m)^func (Test[A-Za-z0-9_]+)\(`)

// existingTests lists every Test function of every _test.go file under the
// server module.
func existingTests(t *testing.T) map[string]bool {
	t.Helper()
	out := map[string]bool{}
	err := filepath.WalkDir(repoRoot(t), func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && (d.Name() == "node_modules" || d.Name() == ".git") {
			return filepath.SkipDir
		}
		if d.IsDir() || !strings.HasSuffix(p, "_test.go") {
			return nil
		}
		b, rerr := os.ReadFile(p)
		if rerr != nil {
			return rerr
		}
		for _, m := range testFuncRe.FindAllSubmatch(b, -1) {
			out[string(m[1])] = true
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk tests: %v", err)
	}
	return out
}

func TestEveryIDRouteDeclaresItsTenantIsolation(t *testing.T) {
	routes := parseRoutes(t)
	baseline := readIsolationBaseline(t)
	tests := existingTests(t)

	var unregistered, newRoutes, badEntries []string
	seen := map[string]bool{}
	used := map[string]bool{}
	counts := map[isolationKind]int{}
	for _, r := range routes {
		if !strings.Contains(r.path, "{") {
			continue
		}
		id := r.method + " " + r.path
		seen[id] = true
		key, d, ok := lookupIsolation(r.path)
		if !ok {
			unregistered = append(unregistered, id+"  ("+r.pos+")")
			continue
		}
		used[key] = true
		counts[d.kind]++
		if baseline[id] {
			continue
		}
		decl, has := tenantIsolationRoutes[id]
		switch {
		case !has:
			newRoutes = append(newRoutes, id+"  ("+r.pos+")")
		case strings.HasPrefix(decl, "test:"):
			if name := strings.TrimSpace(strings.TrimPrefix(decl, "test:")); !tests[name] {
				badEntries = append(badEntries, id+": test "+name+" does not exist")
			}
		case strings.HasPrefix(decl, "scope:") && len(strings.TrimSpace(strings.TrimPrefix(decl, "scope:"))) >= 20:
		default:
			badEntries = append(badEntries, id+`: the entry must be "test: TestName" or "scope: <at least 20 characters on why an id alone is safe>"`)
		}
	}
	sort.Strings(unregistered)
	sort.Strings(newRoutes)
	if len(unregistered) > 0 {
		t.Errorf("a route with a path id has no tenant-isolation declaration: add its path prefix to tenantIsolationRegistry in "+isolationFile+
			" (tested with named cross-organization tests, sql, or none with the reason):\n  %s", strings.Join(unregistered, "\n  "))
	}
	if len(newRoutes) > 0 {
		t.Errorf("a route with a path id was added: write a cross-organization test (a token of B, the id of A: server/internal/server/xorg_*_db_test.go) "+
			"and add the route to tenantIsolationRoutes in "+isolationFile+` as "test: TestName", or as "scope: <why an id alone is safe>":`+"\n  %s",
			strings.Join(newRoutes, "\n  "))
	}
	if len(badEntries) > 0 {
		t.Errorf("tenantIsolationRoutes in "+isolationFile+":\n  %s", strings.Join(badEntries, "\n  "))
	}

	// Entries that match nothing, tested entries naming tests that do not
	// exist, and a baseline that kept a removed route or grew.
	var stale, missingTests, shrink []string
	for key, d := range tenantIsolationRegistry {
		if !used[key] {
			stale = append(stale, key)
		}
		if d.kind == isoTested {
			if len(d.tests) == 0 {
				missingTests = append(missingTests, key+": a tested entry names no test")
			}
			for _, name := range d.tests {
				if !tests[name] {
					missingTests = append(missingTests, key+": test "+name+" does not exist")
				}
			}
		}
		if d.note == "" {
			missingTests = append(missingTests, key+": the note says nothing")
		}
	}
	for id := range baseline {
		if !seen[id] {
			shrink = append(shrink, id)
		}
	}
	for id := range tenantIsolationRoutes {
		if !seen[id] {
			stale = append(stale, id)
		}
	}
	sort.Strings(stale)
	sort.Strings(missingTests)
	sort.Strings(shrink)
	if len(stale) > 0 {
		t.Errorf("a route was removed or renamed: update "+isolationFile+": entries that match no route:\n  %s", strings.Join(stale, "\n  "))
	}
	if len(missingTests) > 0 {
		t.Errorf("update "+isolationFile+":\n  %s", strings.Join(missingTests, "\n  "))
	}
	if len(shrink) > 0 {
		t.Errorf("a route was removed or renamed: delete it from testdata/tenant_isolation_baseline.txt (the list only shrinks):\n  %s", strings.Join(shrink, "\n  "))
	}
	if len(baseline) > baselineCap {
		t.Errorf("testdata/tenant_isolation_baseline.txt has %d routes, the cap is %d: a new route needs its own entry in tenantIsolationRoutes, not a baseline line",
			len(baseline), baselineCap)
	}

	var declared []string
	for key, d := range tenantIsolationRegistry {
		if d.kind == isoSQL {
			declared = append(declared, key)
		}
	}
	sort.Strings(declared)
	t.Logf("id routes by isolation kind: %v; prefixes declared only (no cross-organization test yet): %s", counts, strings.Join(declared, " "))
}

// The longest prefix wins and only at a segment boundary.
func TestTenantIsolationLookup(t *testing.T) {
	cases := map[string]isolationKind{
		"/api/v1/findings/{id}":          isoTested,
		"/api/v1/findings/{id}/comments": isoTested,
		"/api/v1/scan-runs/{id}":         isoTested,
		"/api/v1/scans/{id}":             isoTested,
		"/api/v1/admin/orgs/{id}":        isoNone,
		"/scim/v2/Users/{id}":            isoNone,
	}
	for path, want := range cases {
		if _, got, ok := lookupIsolation(path); !ok || got.kind != want {
			t.Errorf("%s: kind %q, want %q", path, got.kind, want)
		}
	}
	// scan-runs must not be read as scans, nor assets-xyz as assets.
	if key, _, _ := lookupIsolation("/api/v1/assetsx/{id}"); key == "/api/v1/assets" {
		t.Error("a prefix matched inside a path segment")
	}
	if _, _, ok := lookupIsolation("/api/v1/brand-new-surface/{id}"); ok {
		t.Error("an unregistered route matched; the gate would not catch it")
	}
}
