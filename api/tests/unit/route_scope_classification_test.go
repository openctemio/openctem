package unit

import (
	"sort"
	"strings"
	"testing"
)

// The data-surface registry: every HTTP route says how it relates to the
// Layer 2 data scope (research doc 15 §5.1 and §5.10, P1-3). A route added
// without a classification fails TestEveryRouteHasADataScopeClass, so a new
// asset-derived read cannot ship unscoped without someone deciding, in
// review, that it is meant to be. Matching is by the longest path prefix
// (method-agnostic unless the key starts with a method), so a whole module
// is classified once and the exceptions inside it are listed explicitly. A
// key ending in "$" matches its one path exactly, for a single route whose
// path is also the prefix of others.
//
// Classes:
//   - scoped: rows derived from assets are filtered to the caller's data
//     scope (route guard, enforcer or SQL condition); by id out of scope is 404.
//   - partial: rows are scoped, some counts or summaries are tenant-wide by
//     design (documented in authorization-matrix.md) or not yet scoped.
//   - gap: asset-derived data that is NOT yet limited to the caller's scope.
//     The note must cite the research finding (L-xx or §) that tracks it.
//   - separate: another access model decides (pentest campaign membership).
//   - config: tenant configuration or administration, not asset-derived data
//     (still permission-gated; see route_authz_coverage_test.go).
//   - system: authentication, the caller's own data, sensor protocols, the
//     platform-admin realm, global catalogs and public endpoints.
//
// registryFile is named in every failure so whoever added or removed a route
// knows what to edit.
const registryFile = "api/tests/unit/route_scope_classification_test.go (dataSurfaceRegistry)"

type dataScopeClass string

const (
	classScoped   dataScopeClass = "scoped"
	classPartial  dataScopeClass = "partial"
	classGap      dataScopeClass = "gap"
	classSeparate dataScopeClass = "separate"
	classConfig   dataScopeClass = "config"
	classSystem   dataScopeClass = "system"
)

type dataSurface struct {
	class dataScopeClass
	note  string
}

var dataSurfaceRegistry = map[string]dataSurface{
	// --- system --------------------------------------------------------------
	"/health":                          {classSystem, "public liveness"},
	"/ready":                           {classSystem, "public readiness"},
	"/metrics":                         {classSystem, "operator metrics (bearer)"},
	"/openapi.yaml":                    {classSystem, "public API spec"},
	"/docs":                            {classSystem, "public API docs"},
	"/api/v1/version":                  {classSystem, "build identity"},
	"/api/v1/auth":                     {classSystem, "authentication flows"},
	"/api/v1/users":                    {classSystem, "the caller's own account"},
	"/api/v1/me":                       {classSystem, "the caller's own permissions, groups and assets"},
	"/api/v1/views":                    {classSystem, "the caller's saved views and those shared with their groups; a view runs as the viewer, scoped (D15)"},
	"/api/v1/invitations":              {classSystem, "invitation acceptance (token)"},
	"/api/v1/agent/":                   {classSystem, "sensor protocol v1 (write-only, tenant from the key)"},
	"/api/v2/sensor":                   {classSystem, "sensor protocol v2 (write-only, tenant from the key)"},
	"/api/v1/agents":                   {classSystem, "308 redirect to /api/v1/sensors"},
	"/api/v1/platform":                 {classSystem, "platform sensors"},
	"/api/v1/admin":                    {classSystem, "platform-admin realm (RFC-022)"},
	"/scim/v2":                         {classSystem, "SCIM provisioning (per-tenant bearer)"},
	"/api/v1/module-presets":           {classSystem, "module preset catalog"},
	"/api/v1/permissions":              {classSystem, "permission catalog"},
	"/api/v1/asset-types":              {classSystem, "asset type registry"},
	"/api/v1/tools":                    {classSystem, "tool catalog"},
	"/api/v1/tool-categories":          {classSystem, "tool catalog"},
	"/api/v1/capabilities":             {classSystem, "capability catalog"},
	"/api/v1/finding-sources":          {classSystem, "finding source catalog"},
	"/api/v1/threat-intel":             {classSystem, "global EPSS/KEV feeds"},
	"/api/v1/threat-actors":            {classSystem, "threat actor catalog"},
	"/api/v1/ctem-ids":                 {classSystem, "identifier catalog"},
	"/api/v1/vulnerabilities":          {classSystem, "global CVE catalog (no tenant data)"},
	"POST /api/v1/validation/evidence": {classSystem, "sensor evidence upload (sensor key)"},

	// --- config ----------------------------------------------------------------
	"/api/v1/tenants":                {classConfig, "organization administration (team roles)"},
	"/api/v1/organization":           {classConfig, "organization settings"},
	"/api/v1/roles":                  {classConfig, "roles"},
	"/api/v1/groups":                 {classConfig, "access groups: membership and scope administration (D13 cap)"},
	"/api/v1/scim-tokens":            {classConfig, "SCIM tokens"},
	"/api/v1/api-keys":               {classConfig, "API keys"},
	"/api/v1/audit-logs":             {classConfig, "audit log (admin)"},
	"/api/v1/integrations":           {classConfig, "integrations; delivery history is channel-manager only (L-03)"},
	"/api/v1/notification-outbox":    {classConfig, "delivery queue, channel-manager only (L-03)"},
	"/api/v1/webhooks":               {classConfig, "inbound Jira/GitHub webhooks (HMAC); the outbound webhook API is removed"},
	"/api/v1/scope":                  {classConfig, "scope targets, exclusions (two-person, L-07) and schedules"},
	"/api/v1/easm/seeds":             {classConfig, "EASM seeds: tenant boundary configuration, scope permissions (RFC-036 §6.3)"},
	"/api/v1/sensors":                {classConfig, "sensor management"},
	"/api/v1/scan-zones":             {classConfig, "scan zones"},
	"/api/v1/scan-profiles":          {classConfig, "scan profiles"},
	"/api/v1/scanner-templates":      {classConfig, "scanner templates"},
	"/api/v1/template-sources":       {classConfig, "template sources"},
	"/api/v1/tenant-tools":           {classConfig, "tenant tool configuration"},
	"/api/v1/custom-tools":           {classConfig, "custom tools"},
	"/api/v1/custom-tool-categories": {classConfig, "custom tool categories"},
	"/api/v1/custom-capabilities":    {classConfig, "custom capabilities"},
	// Not catalog data: the stats name the caller's own sensors and custom tools
	// (tenant-filtered in SQL; platform tools are the only shared rows, 23b SC-H1).
	"POST /api/v1/capabilities/usage-stats":     {classConfig, "usage of capabilities by the caller tenant's own tools and sensors"},
	"GET /api/v1/capabilities/{id}/usage-stats": {classConfig, "usage of a capability by the caller tenant's own tools and sensors"},
	"/api/v1/secret-store":                      {classConfig, "scanner credentials"},
	"/api/v1/sla-policies":                      {classConfig, "SLA policies"},
	"/api/v1/priority-rules":                    {classConfig, "priority rules"},
	"/api/v1/assignment-rules":                  {classConfig, "finding assignment rules"},
	"/api/v1/attacker-profiles":                 {classConfig, "attacker profiles"},
	"/api/v1/compensating-controls":             {classConfig, "compensating controls"},
	"/api/v1/control-tests":                     {classConfig, "compensating control tests"},
	"/api/v1/workflows":                         {classConfig, "workflow definitions"},
	"/api/v1/compliance":                        {classConfig, "framework and control catalog, assessments"},
	"/api/v1/scoping":                           {classConfig, "scoping summary (counts, tenant-wide by design)"},

	// --- scoped ------------------------------------------------------------------
	"/api/v1/assets":                                      {classScoped, "route guard on /assets/{id}/**, list, stats and facets scoped (RFC-042 F10)"},
	"/api/v1/findings":                                    {classScoped, "route guard on /findings/{id}/**, lists and bulk paths scoped"},
	"POST /api/v1/findings/$":                             {classScoped, "asset_id through AssertAssetRef (tenant + caller scope), branch bound to the asset (research 21b C1)"},
	"GET /api/v1/findings/analytics/sources":              {classGap, "L-18 (source analytics counts are tenant-wide)"},
	"/api/v1/compliance/findings":                         {classScoped, "route guard on /compliance/findings/{id}/**"},
	"/api/v1/verification-checklists":                     {classScoped, "route guard on the finding id"},
	"/api/v1/comments":                                    {classScoped, "comment resolved to its finding, finding scope applies"},
	"/api/v1/exposures":                                   {classScoped, "exposure service scope; POST / checks asset_id with AssertAssetRef (research 21b C3)"},
	"POST /api/v1/exposures/ingest":                       {classGap, "§3 H1 of research 21b: asset_id checked (C3), but the fingerprint upsert can overwrite an out-of-scope or asset-less exposure"},
	"GET /api/v1/exposures/stats":                         {classPartial, "counts tenant-wide (L-18)"},
	"/api/v1/components":                                  {classScoped, "component service scope (L-10)"},
	"/api/v1/repositories":                                {classScoped, "repository must be in scope (L-10)"},
	"/api/v1/relationships":                               {classScoped, "both ends in scope"},
	"/api/v1/services":                                    {classScoped, "asset service handler scope"},
	"/api/v1/state-history":                               {classScoped, "state history handler scope"},
	"/api/v1/threat-models":                               {classScoped, "threat model scope (L-10)"},
	"/api/v1/vulnerabilities/{id}/affected-assets":        {classScoped, "affected assets filtered"},
	"/api/v1/vulnerabilities/cve/{cveId}/affected-assets": {classScoped, "affected assets filtered"},
	"/api/v1/notifications":                               {classScoped, "per-recipient scope on finding and asset notices"},
	"/api/v1/ws":                                          {classScoped, "finding and triage channels need the finding in scope"},
	"/api/v1/mcp":                                         {classScoped, "each tool runs as the key's user (API keys never get full data)"},

	// --- partial -------------------------------------------------------------------
	"/api/v1/asset-groups":      {classPartial, "members, findings and adds scoped; asset_count/risk/finding_count tenant-wide (L-18)"},
	"/api/v1/attack-surface":    {classPartial, "chains dropped unless every hop is in scope; summaries graph-wide"},
	"/api/v1/easm":              {classPartial, "summary scoped; candidates are tenant discovery output"},
	"/api/v1/business-services": {classPartial, "asset links scoped (L-10); the service list is tenant configuration"},
	"/api/v1/business-units":    {classPartial, "asset links scoped (L-10); the unit list and counts are tenant-wide"},
	"/api/v1/ctem-cycles":       {classPartial, "scope snapshot scoped (L-10); cycle metrics are tenant-wide counts"},
	"/api/v1/approvals":         {classPartial, "approvals by id and the page scoped; total tenant-wide (L-18)"},
	"/api/v1/remediation":       {classScoped, "resolve scoped; campaign progress counts follow the reader (L-18, research 24)"},
	"/api/v1/dashboard":         {classPartial, "activity and top risks scoped; counts and trends tenant-wide until P1-4 (D6)"},

	// --- separate ------------------------------------------------------------------
	"/api/v1/pentest":     {classSeparate, "campaign membership (D5 engagement scope is P2)"},
	"/api/v1/attachments": {classSeparate, "pentest and finding evidence; campaign membership"},

	// --- gap -----------------------------------------------------------------------
	"/api/v1/credentials":                 {classScoped, "leaks on in-scope assets; asset-less leaks: unrestricted callers only (L-10)"},
	"/api/v1/vulnerabilities/active":      {classScoped, "aggregated over in-scope findings, REST and MCP (L-10)"},
	"GET /api/v1/groups/{groupId}/assets": {classScoped, "only the group's assets in the caller's scope (L-10)"},
	"/api/v1/scans":                       {classGap, "L-06 (scan reads and targets; D9)"},
	"/api/v1/scan-sessions":               {classGap, "L-06 (scan reads)"},
	"/api/v1/commands":                    {classGap, "L-06 (command payloads)"},
	"/api/v1/pipelines":                   {classGap, "L-06 (pipeline reads)"},
	"POST /api/v1/pipelines/{id}/runs":    {classPartial, "asset_id through AssertAssetRef (research 21b C4), run targets through the act-scope gate (D9); step config targets unchecked (21b LOW)"},
	"/api/v1/pipeline-runs":               {classGap, "L-06 (run reads)"},
	"/api/v1/workflow-runs":               {classGap, "L-18 (trigger data)"},
	"/api/v1/iocs":                        {classGap, "§1.3 IOC matches (L-18)"},
	"/api/v1/suppressions":                {classGap, "§1.3 suppression rules"},
	"/api/v1/reports":                     {classGap, "L-19 (scheduled reports; P1-4/P1-5)"},
	"/api/v1/simulations":                 {classGap, "§1.3 validation and simulation"},
	"/api/v1/validation":                  {classGap, "§1.3 validation coverage"},
}

// lookupDataSurface returns the registry entry whose path prefix is the
// longest one matching the route; a method-specific key beats a generic key
// with the same prefix.
func lookupDataSurface(method, path string) (string, dataSurface, bool) {
	bestKey, bestLen, bestMethod := "", -1, false
	var found dataSurface
	for key, s := range dataSurfaceRegistry {
		prefix, specific := key, false
		if m, rest, ok := strings.Cut(key, " "); ok {
			if m != method {
				continue
			}
			prefix, specific = rest, true
		}
		if exact, ok := strings.CutSuffix(prefix, "$"); ok {
			// A key ending in "$" names exactly one route, not a subtree
			// (POST /findings/ must not also classify POST /findings/search).
			if path != exact {
				continue
			}
			prefix = exact
		} else if !strings.HasPrefix(path, prefix) {
			continue
		}
		if len(prefix) > bestLen || (len(prefix) == bestLen && specific && !bestMethod) {
			bestKey, bestLen, bestMethod, found = key, len(prefix), specific, s
		}
	}
	return bestKey, found, bestKey != ""
}

func TestEveryRouteHasADataScopeClass(t *testing.T) {
	routes := parseRoutes(t)
	used := map[string]bool{}
	var missing []string
	counts := map[dataScopeClass]int{}
	for _, r := range routes {
		key, s, ok := lookupDataSurface(r.method, r.path)
		if !ok {
			missing = append(missing, r.method+" "+r.path+"  ("+r.pos+")")
			continue
		}
		used[key] = true
		counts[s.class]++
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Errorf("a route was added: update "+registryFile+": routes with no data-scope class: classify each in dataSurfaceRegistry "+
			"(scoped, partial, gap with its research id, separate, config or system):\n  %s",
			strings.Join(missing, "\n  "))
	}

	var stale, untracked []string
	for key, s := range dataSurfaceRegistry {
		if !used[key] {
			stale = append(stale, key)
		}
		if s.class == classGap && !strings.Contains(s.note, "L-") && !strings.Contains(s.note, "§") {
			untracked = append(untracked, key)
		}
	}
	sort.Strings(stale)
	sort.Strings(untracked)
	if len(stale) > 0 {
		t.Errorf("a route was removed or renamed: update "+registryFile+": registry entries that match no route (remove or fix them):\n  %s", strings.Join(stale, "\n  "))
	}
	if len(untracked) > 0 {
		t.Errorf("update "+registryFile+": gap entries must cite the research finding that tracks them (L-xx or §):\n  %s", strings.Join(untracked, "\n  "))
	}
	t.Logf("data-scope classes: %v", counts)
}

// The longest match wins, so an exception inside a module overrides it.
func TestDataSurfaceLookup_LongestPrefixWins(t *testing.T) {
	cases := map[string]dataScopeClass{
		"GET /api/v1/vulnerabilities/":                         classSystem,
		"GET /api/v1/vulnerabilities/active":                   classScoped,
		"GET /api/v1/vulnerabilities/{id}/affected-assets":     classScoped,
		"GET /api/v1/groups/{groupId}/assets":                  classScoped,
		"POST /api/v1/groups/{groupId}/assets":                 classConfig,
		"GET /api/v1/compliance/findings/{findingId}/controls": classScoped,
		"GET /api/v1/compliance/frameworks/":                   classConfig,
		"POST /api/v1/findings/":                               classScoped,
		"POST /api/v1/findings/search":                         classScoped,
		"GET /api/v1/findings/analytics/sources":               classGap,
	}
	// An exact key classifies only its own path.
	if key, _, _ := lookupDataSurface("POST", "/api/v1/findings/search"); key == "POST /api/v1/findings/$" {
		t.Errorf("the exact key POST /api/v1/findings/$ matched POST /api/v1/findings/search")
	}
	for route, want := range cases {
		method, path, _ := strings.Cut(route, " ")
		_, got, ok := lookupDataSurface(method, path)
		if !ok || got.class != want {
			t.Errorf("%s: class %q, want %q", route, got.class, want)
		}
	}
}

// A route under a root nobody classified has no class, so the gate fails.
func TestDataSurfaceLookup_UnknownRouteIsUnclassified(t *testing.T) {
	if key, _, ok := lookupDataSurface("GET", "/api/v1/brand-new-surface/{id}"); ok {
		t.Errorf("an unregistered route matched %q; the gate would not catch it", key)
	}
}
