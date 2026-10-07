package routes

// The one tool resource (/api/v1/tools and /api/v1/tool-categories): the
// URLs merged, the authorization did not. Every refusal is checked here:
// a member against an admin, a caller holding only the catalog read, another
// tenant's custom tool and category, and platform tools and categories, which
// no tenant may change from this API (not found, never a 403 that would
// confirm another tenant's id).

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/http/include/includetest"
	"github.com/openctemio/openctem/api/pkg/domain/permission"
)

func listToolNames(t *testing.T, body string) map[string]handler.ToolViewResponse {
	t.Helper()
	var resp handler.ToolListResponse
	mustJSON(t, body, &resp)
	out := make(map[string]handler.ToolViewResponse, len(resp.Items))
	for _, it := range resp.Items {
		out[it.Name] = it
	}
	return out
}

func TestToolsAPI_Authorization_DB(t *testing.T) {
	h := newToolAvailabilityHarness(t)
	tid, other := h.tenant(), h.tenant()
	admin, member, viewer := h.member(tid, "admin"), h.member(tid, "member"), h.member(tid, "viewer")
	otherAdmin := h.member(other, "admin")
	t.Cleanup(func() {
		ctx := context.Background()
		tenants := "{" + tid + "," + other + "}"
		_, _ = h.db.ExecContext(ctx, `DELETE FROM tenant_tool_configs WHERE tenant_id = ANY($1::uuid[])`, tenants)
		_, _ = h.db.ExecContext(ctx, `DELETE FROM tools WHERE tenant_id = ANY($1::uuid[])`, tenants)
		_, _ = h.db.ExecContext(ctx, `DELETE FROM tool_categories WHERE tenant_id = ANY($1::uuid[])`, tenants)
	})

	var nucleiID, platformCategoryID string
	if err := h.db.QueryRowContext(context.Background(),
		`SELECT id FROM tools WHERE name = 'nuclei' AND tenant_id IS NULL`).Scan(&nucleiID); err != nil {
		t.Fatal(err)
	}
	if err := h.db.QueryRowContext(context.Background(),
		`SELECT id FROM tool_categories WHERE tenant_id IS NULL LIMIT 1`).Scan(&platformCategoryID); err != nil {
		t.Fatal(err)
	}

	const create = `{"name":"zz-authz-tool","display_name":"Ours","install_method":"binary"}`
	const update = `{"display_name":"Changed"}`

	// --- Custom tools: admin only (scans:tools:write/delete) -------------
	h.expect(member, http.MethodPost, "/api/v1/tools", create, http.StatusForbidden)
	h.expect(viewer, http.MethodPost, "/api/v1/tools", create, http.StatusForbidden)
	ours := decodeID(t, h.expect(admin, http.MethodPost, "/api/v1/tools", create, http.StatusCreated))
	theirs := decodeID(t, h.expect(otherAdmin, http.MethodPost, "/api/v1/tools",
		`{"name":"zz-their-authz-tool","display_name":"Theirs","install_method":"binary"}`, http.StatusCreated))

	h.expect(member, http.MethodPut, "/api/v1/tools/"+ours, update, http.StatusForbidden)
	h.expect(member, http.MethodDelete, "/api/v1/tools/"+ours, "", http.StatusForbidden)
	h.expect(viewer, http.MethodPut, "/api/v1/tools/"+ours, update, http.StatusForbidden)

	// A platform tool is not changed or deleted from the tenant API, by anyone.
	h.expect(admin, http.MethodPut, "/api/v1/tools/"+nucleiID, update, http.StatusNotFound)
	h.expect(admin, http.MethodDelete, "/api/v1/tools/"+nucleiID, "", http.StatusNotFound)
	// Another tenant's custom tool: not found, for every verb.
	h.expect(admin, http.MethodGet, "/api/v1/tools/"+theirs, "", http.StatusNotFound)
	h.expect(admin, http.MethodPut, "/api/v1/tools/"+theirs, update, http.StatusNotFound)
	h.expect(admin, http.MethodDelete, "/api/v1/tools/"+theirs, "", http.StatusNotFound)
	h.expect(admin, http.MethodPatch, "/api/v1/tools/"+theirs+"/settings", `{"is_enabled":false}`, http.StatusNotFound)
	var name string
	if err := h.db.QueryRowContext(context.Background(), `SELECT display_name FROM tools WHERE id = $1`, theirs).Scan(&name); err != nil || name != "Theirs" {
		t.Fatalf("another tenant's tool after the refused changes: %q (%v)", name, err)
	}
	var theirRows int
	_ = h.db.QueryRowContext(context.Background(), `SELECT count(*) FROM tenant_tool_configs WHERE tool_id = $1`, theirs).Scan(&theirRows)
	if theirRows != 0 {
		t.Fatalf("another tenant's tool got %d settings rows", theirRows)
	}

	h.expect(admin, http.MethodPut, "/api/v1/tools/"+ours, update, http.StatusOK)

	// --- Settings: scans:tenant_tools:write (members yes, viewers no) ----
	h.expect(viewer, http.MethodPatch, "/api/v1/tools/"+nucleiID+"/settings", `{"is_enabled":false}`, http.StatusForbidden)
	h.expect(viewer, http.MethodPatch, "/api/v1/tools/settings", `{"tool_ids":["`+nucleiID+`"],"is_enabled":false}`, http.StatusForbidden)
	// Config overrides change what the sensors run: scans:tools:write, not
	// the member's scans:tenant_tools:write; the switch alone is fine.
	h.expect(member, http.MethodPatch, "/api/v1/tools/"+nucleiID+"/settings", `{"config":{"rate_limit":5}}`, http.StatusForbidden)
	h.expect(member, http.MethodPatch, "/api/v1/tools/"+nucleiID+"/settings", `{"is_enabled":false}`, http.StatusOK)
	var patched handler.ToolViewResponse
	mustJSON(t, h.expect(admin, http.MethodPatch, "/api/v1/tools/"+nucleiID+"/settings",
		`{"is_enabled":false,"config":{"rate_limit":5}}`, http.StatusOK), &patched)
	if patched.Settings == nil || patched.Settings.IsEnabled || patched.Settings.Config["rate_limit"] != float64(5) || patched.Source != "platform" {
		t.Fatalf("settings after PATCH: %+v source %s", patched.Settings, patched.Source)
	}
	// An omitted field is left as it is.
	mustJSON(t, h.expect(member, http.MethodPatch, "/api/v1/tools/"+nucleiID+"/settings", `{"is_enabled":true}`, http.StatusOK), &patched)
	if !patched.Settings.IsEnabled || patched.Settings.Config["rate_limit"] != float64(5) {
		t.Fatalf("is_enabled only: %+v", patched.Settings)
	}
	h.expect(member, http.MethodPatch, "/api/v1/tools/"+nucleiID+"/settings", `{}`, http.StatusBadRequest)
	// Our settings are ours: the other tenant still sees nuclei with no overrides.
	otherView := listToolNames(t, h.expect(otherAdmin, http.MethodGet, "/api/v1/tools?include=settings&per_page=100", "", http.StatusOK))
	if s := otherView["nuclei"].Settings; s == nil || len(s.Config) != 0 || !s.IsEnabled {
		t.Fatalf("the other tenant's nuclei settings: %+v", s)
	}

	// --- Reads: the catalog with scans:tools:read; the tenant's data in it
	// with scans:tenant_tools:read as well --------------------------------
	catalogOnly := h.member(tid, "member")
	h.customRoleMember(catalogOnly, tid, permission.ToolsRead)
	h.mintToken(&catalogOnly, tid)
	h.expect(catalogOnly, http.MethodGet, "/api/v1/tools", "", http.StatusOK)
	h.expect(catalogOnly, http.MethodGet, "/api/v1/tools/"+nucleiID, "", http.StatusOK)
	// The tenant's data asked for without the permission is left out and
	// named, never a 403 (no oracle).
	var omitted handler.ToolListResponse
	mustJSON(t, h.expect(catalogOnly, http.MethodGet, "/api/v1/tools?include=settings,stats,availability", "", http.StatusOK), &omitted)
	if len(omitted.Meta.OmittedIncludes) != 3 || omitted.Availability != nil || len(omitted.Items) == 0 ||
		omitted.Items[0].Settings != nil || omitted.Items[0].Stats != nil || omitted.Items[0].Availability != nil {
		t.Fatalf("without scans:tenant_tools:read: meta %+v, availability %v, first item %+v", omitted.Meta, omitted.Availability, omitted.Items)
	}
	var one handler.ToolViewResponse
	mustJSON(t, h.expect(catalogOnly, http.MethodGet, "/api/v1/tools/"+nucleiID+"?include=settings", "", http.StatusOK), &one)
	if one.Settings != nil || one.Meta == nil || len(one.Meta.OmittedIncludes) != 1 {
		t.Fatalf("one tool without the permission: settings %+v meta %+v", one.Settings, one.Meta)
	}
	// The filters on the tenant's data are refused (a filter cannot be left out).
	for _, q := range []string{"enabled=true", "available=false"} {
		h.expect(catalogOnly, http.MethodGet, "/api/v1/tools?"+q, "", http.StatusForbidden)
	}
	noCatalog := h.member(tid, "member")
	h.customRoleMember(noCatalog, tid, permission.TenantToolsRead)
	h.mintToken(&noCatalog, tid)
	h.expect(noCatalog, http.MethodGet, "/api/v1/tools", "", http.StatusForbidden)

	// Bad parameters are refused, not ignored; filters are bounded.
	long := strings.Repeat("a", 256)
	for _, q := range []string{"include=secrets", "include=settings,secrets", "source=everyone", "sort=-install_cmd",
		"enabled=yes", "q=" + long, "category=" + long[:51], "include=" + strings.Repeat("stats,", 11)} {
		h.expect(admin, http.MethodGet, "/api/v1/tools?"+q, "", http.StatusBadRequest)
	}

	// --- The view: platform plus our own custom tools, never theirs -------
	all := listToolNames(t, h.expect(viewer, http.MethodGet, "/api/v1/tools?per_page=100&include=settings,stats", "", http.StatusOK))
	if _, ok := all["zz-authz-tool"]; !ok {
		t.Fatal("our custom tool is not listed")
	}
	if _, leaked := all["zz-their-authz-tool"]; leaked {
		t.Fatal("another tenant's custom tool is listed")
	}
	if n := all["nuclei"]; n.Source != "platform" || n.Settings == nil || n.Stats == nil {
		t.Fatalf("nuclei: %+v", n)
	}
	custom := listToolNames(t, h.expect(admin, http.MethodGet, "/api/v1/tools?source=custom&per_page=100", "", http.StatusOK))
	if len(custom) != 1 || custom["zz-authz-tool"].Source != "custom" {
		t.Fatalf("source=custom: %v", custom)
	}
	platform := listToolNames(t, h.expect(admin, http.MethodGet, "/api/v1/tools?source=platform&per_page=100", "", http.StatusOK))
	if _, ok := platform["zz-authz-tool"]; ok || len(platform) == 0 {
		t.Fatalf("source=platform lists %d tools, ours included: %v", len(platform), ok)
	}
	h.expect(member, http.MethodPatch, "/api/v1/tools/"+ours+"/settings", `{"is_enabled":false}`, http.StatusOK)
	off := listToolNames(t, h.expect(admin, http.MethodGet, "/api/v1/tools?enabled=false&per_page=100", "", http.StatusOK))
	if _, ok := off["zz-authz-tool"]; !ok || len(off) == 0 {
		t.Fatalf("enabled=false does not list the tool switched off: %v", off)
	}
	if _, ok := off["nuclei"]; ok {
		t.Fatal("enabled=false lists nuclei, which is on")
	}
	var page handler.ToolListResponse
	mustJSON(t, h.expect(admin, http.MethodGet, "/api/v1/tools?sort=-name&per_page=2&page=2", "", http.StatusOK), &page)
	if len(page.Items) != 2 || page.Page != 2 || page.Total < 4 {
		t.Fatalf("paging: %d items, page %d, total %d", len(page.Items), page.Page, page.Total)
	}

	h.expect(admin, http.MethodDelete, "/api/v1/tools/"+ours, "", http.StatusNoContent)
	h.expect(admin, http.MethodGet, "/api/v1/tools/"+ours, "", http.StatusNotFound)

	// --- Categories: the same split -------------------------------------
	const cat = `{"name":"zz-authz-cat","display_name":"Ours"}`
	h.expect(member, http.MethodPost, "/api/v1/tool-categories", cat, http.StatusForbidden)
	ourCat := decodeID(t, h.expect(admin, http.MethodPost, "/api/v1/tool-categories", cat, http.StatusCreated))
	theirCat := decodeID(t, h.expect(otherAdmin, http.MethodPost, "/api/v1/tool-categories",
		`{"name":"zz-their-cat","display_name":"Theirs"}`, http.StatusCreated))
	h.expect(member, http.MethodPut, "/api/v1/tool-categories/"+ourCat, `{"display_name":"X"}`, http.StatusForbidden)
	h.expect(member, http.MethodDelete, "/api/v1/tool-categories/"+ourCat, "", http.StatusForbidden)
	for _, id := range []string{platformCategoryID, theirCat} {
		h.expect(admin, http.MethodPut, "/api/v1/tool-categories/"+id, `{"display_name":"X"}`, http.StatusNotFound)
		h.expect(admin, http.MethodDelete, "/api/v1/tool-categories/"+id, "", http.StatusNotFound)
	}
	h.expect(admin, http.MethodGet, "/api/v1/tool-categories/"+theirCat, "", http.StatusNotFound)
	h.expect(viewer, http.MethodGet, "/api/v1/tool-categories/"+platformCategoryID, "", http.StatusOK)
	var cats handler.ToolCategoryListResponse
	mustJSON(t, h.expect(viewer, http.MethodGet, "/api/v1/tool-categories?source=custom", "", http.StatusOK), &cats)
	if len(cats.Items) != 1 || cats.Items[0].ID != ourCat {
		t.Fatalf("source=custom categories: %+v", cats.Items)
	}
	h.expect(viewer, http.MethodGet, "/api/v1/tool-categories?source=nobody", "", http.StatusBadRequest)
	h.expect(admin, http.MethodPut, "/api/v1/tool-categories/"+ourCat, `{"display_name":"Ours 2"}`, http.StatusOK)
	h.expect(admin, http.MethodDelete, "/api/v1/tool-categories/"+ourCat, "", http.StatusNoContent)
}

// The routes the one tool resource replaced are gone (no alias left that
// could keep an old, wider gate alive).
func TestToolsAPI_RemovedRoutes_DB(t *testing.T) {
	h := newToolAvailabilityHarness(t)
	tid := h.tenant()
	admin := h.member(tid, "admin")
	id := "00000000-0000-0000-0000-0000000000aa"
	removed := []struct{ method, path string }{
		{http.MethodGet, "/api/v1/tools/platform"},
		{http.MethodGet, "/api/v1/tools/name/nuclei"},
		{http.MethodPost, "/api/v1/tools/" + id + "/activate"},
		{http.MethodPost, "/api/v1/tools/" + id + "/deactivate"},
		{http.MethodGet, "/api/v1/custom-tools"},
		{http.MethodPost, "/api/v1/custom-tools"},
		{http.MethodGet, "/api/v1/custom-tools/" + id},
		{http.MethodPut, "/api/v1/custom-tools/" + id},
		{http.MethodDelete, "/api/v1/custom-tools/" + id},
		{http.MethodPost, "/api/v1/custom-tools/" + id + "/activate"},
		{http.MethodPost, "/api/v1/custom-tools/" + id + "/deactivate"},
		{http.MethodGet, "/api/v1/tenant-tools"},
		{http.MethodGet, "/api/v1/tenant-tools/all-tools"},
		{http.MethodGet, "/api/v1/tenant-tools/availability"},
		{http.MethodGet, "/api/v1/tenant-tools/stats"},
		{http.MethodGet, "/api/v1/tenant-tools/stats/" + id},
		{http.MethodGet, "/api/v1/tenant-tools/" + id},
		{http.MethodPut, "/api/v1/tenant-tools/" + id},
		{http.MethodDelete, "/api/v1/tenant-tools/" + id},
		{http.MethodGet, "/api/v1/tenant-tools/" + id + "/effective-config"},
		{http.MethodGet, "/api/v1/tenant-tools/" + id + "/with-config"},
		{http.MethodPost, "/api/v1/tenant-tools/bulk/enable"},
		{http.MethodPost, "/api/v1/tenant-tools/bulk/disable"},
		{http.MethodGet, "/api/v1/tool-categories/all"},
		{http.MethodPost, "/api/v1/custom-tool-categories"},
		{http.MethodPut, "/api/v1/custom-tool-categories/" + id},
		{http.MethodDelete, "/api/v1/custom-tool-categories/" + id},
	}
	for _, rt := range removed {
		code, body := h.do(admin, rt.method, rt.path, `{"tool_ids":["`+id+`"]}`)
		ok := code == http.StatusNotFound || code == http.StatusMethodNotAllowed
		// GET /tools/platform and /tool-categories/all now name an id: a
		// malformed one, refused before any lookup.
		if rt.method == http.MethodGet && (rt.path == "/api/v1/tools/platform" || rt.path == "/api/v1/tool-categories/all") {
			ok = code == http.StatusBadRequest
		}
		if !ok {
			t.Errorf("%s %s: %d, want gone: %s", rt.method, rt.path, code, body)
		}
	}
}

// include= conformance: the shared suite, then what is
// specific to tools (secrets in settings, the stats permission).
func TestToolsAPI_IncludeConformance_DB(t *testing.T) {
	h := newToolAvailabilityHarness(t)
	tid, other := h.tenant(), h.tenant()
	admin, otherAdmin := h.member(tid, "admin"), h.member(other, "admin")
	// bare: the catalog read only (scans:tools:read).
	bare := h.member(tid, "member")
	h.customRoleMember(bare, tid, permission.ToolsRead)
	h.mintToken(&bare, tid)
	t.Cleanup(func() {
		ctx := context.Background()
		tenants := "{" + tid + "," + other + "}"
		_, _ = h.db.ExecContext(ctx, `DELETE FROM tenant_tool_configs WHERE tenant_id = ANY($1::uuid[])`, tenants)
		_, _ = h.db.ExecContext(ctx, `DELETE FROM tools WHERE tenant_id = ANY($1::uuid[])`, tenants)
	})
	ours := decodeID(t, h.expect(admin, http.MethodPost, "/api/v1/tools",
		`{"name":"zz-incl-ours","display_name":"Ours","install_method":"binary"}`, http.StatusCreated))
	theirs := decodeID(t, h.expect(otherAdmin, http.MethodPost, "/api/v1/tools",
		`{"name":"zz-incl-theirs","display_name":"Theirs","install_method":"binary"}`, http.StatusCreated))

	includetest.RunConformance(t, includetest.Fixture{
		Registry: handler.ToolIncludes,
		Get: func(t *testing.T, principal, path string) (int, http.Header, string) {
			u := admin
			if principal == includetest.Bare {
				u = bare
			}
			return h.doWithHeaders(u, http.MethodGet, path)
		},
		ListPath:        "/api/v1/tools",
		ItemPath:        "/api/v1/tools/" + ours,
		ForeignItemPath: "/api/v1/tools/" + theirs,
		ItemsKey:        "items",
		AllowedKeys: map[string][]string{
			"settings":     {"is_enabled", "config", "effective_config", "custom_templates", "custom_patterns", "updated_by", "updated_at"},
			"availability": {"enabled", "status", "sensors_online", "sensors_total", "sensors_excluded", "sensors", "versions", "min_reported_version", "max_reported_version", "min_version", "latest_version", "update_available", "content", "last_reported_at"},
			"stats":        {"tool_id", "total_runs", "successful_runs", "failed_runs", "total_findings", "avg_duration_ms"},
		},
	})

	// Settings never take a secret, by key or by value under an innocent key.
	for _, cfg := range []string{
		`{"api_key":"fake-key-Zq8vT3mP0wX7rL2kN9sB4yH6"}`,
		`{"notes":"sk-Zq8vT3mP0wX7rL2kN9sB4yH6aaaa"}`,
		`{"url":"https://user:Zq8vT3mP0wX7@example.com/x"}`,
		`{"headers":{"Authorization":"Bearer Zq8vT3mP0wX7rL2kN9sB4yH6"}}`,
	} {
		h.expect(admin, http.MethodPatch, "/api/v1/tools/"+ours+"/settings", `{"config":`+cfg+`}`, http.StatusBadRequest)
	}
	h.expect(admin, http.MethodPatch, "/api/v1/tools/"+ours+"/settings", `{"config":{"rate_limit":7}}`, http.StatusOK)
	// A row written before the rule is still masked on read.
	h.exec(`UPDATE tenant_tool_configs SET config = '{"rate_limit":7,"token":"fake-key-Zq8vT3mP0wX7rL2kN9sB4yH6"}'::jsonb
	        WHERE tenant_id = $1 AND tool_id = $2`, tid, ours)
	body := h.expect(admin, http.MethodGet, "/api/v1/tools/"+ours+"?include=settings", "", http.StatusOK)
	if strings.Contains(body, "Zq8vT3mP0wX7") || !strings.Contains(body, `"rate_limit":7`) {
		t.Fatalf("settings must mask a stored secret and keep the rest: %s", body)
	}

	// Stats are tenant-wide counts: scans:read as well as tenant tools.
	toolsNoScans := h.member(tid, "member")
	h.customRoleMember(toolsNoScans, tid, permission.ToolsRead, permission.TenantToolsRead)
	h.mintToken(&toolsNoScans, tid)
	var one handler.ToolViewResponse
	mustJSON(t, h.expect(toolsNoScans, http.MethodGet, "/api/v1/tools/"+ours+"?include=settings,stats", "", http.StatusOK), &one)
	if one.Settings == nil || one.Stats != nil || one.Meta == nil || len(one.Meta.OmittedIncludes) != 1 || one.Meta.OmittedIncludes[0] != "stats" {
		t.Fatalf("without scans:read: settings %v stats %v meta %+v", one.Settings != nil, one.Stats, one.Meta)
	}
}

// doWithHeaders is do with the response headers.
func (h *authzPolicyHarness) doWithHeaders(u policyUser, method, path string) (int, http.Header, string) {
	h.t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), method, h.srv.URL+path, nil)
	if err != nil {
		h.t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+u.token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, resp.Header, string(b)
}
