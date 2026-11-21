package routes

// Saved views of every registered list page (docs/architecture/saved-views.md)
// over the real routes and a migrated database, table-driven over the whole
// page registry: a view is listed, saved and opened only by a member who may
// read the page's list (403 otherwise, the same answer whether or not views
// exist); another member or another organization never reads, changes or
// deletes it (404); a key outside the registry is 400; the caps on the
// number of views and on opaque page params hold.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/openctemio/openctem/server/pkg/domain/permission"
	"github.com/openctemio/openctem/server/pkg/domain/savedview"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
)

// svUnrelatedPerm is held by every test caller, so "no permission of the
// page" never means "no permission at all".
var svUnrelatedPerm = permission.DashboardRead.String()

// svPermsOf is the permission set of a member who may read p's list.
func svPermsOf(p savedview.Page) []string {
	return []string{svUnrelatedPerm, p.Permission.String()}
}

// svPermsWithout is every permission the registry names except p's own.
func svPermsWithout(p savedview.Page) []string {
	out := []string{svUnrelatedPerm, permission.FindingsViewsShare.String()}
	seen := map[string]bool{}
	for _, q := range savedview.Pages() {
		perm := q.Permission.String()
		if perm == p.Permission.String() || seen[perm] {
			continue
		}
		seen[perm] = true
		out = append(out, perm)
	}
	return out
}

// svAllPerms is every permission the registry names.
func svAllPerms() []string {
	return append(svPermsWithout(savedview.Page{}), permission.FindingsViewsShare.String())
}

type svPageResp struct {
	ID         string            `json:"id"`
	Page       string            `json:"page"`
	Name       string            `json:"name"`
	PageParams map[string]string `json:"page_params"`
	Filter     json.RawMessage   `json:"filter"`
}

func svListIDs(t *testing.T, raw string) map[string]bool {
	t.Helper()
	var out struct {
		Data []svPageResp `json:"data"`
	}
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		t.Fatalf("list body: %v: %s", err, raw)
	}
	ids := make(map[string]bool, len(out.Data))
	for _, v := range out.Data {
		ids[v.ID] = true
	}
	return ids
}

func svOtherTenant(t *testing.T, h *gsHarness) string {
	t.Helper()
	other := shared.NewID()
	h.exec(`INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $2)`, other.String(), "svp-"+other.String())
	t.Cleanup(func() {
		_, _ = h.db.ExecContext(context.Background(), `DELETE FROM tenants WHERE id = $1`, other.String())
	})
	return other.String()
}

func TestSavedViewPages_EveryRegisteredPage_PermissionAndIsolation(t *testing.T) {
	h := newGroupScopeHarness(t)
	ten := h.tenant.String()
	other := svOtherTenant(t, h)
	pages := savedview.Pages()
	if len(pages) < 50 {
		t.Fatalf("page registry has %d pages; the list pages are missing", len(pages))
	}

	for _, p := range pages {
		t.Run(p.Key, func(t *testing.T) {
			const secret = "Payroll-Exposure-Watch"
			listPath := "/api/v1/views?page=" + url.QueryEscape(p.Key)
			body := map[string]any{"page": p.Key, "name": secret + " " + p.Key}
			// The harness wires a filter registry for findings only: every
			// other page keeps its state as opaque page params.
			opaque := p.Key != savedview.PageFindings
			if opaque {
				body["page_params"] = map[string]string{"status": "open,triaged", "sort": "-created_at", "q": "payroll"}
			}
			may := svPermsOf(p)

			status, raw := h.doAs(h.memberA, ten, may, http.MethodPost, "/api/v1/views", body)
			if status != http.StatusCreated {
				t.Fatalf("create with the page's permission = %d, want 201 (%s)", status, raw)
			}
			var v svPageResp
			if err := json.Unmarshal([]byte(raw), &v); err != nil || v.ID == "" || v.Page != p.Key {
				t.Fatalf("create body: %v %s", err, raw)
			}
			if opaque && (v.PageParams["status"] != "open,triaged" || v.PageParams["sort"] != "-created_at" || string(v.Filter) != "{}") {
				t.Errorf("stored state = %v filter %s, want the page params as sent and an empty filter", v.PageParams, v.Filter)
			}
			path := "/api/v1/views/" + v.ID
			digest := h.viewRowDigest(v.ID)

			// The owner lists and opens it.
			if status, raw := h.doAs(h.memberA, ten, may, http.MethodGet, listPath, nil); status != http.StatusOK || !svListIDs(t, raw)[v.ID] {
				t.Errorf("owner list = %d, view listed %v", status, svListIDs(t, raw)[v.ID])
			}
			if status, raw := h.doAs(h.memberA, ten, may, http.MethodGet, path, nil); status != http.StatusOK {
				t.Errorf("owner get = %d (%s)", status, raw)
			}

			// Without the page's read permission (holding every other one):
			// the key answers 403, to the owner and to anyone else, and by id
			// the view does not exist. The 403 is the same in an organization
			// that has no views at all.
			without := svPermsWithout(p)
			for _, caller := range []shared.ID{h.memberA, h.memberFree} {
				status, denied := h.doAs(caller, ten, without, http.MethodGet, listPath, nil)
				if status != http.StatusForbidden {
					t.Errorf("list without %s = %d, want 403 (%s)", p.Permission, status, denied)
				}
				if !strings.Contains(denied, p.Permission.String()) {
					t.Errorf("403 does not name the missing permission %s: %s", p.Permission, denied)
				}
				assertNoViewLeak(t, "list without the permission", denied, h.memberA, secret, v.ID)
				_, empty := h.doAs(caller, other, without, http.MethodGet, listPath, nil)
				if empty != denied {
					t.Errorf("the 403 differs between an organization with views and one without:\n%s\n%s", denied, empty)
				}
				if status, raw := h.doAs(caller, ten, without, http.MethodPost, "/api/v1/views", body); status != http.StatusForbidden {
					t.Errorf("create without %s = %d, want 403 (%s)", p.Permission, status, raw)
				}
				for _, req := range svWriteRequests() {
					status, raw := h.doAs(caller, ten, without, req.method, path, req.body)
					if status != http.StatusNotFound {
						t.Errorf("%s by id without %s = %d, want 404 (%s)", req.method, p.Permission, status, raw)
					}
					assertNoViewLeak(t, req.method+" without the permission", raw, h.memberA, secret)
				}
			}

			// Another member of the organization who may read the list: the
			// personal view is not theirs to see.
			if status, raw := h.doAs(h.memberFree, ten, may, http.MethodGet, listPath, nil); status != http.StatusOK || svListIDs(t, raw)[v.ID] {
				t.Errorf("another member's list = %d, lists the personal view %v", status, svListIDs(t, raw)[v.ID])
			}
			// Another organization, with every permission, as the same person
			// and as a stranger.
			all := svAllPerms()
			for _, caller := range []shared.ID{h.memberA, shared.NewID()} {
				status, raw := h.doAs(caller, other, all, http.MethodGet, listPath, nil)
				if status != http.StatusOK || svListIDs(t, raw)[v.ID] {
					t.Errorf("another organization's list = %d, lists the view %v", status, svListIDs(t, raw)[v.ID])
				}
				assertNoViewLeak(t, "cross-organization list", raw, h.memberA, secret)
			}
			for _, c := range []struct {
				user   shared.ID
				tenant string
			}{{h.memberFree, ten}, {h.memberA, other}, {shared.NewID(), other}} {
				for _, req := range svWriteRequests() {
					status, raw := h.doAs(c.user, c.tenant, all, req.method, path, req.body)
					if status != http.StatusNotFound {
						t.Errorf("%s by a caller who may not see the view = %d, want 404 (%s)", req.method, status, raw)
					}
					assertNoViewLeak(t, req.method+" by a caller who may not see the view", raw, h.memberA, secret)
				}
			}
			if h.viewRowDigest(v.ID) != digest {
				t.Fatal("the view changed under a refused request")
			}

			// The owner updates and deletes it.
			body["name"] = "renamed " + p.Key
			if status, raw := h.doAs(h.memberA, ten, may, http.MethodPut, path, body); status != http.StatusOK || !strings.Contains(raw, "renamed") {
				t.Errorf("owner update = %d (%s)", status, raw)
			}
			if status, raw := h.doAs(h.memberA, ten, may, http.MethodDelete, path, nil); status != http.StatusNoContent {
				t.Errorf("owner delete = %d (%s)", status, raw)
			}
		})
	}
}

func TestSavedViewPages_UnknownKeyIsBadRequest(t *testing.T) {
	h := newGroupScopeHarness(t)
	ten := h.tenant.String()
	for _, key := range []string{"nope", "Findings", "findings ", "scans.nope", "findings/../assets", "console:users", "my-work", strings.Repeat("a", 65)} {
		// A member who may read some list: the key itself is refused. A
		// member who may read no list that has views stops at the route.
		for want, perms := range map[int][]string{http.StatusBadRequest: svAllPerms(), http.StatusForbidden: {svUnrelatedPerm}} {
			status, raw := h.doAs(h.memberA, ten, perms, http.MethodGet, "/api/v1/views?page="+url.QueryEscape(key), nil)
			if status != want {
				t.Errorf("list of unknown key %q = %d, want %d (%s)", key, status, want, raw)
			}
			status, raw = h.doAs(h.memberA, ten, perms, http.MethodPost, "/api/v1/views", map[string]any{"page": key, "name": "x"})
			if status != want {
				t.Errorf("create with unknown key %q = %d, want %d (%s)", key, status, want, raw)
			}
		}
	}
	var n int
	if err := h.db.QueryRowContext(context.Background(), `SELECT COUNT(*) FROM saved_views WHERE tenant_id = $1`, ten).Scan(&n); err != nil || n != 0 {
		t.Errorf("views stored under unknown keys: %d (%v)", n, err)
	}
}

// svSeedViews stores n views of one page for a member, straight in the table.
func (h *gsHarness) svSeedViews(user shared.ID, page string, n int) {
	h.t.Helper()
	h.exec(`INSERT INTO saved_views (id, tenant_id, owner_id, page, name)
		SELECT gen_random_uuid(), $1, $2, $3, 'seed ' || i FROM generate_series(1, $4::int) i`,
		h.tenant.String(), user.String(), page, n)
}

func TestSavedViewPages_CapsPerPersonAndPerPage(t *testing.T) {
	h := newGroupScopeHarness(t)
	ten := h.tenant.String()
	all := svAllPerms()
	create := func(user shared.ID, page string) (int, string) {
		return h.doAs(user, ten, all, http.MethodPost, "/api/v1/views", map[string]any{"page": page, "name": "one more"})
	}

	// One page: MaxPerOwnerPerPage views, then 409; another page still saves.
	h.svSeedViews(h.memberA, "scans", savedview.MaxPerOwnerPerPage-1)
	if status, raw := create(h.memberA, "scans"); status != http.StatusCreated {
		t.Fatalf("view %d of a page = %d, want 201 (%s)", savedview.MaxPerOwnerPerPage, status, raw)
	}
	if status, raw := create(h.memberA, "scans"); status != http.StatusConflict {
		t.Errorf("view %d of a page = %d, want 409 (%s)", savedview.MaxPerOwnerPerPage+1, status, raw)
	}
	if status, raw := create(h.memberA, "scans.runs"); status != http.StatusCreated {
		t.Errorf("a view of another page = %d, want 201 (%s)", status, raw)
	}
	// Another member is not counted with them.
	if status, raw := create(h.memberFree, "scans"); status != http.StatusCreated {
		t.Errorf("another member's view of the full page = %d, want 201 (%s)", status, raw)
	}

	// One person: MaxPerOwner views over all pages, then 409 on any page.
	var have int
	if err := h.db.QueryRowContext(context.Background(), `SELECT COUNT(*) FROM saved_views WHERE tenant_id = $1 AND owner_id = $2`,
		ten, h.memberA.String()).Scan(&have); err != nil {
		t.Fatal(err)
	}
	h.svSeedViews(h.memberA, "sensors", savedview.MaxPerOwner-have)
	if status, raw := create(h.memberA, "components"); status != http.StatusConflict {
		t.Errorf("view %d of a person = %d, want 409 (%s)", savedview.MaxPerOwner+1, status, raw)
	}
}

func TestSavedViewPages_OpaquePageParamsAreBoundedText(t *testing.T) {
	h := newGroupScopeHarness(t)
	ten := h.tenant.String()
	all := svAllPerms()
	create := func(body map[string]any) (int, string) {
		body["page"] = "scans.runs"
		if _, ok := body["name"]; !ok {
			body["name"] = "runs"
		}
		return h.doAs(h.memberA, ten, all, http.MethodPost, "/api/v1/views", body)
	}
	params := func(n int, valueLen int) map[string]string {
		out := make(map[string]string, n)
		for i := range n {
			out["p"+string(rune('a'+i/26))+string(rune('a'+i%26))] = strings.Repeat("v", valueLen)
		}
		return out
	}

	for name, body := range map[string]map[string]any{
		"too many params":       {"page_params": params(savedview.MaxStateParams+1, 1)},
		"value too long":        {"page_params": map[string]string{"q": strings.Repeat("v", savedview.MaxStateParamValueLen+1)}},
		"too many bytes":        {"page_params": params(4, savedview.MaxStateParamValueLen)},
		"bad param name":        {"page_params": map[string]string{"Status": "open"}},
		"param name with space": {"page_params": map[string]string{"a b": "open"}},
		"control character":     {"page_params": map[string]string{"q": "a\x00b"}},
		"a filter document":     {"filter": map[string]any{"severity": map[string]any{"in": []string{"high"}}}},
		"a flat query":          {"query": "status=open"},
		"group_by":              {"group_by": "severity"},
		"unknown body field":    {"sql": "select 1"},
	} {
		if status, raw := create(body); status != http.StatusBadRequest {
			t.Errorf("%s = %d, want 400 (%s)", name, status, raw)
		}
	}

	// The largest state the service accepts fits the table's own check.
	full := params(savedview.MaxStateParams, savedview.MaxStateParamsBytes/savedview.MaxStateParams-3)
	status, raw := create(map[string]any{"page_params": full})
	if status != http.StatusCreated {
		t.Fatalf("the largest allowed page_params = %d, want 201 (%s)", status, raw)
	}

	// Text in, the same text out: markup and filter-looking values are kept
	// verbatim as JSON strings and never run.
	const markup = `<img src=x onerror=alert(1)>`
	state := map[string]string{"q": `'; DROP TABLE saved_views; --`, "sort": markup}
	status, raw = create(map[string]any{"name": markup, "page_params": state, "columns": []string{"name", "status"}, "density": "compact"})
	if status != http.StatusCreated {
		t.Fatalf("create = %d (%s)", status, raw)
	}
	var v svPageResp
	_ = json.Unmarshal([]byte(raw), &v)
	if v.Name != markup || v.PageParams["q"] != state["q"] || v.PageParams["sort"] != markup {
		t.Errorf("stored text changed: %+v", v)
	}
	// A view of a page with opaque state does not run on a list endpoint.
	if status, raw := h.doAs(h.memberA, ten, all, http.MethodGet, "/api/v1/findings?view="+v.ID, nil); status != http.StatusNotFound {
		t.Errorf("findings list with a view of another page = %d, want 404 (%.200s)", status, raw)
	}
	// Duplicating keeps the state.
	status, raw = h.doAs(h.memberFree, ten, all, http.MethodPost, "/api/v1/views", map[string]any{"from_view_id": v.ID, "name": "mine"})
	if status != http.StatusNotFound {
		t.Errorf("duplicating another member's personal view = %d, want 404 (%s)", status, raw)
	}
	status, raw = h.doAs(h.memberA, ten, all, http.MethodPost, "/api/v1/views", map[string]any{"from_view_id": v.ID, "name": "copy"})
	var dup svPageResp
	_ = json.Unmarshal([]byte(raw), &dup)
	if status != http.StatusCreated || dup.Page != "scans.runs" || dup.PageParams["sort"] != markup {
		t.Errorf("duplicate = %d %+v (%s)", status, dup, raw)
	}
}
