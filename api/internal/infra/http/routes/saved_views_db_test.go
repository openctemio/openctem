package routes

// Saved views (D15, RFC-048 §3.6) over the real routes and a migrated
// database: a view is visible to its owner and to members of the group it is
// shared with, never to anyone else or another tenant; only the owner edits
// or deletes it (A1); it runs as the person using it (A5), so sharing a view
// shares a query, not rows; its stored filter is validated on save and again
// on every run; changes are audit-logged.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"

	savedviewapp "github.com/openctemio/openctem/api/internal/app/savedview"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

type svResp struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	IsOwner bool   `json:"is_owner"`
	GroupID string `json:"group_id"`
}

func (h *gsHarness) createView(t *testing.T, user shared.ID, body map[string]any) (int, svResp, string) {
	t.Helper()
	status, raw := h.do(user, false, http.MethodPost, "/api/v1/views", body)
	var v svResp
	_ = json.Unmarshal([]byte(raw), &v)
	return status, v, raw
}

func (h *gsHarness) listViews(t *testing.T, user shared.ID) []svResp {
	t.Helper()
	status, raw := h.do(user, false, http.MethodGet, "/api/v1/views?page=findings", nil)
	if status != http.StatusOK {
		t.Fatalf("list views: %d %s", status, raw)
	}
	var out struct {
		Data []svResp `json:"data"`
	}
	_ = json.Unmarshal([]byte(raw), &out)
	return out.Data
}

func TestSavedViews_VisibilityOwnershipAndRunAsViewer(t *testing.T) {
	h := newGroupScopeHarness(t)
	ten := h.tenant.String()
	team, otherTeam := shared.NewID(), shared.NewID()
	h.exec(`INSERT INTO groups (id, tenant_id, name, slug, group_type) VALUES ($1, $2, 'sv-team', $3, 'team')`, team.String(), ten, "sv-"+team.String())
	h.exec(`INSERT INTO groups (id, tenant_id, name, slug, group_type) VALUES ($1, $2, 'sv-other', $3, 'team')`, otherTeam.String(), ten, "sv-"+otherTeam.String())
	h.exec(`INSERT INTO group_members (group_id, user_id) VALUES ($1, $2), ($1, $3), ($1, $4)`, team.String(), h.memberA.String(), h.memberFree.String(), h.memberFull.String())

	// A personal view and a team view, both "SAST findings".
	status, personal, raw := h.createView(t, h.memberA, map[string]any{"page": "findings", "name": "My SAST", "query": "source=sast&sort=-severity"})
	if status != http.StatusCreated || !personal.IsOwner {
		t.Fatalf("create personal: %d %s", status, raw)
	}
	status, shared1, raw := h.createView(t, h.memberA, map[string]any{"page": "findings", "name": "Team SAST",
		"filter": map[string]any{"v": 1, "filter": map[string]any{"source": []string{"sast"}}}, "group_id": team.String()})
	if status != http.StatusCreated || shared1.GroupID != team.String() {
		t.Fatalf("create shared: %d %s", status, raw)
	}

	// Visibility: owner sees both; a team member sees the team view only; a
	// member outside the team, and the owner of the org, see neither.
	names := func(vs []svResp) string {
		var n []string
		for _, v := range vs {
			n = append(n, v.Name)
		}
		return strings.Join(n, ",")
	}
	if got := names(h.listViews(t, h.memberA)); got != "My SAST,Team SAST" {
		t.Errorf("memberA views = %s", got)
	}
	if got := names(h.listViews(t, h.memberFree)); got != "Team SAST" {
		t.Errorf("team member views = %s", got)
	}
	if got := names(h.listViews(t, h.memberStrict)); got != "" {
		t.Errorf("non-member sees %s", got)
	}
	for _, u := range []shared.ID{h.memberStrict, h.memberFree} {
		if status, _ := h.do(u, false, http.MethodGet, "/api/v1/views/"+personal.ID, nil); status != http.StatusNotFound {
			t.Errorf("another user read a personal view: %d", status)
		}
	}

	// A1: only the owner edits or deletes; others duplicate.
	if status, _ := h.do(h.memberFree, false, http.MethodPut, "/api/v1/views/"+shared1.ID, map[string]any{"name": "hijack", "query": ""}); status != http.StatusForbidden {
		t.Errorf("team member edited a shared view: %d", status)
	}
	if status, _ := h.do(h.memberFree, false, http.MethodDelete, "/api/v1/views/"+shared1.ID, nil); status != http.StatusForbidden {
		t.Errorf("team member deleted a shared view: %d", status)
	}
	status, raw = h.do(h.memberFree, false, http.MethodPost, "/api/v1/views", map[string]any{"from_view_id": shared1.ID})
	var dup svResp
	_ = json.Unmarshal([]byte(raw), &dup)
	if status != http.StatusCreated || !dup.IsOwner || dup.GroupID != "" || dup.Name != "Copy of Team SAST" {
		t.Errorf("duplicate: %d %s", status, raw)
	}
	if status, _ := h.do(h.memberStrict, false, http.MethodPost, "/api/v1/views", map[string]any{"from_view_id": personal.ID}); status != http.StatusNotFound {
		t.Errorf("duplicated a view the caller cannot see: %d", status)
	}

	// Sharing needs membership of an active group of this tenant.
	for name, gid := range map[string]string{"not a member": otherTeam.String(), "no such group": shared.NewID().String()} {
		if status, _, raw := h.createView(t, h.memberA, map[string]any{"page": "findings", "name": "x", "query": "", "group_id": gid}); status != http.StatusBadRequest {
			t.Errorf("share with %s: %d %s", name, status, raw)
		}
	}

	// A5: the shared view runs as the viewer. memberA (scope A1) gets FA;
	// memberFull (full-data role) gets FA and FB2 from the same view; memberFree
	// (team member, no scope row) gets nothing.
	run := func(c flCaller, extra string) ([]string, int) {
		status, _, body := h.listFindingsPath(t, c, "/api/v1/findings?view="+url.QueryEscape(shared1.ID)+extra)
		if status != http.StatusOK {
			return nil, status
		}
		var out flResponse
		_ = json.Unmarshal([]byte(body), &out)
		ids := make([]string, 0, len(out.Data))
		for _, d := range out.Data {
			ids = append(ids, d.ID)
		}
		return sorted(ids...), status
	}
	fa, fb2 := h.findingA.String(), h.findingB2.String()
	if ids, _ := run(flCaller{"memberA", h.memberA, false}, ""); strings.Join(ids, ",") != fa {
		t.Errorf("memberA via view = %v", ids)
	}
	if ids, _ := run(flCaller{"full", h.memberFull, false}, ""); strings.Join(ids, ",") != strings.Join(sorted(fa, fb2), ",") {
		t.Errorf("full-data team member via view = %v", ids)
	}
	if ids, status := run(flCaller{"free", h.memberFree, false}, ""); status != http.StatusOK || len(ids) != 0 {
		t.Errorf("scopeless team member via view = %v (%d), want nothing", ids, status)
	}
	// Explicit params override the view field by field: source=dast replaces sast.
	if ids, _ := run(flCaller{"full", h.memberFull, false}, "&source=dast"); strings.Join(ids, ",") != h.findingB.String() {
		t.Errorf("override = %v", ids)
	}
	// Stats and groups follow the view too.
	if n := h.statsTotal(t, flCaller{"memberA", h.memberA, false}, "view="+shared1.ID); n != 1 {
		t.Errorf("stats via view = %d", n)
	}
	// A view the caller may not see is not found.
	if _, status := run(flCaller{"strict", h.memberStrict, false}, ""); status != http.StatusNotFound {
		t.Errorf("non-member ran the team view: %d", status)
	}

	// Validated on save; and again on every run (the registry may change).
	if status, _, raw := h.createView(t, h.memberA, map[string]any{"page": "findings", "name": "bad", "query": "severity=urgent"}); status != http.StatusBadRequest || !strings.Contains(raw, "INVALID_FILTER") {
		t.Errorf("invalid filter saved: %d %s", status, raw)
	}
	if status, _, raw := h.createView(t, h.memberA, map[string]any{"page": "assets", "name": "x"}); status != http.StatusNotFound {
		t.Errorf("unknown page: %d %s", status, raw)
	}
	h.exec(`UPDATE saved_views SET filter = '{"filter":{"field":"retired_field","op":"in","value":["x"]}}' WHERE id = $1`, personal.ID)
	if _, status := runView(t, h, personal.ID); status != http.StatusBadRequest {
		t.Errorf("a stale stored filter ran: %d", status)
	}

	// Another tenant's user never sees or runs the views.
	other := shared.NewID()
	h.exec(`INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $2)`, other.String(), "sv-"+other.String())
	t.Cleanup(func() {
		_, _ = h.db.ExecContext(context.Background(), `DELETE FROM tenants WHERE id = $1`, other.String())
	})
	all := func(string) bool { return true }
	foreign := savedviewapp.Caller{TenantID: other, UserID: h.memberA, Has: all}
	vid, _ := shared.IDFromString(shared1.ID)
	if _, err := h.views.Get(context.Background(), foreign, vid); !savedviewapp.IsNotFound(err) {
		t.Errorf("a view was found from another tenant: %v", err)
	}
	if vs, err := h.views.List(context.Background(), foreign, "findings"); err != nil || len(vs) != 0 {
		t.Errorf("another tenant listed %d views (%v)", len(vs), err)
	}
	if _, err := h.views.Update(context.Background(), foreign, vid, savedviewapp.Input{Name: "x"}); !savedviewapp.IsNotFound(err) {
		t.Errorf("a view was updated from another tenant: %v", err)
	}

	// Owner deletes; audit rows exist for create, update and delete.
	if status, raw := h.do(h.memberA, false, http.MethodPut, "/api/v1/views/"+shared1.ID, map[string]any{"name": "Team SAST v2", "query": "source=sast", "group_id": team.String()}); status != http.StatusOK {
		t.Errorf("owner update: %d %s", status, raw)
	}
	if status, _ := h.do(h.memberA, false, http.MethodDelete, "/api/v1/views/"+shared1.ID, nil); status != http.StatusNoContent {
		t.Errorf("owner delete: %d", status)
	}
	var audits int
	_ = h.db.QueryRow(`SELECT COUNT(*) FROM audit_logs WHERE tenant_id = $1 AND action LIKE 'saved_view.%' AND resource_id = $2`, ten, shared1.ID).Scan(&audits)
	if audits != 3 {
		t.Errorf("audit rows for the shared view = %d, want 3", audits)
	}
}

func runView(t *testing.T, h *gsHarness, id string) (string, int) {
	t.Helper()
	status, _, body := h.listFindingsPath(t, flCaller{"memberA", h.memberA, false}, "/api/v1/findings?view="+id)
	return body, status
}
