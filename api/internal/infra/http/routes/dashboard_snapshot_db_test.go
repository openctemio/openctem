package routes

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/dashboard/widgets"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/permission"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func (e *widgetEnv) createPersonal(t *testing.T, user shared.ID, admin bool, layout []any) string {
	t.Helper()
	code, body := e.call(user, admin, nil, http.MethodPost, "/api/v1/me/dashboards", map[string]any{"name": "Snap", "layout": layout})
	if code != http.StatusCreated {
		t.Fatalf("create = %d %s", code, body)
	}
	var d struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal([]byte(body), &d)
	return d.ID
}

func (e *widgetEnv) addFinding(t *testing.T, asset shared.ID, title string) {
	t.Helper()
	id := shared.NewID()
	e.h.exec(`INSERT INTO findings (id, tenant_id, asset_id, source, tool_name, message, title, severity, fingerprint, status, priority_class)
		VALUES ($1::uuid, $2, $3, 'sast', 'snap', $4::text, $4::text, 'medium', $1::text, 'confirmed', 'P2')`, id.String(), e.h.tenant.String(), asset.String(), title)
	if _, err := postgres.NewDashboardFactsRepository(&postgres.DB{DB: e.h.db}).RebuildTenant(context.Background(), e.h.tenant, 100); err != nil {
		t.Fatal(err)
	}
}

func openValue(t *testing.T, d dataResp) int64 {
	t.Helper()
	w := byID(t, d, "w_open")
	if w.Scalar == nil {
		t.Fatalf("open widget = %+v", w)
	}
	return w.Scalar.Value
}

// Opening serves the stored snapshot; new data shows after Refresh now (or
// the schedule), Refresh now is budgeted, and a snapshot computed for
// another scope or another layout is never served.
func TestDashboardSnapshots_ServeRefreshBudgetScope_DB(t *testing.T) {
	e := newWidgetEnv(t)
	h := e.h
	layout := []any{metricWidget("w_open", "findings.open", nil)}
	id := e.createPersonal(t, h.memberA, false, layout)
	path := "/api/v1/me/dashboards/" + id

	first := e.data(t, h.memberA, false, nil, path+"/data")
	if openValue(t, first) != 2 || first.RefreshSchedule != "1h" || first.NextRefreshAt == nil || first.Stale {
		t.Fatalf("first open = %+v", first)
	}
	var key string
	if err := h.db.QueryRow(`SELECT scope_key FROM dash_snapshots WHERE dashboard_id = $1`, id).Scan(&key); err != nil || !strings.HasPrefix(key, "restricted:") {
		t.Fatalf("snapshot scope key = %q (%v)", key, err)
	}

	// New data in scope: the open still shows the snapshot.
	e.addFinding(t, h.assetA, "snap-new-A")
	if v := openValue(t, e.data(t, h.memberA, false, nil, path+"/data")); v != 2 {
		t.Errorf("open after new data = %d, want the stored 2", v)
	}
	// Refresh now recomputes; a second one within the minute is refused.
	code, body := e.call(h.memberA, false, nil, http.MethodPost, path+"/refresh", nil)
	if code != http.StatusOK {
		t.Fatalf("refresh = %d %s", code, body)
	}
	var refreshed dataResp
	_ = json.Unmarshal([]byte(body), &refreshed)
	if openValue(t, refreshed) != 3 {
		t.Errorf("after refresh = %d, want 3", openValue(t, refreshed))
	}
	code, _ = e.call(h.memberA, false, nil, http.MethodPost, path+"/refresh", nil)
	if code != http.StatusTooManyRequests {
		t.Errorf("second refresh within a minute = %d, want 429", code)
	}

	// The owner's scope widens: the stored snapshot is not served, the
	// figures follow the new scope at once.
	h.exec(`INSERT INTO user_accessible_assets (user_id, tenant_id, asset_id, ownership_type) VALUES ($1, $2, $3, 'secondary')`,
		h.memberA.String(), h.tenant.String(), h.assetB.String())
	if v := openValue(t, e.data(t, h.memberA, false, nil, path+"/data")); v != 4 {
		t.Errorf("after scope change = %d, want 4 (A1 and B1)", v)
	}
	// And narrows back: the wider snapshot is never served again.
	h.exec(`DELETE FROM user_accessible_assets WHERE user_id = $1 AND tenant_id = $2 AND asset_id = $3`,
		h.memberA.String(), h.tenant.String(), h.assetB.String())
	if v := openValue(t, e.data(t, h.memberA, false, nil, path+"/data")); v != 3 {
		t.Errorf("after scope narrowed = %d, want 3", v)
	}
	// A layout change is computed at once.
	code, _ = e.call(h.memberA, false, nil, http.MethodPut, path, map[string]any{"name": "Snap", "layout": append(layout,
		metricWidget("w_p0", "findings.open", map[string]any{"filter": map[string]any{"priority_class": []string{"P0"}}}))})
	if code != http.StatusOK {
		t.Fatalf("update layout = %d", code)
	}
	if out := e.data(t, h.memberA, false, nil, path+"/data"); len(out.Widgets) != 2 {
		t.Errorf("after layout change = %d widgets", len(out.Widgets))
	}

	// The organization budget: 30 an hour, whoever asks.
	other := e.createPersonal(t, h.owner, true, layout)
	for i := 0; i < 30; i++ {
		h.exec(`INSERT INTO dash_refresh_requests (tenant_id, dashboard_id, user_id) VALUES ($1, $2, $3)`, h.tenant.String(), shared.NewID().String(), shared.NewID().String())
	}
	if code, _ := e.call(h.owner, true, nil, http.MethodPost, "/api/v1/me/dashboards/"+other+"/refresh", nil); code != http.StatusTooManyRequests {
		t.Errorf("refresh over the organization budget = %d, want 429", code)
	}
	// Another person cannot refresh or read my dashboard.
	if code, _ := e.call(e.tester, false, nil, http.MethodPost, path+"/refresh", nil); code != http.StatusNotFound {
		t.Errorf("refresh of another person's dashboard = %d, want 404", code)
	}

	// A failed refresh marks the snapshot stale and keeps the last figures.
	h.exec(`UPDATE dash_snapshots SET last_error = 'failed', failed_at = now() WHERE dashboard_id = $1`, id)
	if out := e.data(t, h.memberA, false, nil, path+"/data"); !out.Stale || out.LastRefreshError != "failed" {
		t.Errorf("after a failed refresh: stale = %v, error = %q", out.Stale, out.LastRefreshError)
	}
}

// One organization snapshot serves every permitted viewer; list rows are
// filtered per viewer on read and the campaign fields never leave the server.
func TestDashboardSnapshots_OrganizationShared_DB(t *testing.T) {
	e := newWidgetEnv(t)
	h := e.h
	view := append(append([]string{}, dsMemberPerms...), permission.DashboardsOrgView.String())
	code, body := e.call(h.owner, true, nil, http.MethodPost, "/api/v1/organization/dashboards",
		map[string]any{"name": "Org", "layout": []any{metricWidget("w_open", "findings.open", nil), metricWidget("w_next", "fix.next", nil)}})
	if code != http.StatusCreated {
		t.Fatalf("create org = %d", code)
	}
	var org struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal([]byte(body), &org)
	path := "/api/v1/organization/dashboards/" + org.ID + "/data"

	for _, tc := range []struct {
		user    shared.ID
		seesPub bool
	}{{e.tester, true}, {h.memberA, false}, {h.memberFull, false}} {
		code, raw := e.call(tc.user, false, view, http.MethodGet, path, nil)
		if code != http.StatusOK {
			t.Fatalf("org data = %d", code)
		}
		if strings.Contains(raw, "campaign_id") || strings.Contains(raw, `"pentest"`) {
			t.Errorf("response carries campaign fields: %s", raw)
		}
		var out dataResp
		_ = json.Unmarshal([]byte(raw), &out)
		if openValue(t, out) != 4 {
			t.Errorf("organization open = %d, want 4", openValue(t, out))
		}
		saw := false
		for _, r := range byID(t, out, "w_next").Items.Rows {
			saw = saw || r.Title == ptPub
		}
		if saw != tc.seesPub {
			t.Errorf("viewer %s sees the campaign finding = %v, want %v", tc.user, saw, tc.seesPub)
		}
	}
	var n int
	_ = h.db.QueryRow(`SELECT count(*) FROM dash_snapshots WHERE dashboard_id = $1 AND scope_key = 'organization'`, org.ID).Scan(&n)
	if n != 1 {
		t.Errorf("organization snapshots = %d, want one shared", n)
	}
	// The stored list keeps the campaign so the rule applies on read.
	var stored string
	_ = h.db.QueryRow(`SELECT data::text FROM dash_snapshots WHERE dashboard_id = $1`, org.ID).Scan(&stored)
	if !strings.Contains(stored, ptPub) || !strings.Contains(stored, "campaign_id") {
		t.Error("stored organization list does not keep the campaign finding with its campaign")
	}
}

// The refresher recomputes due snapshots for their owner as they are now,
// and removes the snapshot of an owner who left.
func TestDashboardSnapshots_Refresher_DB(t *testing.T) {
	e := newWidgetEnv(t)
	h := e.h
	layout := []any{metricWidget("w_open", "findings.open", nil)}
	idA := e.createPersonal(t, h.memberA, false, layout)
	idF := e.createPersonal(t, h.memberFull, false, layout)
	_ = e.data(t, h.memberA, false, nil, "/api/v1/me/dashboards/"+idA+"/data")
	_ = e.data(t, h.memberFull, false, nil, "/api/v1/me/dashboards/"+idF+"/data")
	e.addFinding(t, h.assetA, "snap-refresher")
	h.exec(`UPDATE dash_snapshots SET next_refresh_at = now() - interval '1 minute' WHERE dashboard_id IN ($1, $2)`, idA, idF)
	// memberFull leaves the organization: their snapshot goes, nothing is
	// computed on their behalf.
	h.exec(`DELETE FROM tenant_members WHERE user_id = $1 AND tenant_id = $2`, h.memberFull.String(), h.tenant.String())

	n, err := e.svc.RefreshDue(context.Background(), 10)
	if err != nil || n != 1 {
		t.Fatalf("refreshed = %d, %v (want 1)", n, err)
	}
	var data string
	if err := h.db.QueryRow(`SELECT data::text FROM dash_snapshots WHERE dashboard_id = $1`, idA).Scan(&data); err != nil {
		t.Fatal(err)
	}
	var out dataResp
	_ = json.Unmarshal([]byte(data), &out)
	if openValue(t, out) != 3 {
		t.Errorf("refreshed snapshot = %d, want 3", openValue(t, out))
	}
	var left int
	_ = h.db.QueryRow(`SELECT count(*) FROM dash_snapshots WHERE dashboard_id = $1`, idF).Scan(&left)
	if left != 0 {
		t.Error("the snapshot of a member who left was kept")
	}
	// Nothing else is due.
	if n, _ := e.svc.RefreshDue(context.Background(), 10); n != 0 {
		t.Errorf("second pass refreshed %d", n)
	}
	_ = widgets.StateReady
}
