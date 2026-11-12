package routes

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// A pentest finding without a campaign is not counted for a reader outside
// every campaign in the day-table trends (new versus fixed), the same as in
// the current counts; organization-wide and administrator reads count it.
func TestDashboardFacts_PentestWithoutCampaign_DB(t *testing.T) {
	e := newWidgetEnv(t)
	h := e.h
	for _, st := range []string{"confirmed", "resolved"} {
		id := shared.NewID()
		h.exec(`INSERT INTO findings (id, tenant_id, asset_id, source, tool_name, message, title, severity, fingerprint, status, priority_class, resolved_at)
			VALUES ($1::uuid, $2, $3, 'pentest', 'pt', 'pt-nocamp', 'pt-nocamp', 'high', $1::text, $4::text, 'P1',
			        CASE WHEN $4::text = 'resolved' THEN now() END)`, id.String(), h.tenant.String(), h.assetB.String(), st)
	}
	if _, err := postgres.NewDashboardFactsRepository(&postgres.DB{DB: h.db}).RebuildTenant(context.Background(), h.tenant, 100); err != nil {
		t.Fatal(err)
	}
	layout := []any{metricWidget("w_open", "findings.open", nil), metricWidget("w_flow", "flow.new_vs_fixed", nil)}
	for _, tc := range []struct {
		name         string
		user         shared.ID
		admin        bool
		open, opened int64
		fixed        int64
	}{
		// Base data: A1, A2 (one a campaign finding), B1 and the campaign
		// finding; see newPtEnv.
		{"full-data non-member", h.memberFull, false, 3, 3, 0},
		{"campaign tester (another campaign)", e.tester, false, 3, 3, 0},
		{"administrator", h.owner, true, 5, 6, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			id := e.createPersonal(t, tc.user, tc.admin, layout)
			out := e.data(t, tc.user, tc.admin, nil, "/api/v1/me/dashboards/"+id+"/data")
			if v := openValue(t, out); v != tc.open {
				t.Errorf("open = %d, want %d", v, tc.open)
			}
			flow := byID(t, out, "w_flow")
			if flow.Series == nil || flow.Series.Totals["opened"] != tc.opened || flow.Series.Totals["fixed"] != tc.fixed {
				t.Errorf("new vs fixed = %+v, want opened %d fixed %d", flow.Series, tc.opened, tc.fixed)
			}
		})
	}
}

// One Refresh now per dashboard at a time: while a refresh holds the
// dashboard's lock another is refused with 429 and does not use the budget;
// a refresh that cannot compute gives its budget back.
func TestDashboardRefresh_OneInFlightAndRefund_DB(t *testing.T) {
	e := newWidgetEnv(t)
	h := e.h
	ctx := context.Background()
	repo := postgres.NewDashboardSnapshotRepository(&postgres.DB{DB: h.db})
	id := e.createPersonal(t, h.memberA, false, []any{metricWidget("w_open", "findings.open", nil)})
	did := shared.MustIDFromString(id)
	path := "/api/v1/me/dashboards/" + id + "/refresh"
	requests := func() int {
		var n int
		_ = h.db.QueryRow(`SELECT count(*) FROM dash_refresh_requests WHERE dashboard_id = $1`, id).Scan(&n)
		return n
	}

	release, ok, err := repo.TryRefreshLock(ctx, h.tenant, did)
	if err != nil || !ok {
		t.Fatalf("take lock = %v, %v", ok, err)
	}
	if _, again, _ := repo.TryRefreshLock(ctx, h.tenant, did); again {
		t.Fatal("a second holder took the same dashboard's lock")
	}
	if code, body := e.call(h.memberA, false, nil, http.MethodPost, path, nil); code != http.StatusTooManyRequests {
		t.Fatalf("refresh while one runs = %d %s, want 429", code, body)
	}
	if n := requests(); n != 0 {
		t.Errorf("a refused refresh used the budget (%d requests)", n)
	}
	// Another dashboard is not blocked.
	code, resp := e.call(h.memberA, false, nil, http.MethodPost, "/api/v1/me/dashboards",
		map[string]any{"name": "Snap 2", "layout": []any{metricWidget("w_open", "findings.open", nil)}})
	if code != http.StatusCreated {
		t.Fatalf("create second = %d %s", code, resp)
	}
	var od struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal([]byte(resp), &od)
	other := od.ID
	if code, _ := e.call(h.memberA, false, nil, http.MethodPost, "/api/v1/me/dashboards/"+other+"/refresh", nil); code != http.StatusOK {
		t.Errorf("refresh of another dashboard = %d, want 200", code)
	}
	release()
	release() // idempotent
	if code, body := e.call(h.memberA, false, nil, http.MethodPost, path, nil); code != http.StatusOK {
		t.Fatalf("refresh after the lock is free = %d %s", code, body)
	}
	if n := requests(); n != 1 {
		t.Errorf("requests after one refresh = %d, want 1", n)
	}

	// Refund gives back only this person's newest request on this dashboard.
	if err := repo.RefundRefreshBudget(ctx, h.tenant, did, h.owner); err != nil {
		t.Fatal(err)
	}
	if n := requests(); n != 1 {
		t.Errorf("refund by another person removed a request (%d left)", n)
	}
	if err := repo.RefundRefreshBudget(ctx, h.tenant, did, h.memberA); err != nil {
		t.Fatal(err)
	}
	if n := requests(); n != 0 {
		t.Errorf("after refund = %d requests, want 0", n)
	}
	if ok, _, err := repo.TakeRefreshBudget(ctx, h.tenant, did, h.memberA); err != nil || !ok {
		t.Errorf("budget after refund = %v, %v; want available", ok, err)
	}
}

// Widget previews are limited per person: a burst, then 429 with
// Retry-After; another person is not affected.
func TestDashboardPreview_RateLimitedPerUser_DB(t *testing.T) {
	e := newWidgetEnv(t)
	h := e.h
	body := map[string]any{"widget_type": "metric", "config": metricWidget("w_p", "findings.open", nil)["config"]}
	limited := false
	for i := 0; i < 40 && !limited; i++ {
		code, resp := e.call(h.memberA, false, nil, http.MethodPost, "/api/v1/me/dashboards/widget-preview", body)
		switch code {
		case http.StatusOK:
		case http.StatusTooManyRequests:
			limited = true
			if i < 24 {
				t.Errorf("limited after %d previews, want a burst of 24", i)
			}
		default:
			t.Fatalf("preview = %d %s", code, resp)
		}
	}
	if !limited {
		t.Fatal("40 previews in a row were never limited")
	}
	if code, resp := e.call(h.memberFull, false, nil, http.MethodPost, "/api/v1/me/dashboards/widget-preview", body); code != http.StatusOK {
		t.Errorf("another person's preview = %d %s", code, resp)
	}
}
