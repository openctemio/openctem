package routes

// RFC-056 P1: the change feed is written with each change, the retention
// sweep marks unseen endpoints gone and purges old ones, and the grouped
// views (path patterns, origins with the coverage gap) and the feed count
// only what the caller may see, within one tenant.

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/ctis"

	"github.com/openctemio/openctem/api/internal/app/ingest"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/webendpoint"
)

func TestWebEndpointEventsAndRetention_DB(t *testing.T) {
	h, agt := newWebEndpointHarness(t)
	ctx := context.Background()
	cmd := shared.NewID()
	bound := ingest.Options{Binding: ingest.Binding{Kind: ingest.BindingCommand, CommandID: &cmd,
		Targets: []string{"https://ev.web-p1.test"}, Tool: "katana"}}
	report := func(status int, auth ctis.EndpointAuth, params ...string) *ctis.Report {
		ep := ctis.Endpoint{Origin: "https://ev.web-p1.test", Method: "GET", Path: "/actuator/env", StatusCode: status, Auth: auth}
		for _, p := range params {
			ep.Params = append(ep.Params, ctis.EndpointParam{Location: ctis.ParamLocationQuery, Name: p})
		}
		return &ctis.Report{Version: "1.0", Metadata: ctis.ReportMetadata{ID: "ev"}, Tool: &ctis.Tool{Name: "katana"},
			Endpoints: []ctis.Endpoint{ep}}
	}
	kinds := func() []string {
		rows, err := h.db.Query(`SELECT kind FROM web_endpoint_events WHERE tenant_id = $1 ORDER BY at, kind`, h.tenantID)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = rows.Close() }()
		var out []string
		for rows.Next() {
			var k string
			if err := rows.Scan(&k); err != nil {
				t.Fatal(err)
			}
			out = append(out, k)
		}
		if err := rows.Err(); err != nil {
			t.Fatal(err)
		}
		return out
	}

	if _, err := h.ingest.Ingest(ctx, agt, ingest.Input{Report: report(401, ctis.EndpointAuthRequired)}); err != nil {
		t.Fatal(err)
	}
	var catalog string
	if err := h.db.QueryRow(`SELECT COALESCE(catalog_key, '') FROM web_endpoints WHERE tenant_id = $1`, h.tenantID).Scan(&catalog); err != nil || catalog != "spring.actuator.env" {
		t.Fatalf("catalog_key = %q %v", catalog, err)
	}
	// The same endpoint answers 200 without authentication, with a new
	// parameter: three events.
	if _, err := h.ingest.Ingest(ctx, agt, ingest.Input{Report: report(200, ctis.EndpointAuthNone, "debug"), Options: bound}); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(kinds(), ","); got != "appeared,auth_changed,param_added,status_changed" {
		t.Fatalf("events = %s", got)
	}

	// Retention: unseen 31 days -> gone (with an event); seen again ->
	// returned; gone for a year -> purged with its params and events.
	repo := postgres.NewWebEndpointRepository(&postgres.DB{DB: h.db})
	if _, err := h.db.Exec(`UPDATE web_endpoints SET last_seen_at = now() - interval '31 days' WHERE tenant_id = $1`, h.tenantID); err != nil {
		t.Fatal(err)
	}
	if n, err := repo.MarkGone(ctx, time.Now().Add(-webendpoint.GoneAfter), 1000); err != nil || n < 1 {
		t.Fatalf("MarkGone = %d %v", n, err)
	}
	if _, err := h.ingest.Ingest(ctx, agt, ingest.Input{Report: report(200, ctis.EndpointAuthNone, "debug"), Options: bound}); err != nil {
		t.Fatal(err)
	}
	got := kinds()
	if got[len(got)-2] != "gone" && got[len(got)-1] != "gone" || !strings.Contains(strings.Join(got, ","), "returned") {
		t.Fatalf("events after gone and back = %v", got)
	}
	if _, err := h.db.Exec(`UPDATE web_endpoints SET state = 'gone', last_seen_at = now() - interval '400 days' WHERE tenant_id = $1`, h.tenantID); err != nil {
		t.Fatal(err)
	}
	if n, err := repo.PurgeGone(ctx, time.Now().Add(-webendpoint.PurgeAfter), 1000); err != nil || n < 1 {
		t.Fatalf("PurgeGone = %d %v", n, err)
	}
	if n := scalar(t, h.db, `SELECT count(*) FROM web_endpoint_events WHERE tenant_id = $1`, h.tenantID) +
		scalar(t, h.db, `SELECT count(*) FROM web_endpoint_params WHERE tenant_id = $1`, h.tenantID); n != 0 {
		t.Fatalf("%d params/events left after the purge", n)
	}
	if _, err := repo.DeleteEventsBefore(ctx, time.Now(), 10); err != nil {
		t.Fatal(err)
	}
}

func TestWebSurfaceViews_DataScopeAndTenant_DB(t *testing.T) {
	h := newDSHarness(t)
	s := h.seedWebEndpoints()
	// A sensitive endpoint on each origin, and a change event on each.
	h.exec(`UPDATE web_endpoints SET catalog_key = 'admin.admin', auth_state = 'none', last_status = 200 WHERE id = ANY($1::uuid[])`,
		"{"+s.epA.String()+","+s.epB.String()+"}")
	for _, ep := range []struct{ id, asset shared.ID }{{s.epA, h.assetA}, {s.epB, h.assetB}} {
		h.exec(`INSERT INTO web_endpoint_events (tenant_id, endpoint_id, origin_asset_id, kind) VALUES ($1, $2, $3, 'appeared')`,
			h.tenant.String(), ep.id.String(), ep.asset.String())
	}

	// memberA sees one origin, one pattern, one event; nothing of B.
	for _, c := range []struct{ path, want string }{
		{"/api/v1/web-origins", `"total":1`},
		{"/api/v1/web-path-patterns", `"total":1`},
		{"/api/v1/web-endpoint-events", `"total":1`},
		{"/api/v1/web-endpoint-events?kind=appeared&sensitive=true", `"total":1`},
	} {
		st, body := h.do(h.memberA, false, http.MethodGet, c.path, nil)
		if st != http.StatusOK || !strings.Contains(body, c.want) || strings.Contains(body, "SECRET") || strings.Contains(body, h.assetB.String()) {
			t.Errorf("memberA %s = %d %s", c.path, st, body)
		}
	}
	if st, body := h.do(h.memberStrict, false, http.MethodGet, "/api/v1/web-origins", nil); st != http.StatusOK || !strings.Contains(body, `"total":0`) {
		t.Errorf("member without scope: %d %s", st, body)
	}

	// The owner: two origins with the coverage gap of B (excluded, sensitive).
	st, body := h.do(h.owner, true, http.MethodGet, "/api/v1/web-origins", nil)
	if st != http.StatusOK || !strings.Contains(body, `"total":2`) || !strings.Contains(body, `"excluded_sensitive":1`) || strings.Contains(body, "we-other") {
		t.Fatalf("owner origins = %d %s", st, body)
	}
	if st, body := h.do(h.owner, true, http.MethodGet, "/api/v1/web-endpoints/stats", nil); st != http.StatusOK ||
		!strings.Contains(body, `"excluded_sensitive":1`) || !strings.Contains(body, `"unauth_sensitive":2`) {
		t.Errorf("owner stats = %d %s", st, body)
	}
	if st, body := h.do(h.owner, true, http.MethodGet, "/api/v1/web-endpoints/"+s.epA.String(), nil); st != http.StatusOK ||
		!strings.Contains(body, `"catalog":{"key":"admin.admin"`) {
		t.Errorf("detail catalog = %d %s", st, body)
	}
	if st, body := h.do(h.memberA, false, http.MethodGet, "/api/v1/web-path-catalog", nil); st != http.StatusOK || !strings.Contains(body, `"spring.actuator.env"`) {
		t.Errorf("catalog = %d %.200s", st, body)
	}
}
