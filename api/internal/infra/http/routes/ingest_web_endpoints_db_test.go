package routes

// Web endpoints land in the web surface sub-inventory under their origin
// asset (RFC-056): a crawl creates no asset per URL, query values and
// tokens never reach the database, and an endpoint never lands under
// another tenant's origin.

import (
	"context"
	"database/sql"
	"strings"
	"testing"

	"github.com/lib/pq"
	"github.com/openctemio/ctis"

	"github.com/openctemio/openctem/api/internal/app/ingest"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/webendpoint"
)

const webSecret = "SECRETv4lue9Zq"

func newWebEndpointHarness(t *testing.T) (*v2Harness, *sensor.Sensor) {
	t.Helper()
	h := newV2Harness(t, v2HarnessOpts{})
	h.ingest.SetWebEndpointRepository(postgres.NewWebEndpointRepository(&postgres.DB{DB: h.db}))
	t.Cleanup(func() {
		_, _ = h.db.ExecContext(context.Background(), `DELETE FROM assets WHERE tenant_id = $1`, h.tenantID)
		_, _ = h.db.ExecContext(context.Background(), `DELETE FROM audit_logs WHERE tenant_id = $1`, h.tenantID)
	})
	agt, err := postgres.NewSensorRepository(&postgres.DB{DB: h.db}).GetByTenantAndID(context.Background(),
		shared.MustIDFromString(h.tenantID), shared.MustIDFromString(h.sensorID))
	if err != nil {
		t.Fatal(err)
	}
	return h, agt
}

func katanaLikeReport() *ctis.Report {
	return &ctis.Report{
		Version:  "1.0",
		Metadata: ctis.ReportMetadata{ID: "web-ep-1", SourceType: "scanner"},
		Tool:     &ctis.Tool{Name: "katana"},
		Assets: []ctis.Asset{
			// A legacy crawl asset with secrets in its query: folded, never stored.
			{ID: "u1", Type: ctis.AssetTypeDiscoveredURL,
				Value: "https://shop.web-ep.test/account/reset?token=" + webSecret + "&sig=" + webSecret},
		},
		Endpoints: []ctis.Endpoint{
			{Origin: "https://shop.web-ep.test", Method: "GET", Path: "/products/42", Kind: ctis.EndpointKindPage,
				Source: ctis.EndpointSourceCrawl, StatusCode: 200, ContentType: "text/html",
				Params: []ctis.EndpointParam{{Location: ctis.ParamLocationQuery, Name: "ref"}}},
			{Origin: "https://shop.web-ep.test", Method: "GET", Path: "/products/43", Source: ctis.EndpointSourceSitemap},
			{Origin: "https://shop.web-ep.test", Method: "POST", Path: "/login", Kind: ctis.EndpointKindForm,
				Params: []ctis.EndpointParam{
					{Location: ctis.ParamLocationForm, Name: "username"},
					{Location: ctis.ParamLocationForm, Name: "password", Required: true},
				}},
			{Origin: "https://shop.web-ep.test", Method: "GET", Path: "/reset/" + webSecret + "Ab12CdEf34GhIj56"},
			{Origin: "https://shop.web-ep.test", Method: "GET", Path: "/static/logo.png", Kind: ctis.EndpointKindStatic},
		},
	}
}

func scalar(t *testing.T, db *sql.DB, q string, args ...any) int {
	t.Helper()
	var n int
	if err := db.QueryRow(q, args...).Scan(&n); err != nil {
		t.Fatalf("%s: %v", q, err)
	}
	return n
}

func TestIngest_WebEndpoints_SubInventoryNotAssets_DB(t *testing.T) {
	h, agt := newWebEndpointHarness(t)
	out, err := h.ingest.Ingest(context.Background(), agt, ingest.Input{Report: katanaLikeReport()})
	if err != nil {
		t.Fatal(err)
	}
	if out.EndpointsCreated != 4 || out.EndpointsStatic != 1 || out.LegacyURLAssetsFolded != 1 {
		t.Fatalf("created %d static %d folded %d (errors %v)", out.EndpointsCreated, out.EndpointsStatic, out.LegacyURLAssetsFolded, out.Errors)
	}

	// No asset per URL: the origin is the only asset the crawl wrote.
	if n := scalar(t, h.db, `SELECT count(*) FROM assets WHERE tenant_id = $1 AND sub_type = 'discovered_url'`, h.tenantID); n != 0 {
		t.Fatalf("%d discovered_url assets created", n)
	}
	if n := scalar(t, h.db, `SELECT count(*) FROM assets WHERE tenant_id = $1`, h.tenantID); n != 1 {
		t.Fatalf("%d assets, want only the origin", n)
	}
	var originID, originType, originSub string
	if err := h.db.QueryRow(`SELECT id, asset_type, COALESCE(sub_type, '') FROM assets WHERE tenant_id = $1`, h.tenantID).
		Scan(&originID, &originType, &originSub); err != nil {
		t.Fatal(err)
	}
	if originType != "service" || originSub != "http" {
		t.Fatalf("origin asset is %s/%s", originType, originSub)
	}

	// The two product pages are one endpoint; the legacy URL and the token
	// path are templated.
	rows, err := h.db.Query(`SELECT method, path_template, COALESCE(example_path, ''), sources, origin_asset_id, tenant_id, param_count
		FROM web_endpoints WHERE tenant_id = $1 ORDER BY path_template, method`, h.tenantID)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	got := map[string]string{}
	for rows.Next() {
		var method, tmpl, example, origin, tenant string
		var sources []string
		var params int
		if err := rows.Scan(&method, &tmpl, &example, (*pq.StringArray)(&sources), &origin, &tenant, &params); err != nil {
			t.Fatal(err)
		}
		if origin != originID || tenant != h.tenantID {
			t.Fatalf("endpoint %s under %s/%s", tmpl, origin, tenant)
		}
		got[method+" "+tmpl] = example + "|" + strings.Join(sources, ",")
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"GET /products/{int}", "POST /login", "GET /reset/{token}", "GET /account/reset"} {
		if _, ok := got[want]; !ok {
			t.Errorf("missing endpoint %q (have %v)", want, got)
		}
	}
	if got["GET /products/{int}"] != "/products/42|crawl,sitemap" {
		t.Errorf("products = %q, want the first example and both sources", got["GET /products/{int}"])
	}

	// Parameters: names only, classified.
	var sensitive string
	if err := h.db.QueryRow(`SELECT COALESCE(p.sensitive, '') FROM web_endpoint_params p JOIN web_endpoints e ON e.id = p.endpoint_id
		WHERE p.tenant_id = $1 AND e.path_template = '/login' AND p.name = 'password'`, h.tenantID).Scan(&sensitive); err != nil {
		t.Fatal(err)
	}
	if sensitive != webendpoint.SensitiveCredential {
		t.Errorf("password sensitive = %q", sensitive)
	}
	if n := scalar(t, h.db, `SELECT count(*) FROM web_endpoint_params p JOIN web_endpoints e ON e.id = p.endpoint_id
		WHERE p.tenant_id = $1 AND e.path_template = '/account/reset' AND p.location = 'query' AND p.name IN ('token','sig')`, h.tenantID); n != 2 {
		t.Errorf("legacy query names stored = %d, want token and sig", n)
	}

	// No value, token or secret anywhere in the sub-inventory or the assets.
	for _, q := range []string{
		`SELECT count(*) FROM web_endpoints e WHERE e.tenant_id = $1 AND row_to_json(e)::text LIKE '%' || $2 || '%'`,
		`SELECT count(*) FROM web_endpoint_params p WHERE p.tenant_id = $1 AND row_to_json(p)::text LIKE '%' || $2 || '%'`,
		`SELECT count(*) FROM assets a WHERE a.tenant_id = $1 AND row_to_json(a)::text LIKE '%' || $2 || '%'`,
	} {
		if n := scalar(t, h.db, q, h.tenantID, webSecret); n != 0 {
			t.Errorf("a secret value was stored: %s", q)
		}
	}

	// An unsolicited report may not change the existing origin: nothing is
	// written under it.
	out, err = h.ingest.Ingest(context.Background(), agt, ingest.Input{Report: katanaLikeReport()})
	if err != nil {
		t.Fatal(err)
	}
	if out.EndpointsCreated != 0 || out.EndpointsUpdated != 0 || out.EndpointsRefused == 0 {
		t.Fatalf("unsolicited re-ingest created %d updated %d refused %d", out.EndpointsCreated, out.EndpointsUpdated, out.EndpointsRefused)
	}

	// A command covering the origin re-sights it: updates, never duplicates.
	cmd := shared.NewID()
	bound := ingest.Options{Binding: ingest.Binding{Kind: ingest.BindingCommand, CommandID: &cmd,
		Targets: []string{"https://shop.web-ep.test"}, Tool: "katana"}}
	out, err = h.ingest.Ingest(context.Background(), agt, ingest.Input{Report: katanaLikeReport(), Options: bound})
	if err != nil {
		t.Fatal(err)
	}
	if out.EndpointsCreated != 0 || out.EndpointsUpdated != 4 {
		t.Fatalf("re-ingest created %d updated %d", out.EndpointsCreated, out.EndpointsUpdated)
	}
	if n := scalar(t, h.db, `SELECT count(*) FROM web_endpoints WHERE tenant_id = $1`, h.tenantID); n != 4 {
		t.Fatalf("%d endpoints after re-ingest", n)
	}
}

func TestIngest_WebEndpoints_NeverUnderAnotherTenantsOrigin_DB(t *testing.T) {
	h, agt := newWebEndpointHarness(t)
	ctx := context.Background()

	// Tenant B owns an origin with the same name.
	tenantB := shared.NewID()
	if _, err := h.db.Exec(`INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $2)`, tenantB.String(), "web-ep-b-"+tenantB.String()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = h.db.Exec(`DELETE FROM tenants WHERE id = $1`, tenantB.String()) })
	originB := shared.NewID()
	if _, err := h.db.Exec(`INSERT INTO assets (id, tenant_id, name, asset_type, sub_type, exposure, criticality)
		VALUES ($1, $2, 'https://shop.web-ep.test', 'service', 'http', 'public', 'high')`, originB.String(), tenantB.String()); err != nil {
		t.Fatal(err)
	}

	if _, err := h.ingest.Ingest(ctx, agt, ingest.Input{Report: katanaLikeReport()}); err != nil {
		t.Fatal(err)
	}
	if n := scalar(t, h.db, `SELECT count(*) FROM web_endpoints WHERE origin_asset_id = $1 OR tenant_id = $2`, originB.String(), tenantB.String()); n != 0 {
		t.Fatalf("%d endpoints written under tenant B", n)
	}

	// The storage refuses a cross-tenant pairing even if a caller tried.
	repo := postgres.NewWebEndpointRepository(&postgres.DB{DB: h.db})
	obs, _ := webendpoint.Observe(ctis.Endpoint{Origin: "https://shop.web-ep.test", Path: "/x"})
	if _, err := repo.Record(ctx, shared.MustIDFromString(h.tenantID), originB, []webendpoint.Observation{obs}, webendpoint.Provenance{}); err == nil {
		t.Fatal("an endpoint of tenant A was stored under tenant B's origin asset")
	}
}

func TestIngest_WebEndpoints_CommandOutsideItsTargets_DB(t *testing.T) {
	h, agt := newWebEndpointHarness(t)
	cmd := shared.NewID()
	b := ingest.Binding{Kind: ingest.BindingCommand, CommandID: &cmd, Targets: []string{"https://other.web-ep.test"}, Tool: "katana"}
	out, err := h.ingest.Ingest(context.Background(), agt, ingest.Input{Report: katanaLikeReport(), Options: ingest.Options{Binding: b}})
	if err != nil {
		t.Fatal(err)
	}
	if n := scalar(t, h.db, `SELECT count(*) FROM web_endpoints WHERE tenant_id = $1`, h.tenantID); n != 0 || out.EndpointsCreated != 0 {
		t.Fatalf("%d endpoints stored for an origin the command does not cover", n)
	}
	if n := scalar(t, h.db, `SELECT count(*) FROM assets WHERE tenant_id = $1 AND name LIKE '%shop.web-ep.test%'`, h.tenantID); n != 0 {
		t.Fatalf("the uncovered origin became an asset")
	}
}

func TestWebEndpointRepository_CapsPerOrigin_DB(t *testing.T) {
	h, _ := newWebEndpointHarness(t)
	ctx := context.Background()
	tenant := shared.MustIDFromString(h.tenantID)
	origin := shared.NewID()
	if _, err := h.db.Exec(`INSERT INTO assets (id, tenant_id, name, asset_type, sub_type, exposure, criticality)
		VALUES ($1, $2, 'https://cap.web-ep.test', 'service', 'http', 'public', 'low')`, origin.String(), h.tenantID); err != nil {
		t.Fatal(err)
	}
	if _, err := h.db.Exec(`INSERT INTO web_endpoints (id, tenant_id, origin_asset_id, method, path_template, template_hash, path_hash)
		SELECT gen_random_uuid(), $1, $2, 'GET', '/p' || g, lpad(to_hex(g), 64, '0'), lpad(to_hex(g), 64, '0')
		FROM generate_series(1, $3::int) g`, h.tenantID, origin.String(), webendpoint.MaxActivePerOrigin); err != nil {
		t.Fatal(err)
	}
	repo := postgres.NewWebEndpointRepository(&postgres.DB{DB: h.db})
	obs, _ := webendpoint.Observe(ctis.Endpoint{Origin: "https://cap.web-ep.test", Path: "/new"})
	res, err := repo.Record(ctx, tenant, origin, []webendpoint.Observation{obs}, webendpoint.Provenance{})
	if err != nil {
		t.Fatal(err)
	}
	if res.OverCap != 1 || res.Created != 0 {
		t.Fatalf("over cap: %+v", res)
	}
	// Retiring one makes room.
	if _, err := h.db.Exec(`UPDATE web_endpoints SET state = 'gone' WHERE tenant_id = $1 AND path_template = '/p1'`, h.tenantID); err != nil {
		t.Fatal(err)
	}
	if res, err = repo.Record(ctx, tenant, origin, []webendpoint.Observation{obs}, webendpoint.Provenance{}); err != nil || res.Created != 1 {
		t.Fatalf("after retiring one: %+v %v", res, err)
	}
}
