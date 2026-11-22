package routes

// A finding keeps its web location (CTIS finding.web): the method, the
// parameter's location and name, the status, and the web endpoint it belongs
// to: through the report's endpoint_ref, or by method and URL template. A
// link never crosses tenants and no parameter value is stored.

import (
	"context"
	"testing"
	"time"

	"github.com/openctemio/ctis/v2"

	"github.com/openctemio/openctem/server/internal/app/ingest"
	"github.com/openctemio/openctem/server/internal/infra/postgres"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/server/pkg/domain/webendpoint"
)

const fwlOrigin = "https://shop.fwl.test"

func fwlReport() *ctis.Report {
	dast := func(title, rule, path string, w *ctis.WebLocation) ctis.Finding {
		return ctis.Finding{Type: ctis.FindingTypeVulnerability, Title: title, Severity: ctis.SeverityHigh, RuleID: rule,
			AssetRef: "origin", Location: &ctis.FindingLocation{Path: fwlOrigin + path}, Web: w}
	}
	return &ctis.Report{
		Version:  ctis.SchemaVersion,
		Metadata: ctis.ReportMetadata{ID: ctis.NewReportID(), GeneratedAt: time.Now().UTC(), Channel: ctis.ChannelScanner},
		Tool:     &ctis.Tool{Name: "dalfox", Techniques: []ctis.Technique{ctis.TechniqueDAST}},
		Assets:   []ctis.Asset{{ID: "origin", Type: ctis.AssetTypeWebOrigin, Value: fwlOrigin}},
		Endpoints: []ctis.Endpoint{
			{ID: "ep-login", Origin: fwlOrigin, OriginRef: "origin", Method: "POST", Path: "/login", Kind: ctis.EndpointKindForm},
			{ID: "ep-item", Origin: fwlOrigin, OriginRef: "origin", Method: "GET", Path: "/items/8", Source: ctis.EndpointSourceCrawl},
		},
		Findings: []ctis.Finding{
			// By endpoint_ref; the producer even sent a value after the name.
			dast("XSS in login", "xss-reflected", "/login", &ctis.WebLocation{URL: fwlOrigin + "/login", Method: "POST",
				EndpointRef: "ep-login", StatusCode: 500,
				Parameter: &ctis.WebParameter{Location: ctis.ParamLocationQuery, Name: "q=" + webSecret}}),
			// No ref: the method and the URL template name /items/{int}.
			dast("SQLi in item", "sqli-error", "/items/9", &ctis.WebLocation{URL: fwlOrigin + "/items/9", Method: "GET", StatusCode: 200}),
			// A path no endpoint records: the method is kept, no link.
			dast("Debug page", "debug-page", "/debug", &ctis.WebLocation{URL: fwlOrigin + "/debug", Method: "GET"}),
		},
	}
}

type fwlRow struct {
	method, ploc, pname string
	status              int
	endpoint            string
}

func fwlRows(t *testing.T, h *v2Harness) map[string]fwlRow {
	t.Helper()
	rows, err := h.db.QueryContext(context.Background(), `SELECT f.title, COALESCE(w.method, ''), COALESCE(w.param_location, ''), COALESCE(w.param_name, ''),
		COALESCE(w.status_code, 0), COALESCE(e.method || ' ' || e.path_template, '')
		FROM findings f JOIN finding_web_locations w ON w.tenant_id = f.tenant_id AND w.finding_id = f.id
		LEFT JOIN web_endpoints e ON e.tenant_id = w.tenant_id AND e.id = w.endpoint_id
		WHERE f.tenant_id = $1`, h.tenantID)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	out := map[string]fwlRow{}
	for rows.Next() {
		var title string
		var r fwlRow
		if err := rows.Scan(&title, &r.method, &r.ploc, &r.pname, &r.status, &r.endpoint); err != nil {
			t.Fatal(err)
		}
		out[title] = r
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestIngest_FindingKeepsWebLocationAndEndpoint_DB(t *testing.T) {
	h, agt := newWebEndpointHarness(t)
	out, err := h.ingest.Ingest(context.Background(), agt, ingest.Input{Report: fwlReport()})
	if err != nil {
		t.Fatal(err)
	}
	if out.EndpointsCreated != 2 || out.FindingsCreated != 3 {
		t.Fatalf("endpoints %d findings %d (errors %v)", out.EndpointsCreated, out.FindingsCreated, out.Errors)
	}
	got := fwlRows(t, h)
	if want := (fwlRow{"POST", "query", "q", 500, "POST /login"}); got["XSS in login"] != want {
		t.Errorf("endpoint_ref finding = %+v, want %+v", got["XSS in login"], want)
	}
	if want := (fwlRow{"GET", "", "", 200, "GET /items/{int}"}); got["SQLi in item"] != want {
		t.Errorf("template-matched finding = %+v, want %+v", got["SQLi in item"], want)
	}
	if want := (fwlRow{"GET", "", "", 0, ""}); got["Debug page"] != want {
		t.Errorf("unrecorded path finding = %+v, want %+v", got["Debug page"], want)
	}

	// No parameter value is stored anywhere in the location.
	if n := scalar(t, h.db, `SELECT count(*) FROM finding_web_locations w WHERE w.tenant_id = $1 AND row_to_json(w)::text LIKE '%' || $2 || '%'`,
		h.tenantID, webSecret); n != 0 {
		t.Fatalf("%d web location rows carry the parameter value", n)
	}

	// The path tree reads the exact link: the login finding counts at
	// POST /login and nowhere else.
	repo := postgres.NewWebEndpointRepository(&postgres.DB{DB: h.db})
	var originID string
	if err := h.db.QueryRowContext(context.Background(), `SELECT id FROM assets WHERE tenant_id = $1 AND sub_type = 'http'`, h.tenantID).Scan(&originID); err != nil {
		t.Fatal(err)
	}
	fs, err := repo.OriginOpenFindings(context.Background(), shared.MustIDFromString(h.tenantID), shared.MustIDFromString(originID))
	if err != nil {
		t.Fatal(err)
	}
	linked := map[string]bool{}
	for _, f := range fs {
		if f.Template != "" {
			linked[f.Method+" "+f.Template] = true
		}
	}
	if !linked["POST /login"] || !linked["GET /items/{int}"] || len(linked) != 2 {
		t.Fatalf("linked path findings = %v", linked)
	}

	// A re-sighting that names no status and no endpoint_ref keeps what is
	// stored (the method and the parameter name are part of the identity, so
	// they stay the same).
	r2 := fwlReport()
	r2.Metadata.ID = ctis.NewReportID()
	r2.Findings[0].Web.EndpointRef, r2.Findings[0].Web.StatusCode = "", 0
	if _, err := h.ingest.Ingest(context.Background(), agt, ingest.Input{Report: r2}); err != nil {
		t.Fatal(err)
	}
	if want := (fwlRow{"POST", "query", "q", 500, "POST /login"}); fwlRows(t, h)["XSS in login"] != want {
		t.Errorf("after a re-sighting without status or ref = %+v, want %+v", fwlRows(t, h)["XSS in login"], want)
	}
}

func TestFindingWebLocation_NeverLinksAcrossTenants_DB(t *testing.T) {
	h, agt := newWebEndpointHarness(t)
	if _, err := h.ingest.Ingest(context.Background(), agt, ingest.Input{Report: fwlReport()}); err != nil {
		t.Fatal(err)
	}
	// Tenant B owns an origin and an endpoint with the very same key.
	tenantB := shared.NewID()
	if _, err := h.db.ExecContext(context.Background(), `INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $2)`, tenantB.String(), "fwl-b-"+tenantB.String()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = h.db.ExecContext(context.Background(), `DELETE FROM tenants WHERE id = $1`, tenantB.String())
	})
	originB := shared.NewID()
	if _, err := h.db.ExecContext(context.Background(), `INSERT INTO assets (id, tenant_id, name, asset_type, sub_type, exposure, criticality)
		VALUES ($1, $2, 'https://shop.fwl.test', 'service', 'http', 'public', 'high')`, originB.String(), tenantB.String()); err != nil {
		t.Fatal(err)
	}
	obs, err := webendpoint.Observe(ctis.Endpoint{Origin: fwlOrigin, Method: "GET", Path: "/debug"})
	if err != nil {
		t.Fatal(err)
	}
	repo := postgres.NewWebEndpointRepository(&postgres.DB{DB: h.db})
	if _, err := repo.Record(context.Background(), tenantB, originB, []webendpoint.Observation{obs}, webendpoint.Provenance{}); err != nil {
		t.Fatal(err)
	}

	// Tenant A's finding, told to resolve onto tenant B's origin and key.
	var fp string
	if err := h.db.QueryRowContext(context.Background(), `SELECT fingerprint FROM findings WHERE tenant_id = $1 AND title = 'Debug page'`, h.tenantID).Scan(&fp); err != nil {
		t.Fatal(err)
	}
	fr := postgres.NewFindingRepository(&postgres.DB{DB: h.db})
	err = fr.StoreWebLocations(context.Background(), shared.MustIDFromString(h.tenantID), []vulnerability.WebLocationUpdate{{
		Fingerprint: fp, Method: "GET", OriginAssetID: originB.String(), EndpointHash: obs.TemplateHash, AnyMethodHash: obs.TemplateHash}})
	if err != nil {
		t.Fatal(err)
	}
	if n := scalar(t, h.db, `SELECT count(*) FROM finding_web_locations WHERE tenant_id = $1 AND endpoint_id IS NOT NULL
		AND finding_id = (SELECT id FROM findings WHERE tenant_id = $1 AND fingerprint = $2)`, h.tenantID, fp); n != 0 {
		t.Fatal("a finding was linked to another tenant's endpoint")
	}
	// And tenant B's fingerprint space is not reachable either.
	if err := fr.StoreWebLocations(context.Background(), tenantB, []vulnerability.WebLocationUpdate{{Fingerprint: fp, Method: "GET"}}); err != nil {
		t.Fatal(err)
	}
	if n := scalar(t, h.db, `SELECT count(*) FROM finding_web_locations WHERE tenant_id = $1`, tenantB.String()); n != 0 {
		t.Fatal("a web location was written for tenant B from tenant A's fingerprint")
	}
}
