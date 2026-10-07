package routes

// End to end over the sensor wire (RFC-056): a crawl report in CTIS 1.6
// (endpoints[] plus a legacy discovered_url URL with a token in its query)
// PUT to /api/v2/sensor/results and processed by the ingest worker lands as
// endpoints and parameter names under one origin asset: no URL asset, no
// token stored, and an endpoint under a path exclusion is recorded
// excluded-untested.

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	scopeapp "github.com/openctemio/openctem/api/internal/app/scope"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

func TestWebSurface_EndToEndOverTheSensorWire_DB(t *testing.T) {
	h := newV2Harness(t, v2HarnessOpts{})
	db := &postgres.DB{DB: h.db}
	h.ingest.SetWebEndpointRepository(postgres.NewWebEndpointRepository(db))
	h.ingest.SetExclusionSource(scopeapp.NewService(postgres.NewScopeTargetRepository(db),
		postgres.NewScopeExclusionRepository(db), postgres.NewAssetRepository(db), logger.NewNop()))
	t.Cleanup(func() {
		_, _ = h.db.Exec(`DELETE FROM assets WHERE tenant_id = $1`, h.tenantID)
		_, _ = h.db.Exec(`DELETE FROM scope_exclusions WHERE tenant_id = $1`, h.tenantID)
	})
	if _, err := h.db.Exec(`UPDATE sensors SET reported_tools = '[{"name":"katana","installed":true}]',
		reported_tool_names = ARRAY['katana'], reported_at = NOW() WHERE id = $1`, h.sensorID); err != nil {
		t.Fatal(err)
	}
	// "/admin/debug must never be scanned" (U24), on every host.
	exclusion := shared.NewID()
	if _, err := h.db.Exec(`INSERT INTO scope_exclusions (id, tenant_id, exclusion_type, pattern, reason, status, approved_by, approved_at, created_by, path_prefix)
		VALUES ($1, $2, 'path', '*/admin/debug', 'fragile', 'active', 'a', NOW(), 'c', '/admin/debug')`, exclusion.String(), h.tenantID); err != nil {
		t.Fatal(err)
	}

	const secret = "tok3nSECRETvalue99"
	report := map[string]any{
		"version":  "1.6",
		"metadata": map[string]any{"timestamp": "2026-10-07T12:00:00Z"},
		"tool":     map[string]any{"name": "katana"},
		"assets": []any{map[string]any{"id": "u1", "type": "discovered_url",
			"value": "https://e2e.web-wire.test/reset?token=" + secret}},
		"endpoints": []any{
			map[string]any{"origin": "https://e2e.web-wire.test", "method": "GET", "path": "/products/42",
				"source": "crawl", "status_code": 200, "params": []any{map[string]any{"location": "query", "name": "ref"}}},
			map[string]any{"origin": "https://e2e.web-wire.test", "method": "GET", "path": "/admin/debug/vars", "source": "js"},
			map[string]any{"origin": "https://e2e.web-wire.test", "method": "GET", "path": "/assets/app.css", "kind": "static"},
		},
	}
	body, _ := json.Marshal(report)
	id := newReportID()
	resp, raw := h.do(http.MethodPut, "/api/v2/sensor/results/"+id, body)
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("PUT report = %d %s", resp.StatusCode, raw)
	}
	h.work(id)

	ctx := context.Background()
	var urlAssets, assets int
	if err := h.db.QueryRowContext(ctx, `SELECT count(*) FILTER (WHERE sub_type = 'discovered_url'), count(*) FROM assets WHERE tenant_id = $1`,
		h.tenantID).Scan(&urlAssets, &assets); err != nil {
		t.Fatal(err)
	}
	if urlAssets != 0 || assets != 1 {
		t.Fatalf("assets: %d URL assets, %d in all; want 0 and the origin only", urlAssets, assets)
	}
	got := map[string]bool{}
	rows, err := h.db.QueryContext(ctx, `SELECT path_template, in_scope, COALESCE(exclusion_id::text, '') FROM web_endpoints WHERE tenant_id = $1`, h.tenantID)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var tmpl, excl string
		var in bool
		if err := rows.Scan(&tmpl, &in, &excl); err != nil {
			t.Fatal(err)
		}
		got[tmpl] = in
		if tmpl == "/admin/debug/vars" && (in || excl != exclusion.String()) {
			t.Errorf("/admin/debug/vars in_scope=%v exclusion=%q: want excluded-untested under the exclusion", in, excl)
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 || !got["/products/{int}"] || !got["/reset"] {
		t.Fatalf("endpoints = %v, want products, reset and the excluded debug path (no static file)", got)
	}
	if n := scalar(t, h.db, `SELECT count(*) FROM web_endpoint_params WHERE tenant_id = $1 AND name IN ('ref', 'token')`, h.tenantID); n != 2 {
		t.Fatalf("parameter names stored = %d, want ref and token", n)
	}
	for _, q := range []string{
		`SELECT count(*) FROM web_endpoints e WHERE e.tenant_id = $1 AND row_to_json(e)::text LIKE '%' || $2 || '%'`,
		`SELECT count(*) FROM web_endpoint_params p WHERE p.tenant_id = $1 AND row_to_json(p)::text LIKE '%' || $2 || '%'`,
		`SELECT count(*) FROM assets a WHERE a.tenant_id = $1 AND row_to_json(a)::text LIKE '%' || $2 || '%'`,
	} {
		if n := scalar(t, h.db, q, h.tenantID, secret); n != 0 {
			t.Errorf("the token in the URL was stored: %s", q)
		}
	}
}
