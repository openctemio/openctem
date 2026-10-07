package routes

// Endpoints under a path exclusion are recorded excluded-untested, naming
// the exclusion (RFC-056 WS10): the tenant learns what lies behind it, and
// nothing targets it. A method-scoped exclusion leaves the other methods
// testable.

import (
	"context"
	"testing"

	"github.com/openctemio/ctis"

	"github.com/openctemio/openctem/api/internal/app/ingest"
	scopeapp "github.com/openctemio/openctem/api/internal/app/scope"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

func TestIngest_WebEndpointsUnderAPathExclusion_DB(t *testing.T) {
	h, agt := newWebEndpointHarness(t)
	db := &postgres.DB{DB: h.db}
	all, writes := shared.NewID(), shared.NewID()
	ins := `INSERT INTO scope_exclusions (id, tenant_id, exclusion_type, pattern, reason, status, approved_by, approved_at, created_by, path_prefix, methods)
		VALUES ($1, $2, 'path', $3, 'fragile', 'active', 'a', NOW(), 'c', $4, $5::text[])`
	for _, args := range [][]any{
		{all.String(), h.tenantID, "*/admin/debug", "/admin/debug", "{}"},
		{writes.String(), h.tenantID, "*.web-ex.test/orders", "/orders", "{POST,DELETE}"},
	} {
		if _, err := h.db.Exec(ins, args...); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() { _, _ = h.db.Exec(`DELETE FROM scope_exclusions WHERE tenant_id = $1`, h.tenantID) })

	h.ingest.SetExclusionSource(scopeapp.NewService(postgres.NewScopeTargetRepository(db), postgres.NewScopeExclusionRepository(db),
		postgres.NewAssetRepository(db), logger.NewNop()))
	report := &ctis.Report{
		Version: "1.0", Metadata: ctis.ReportMetadata{ID: "web-ex-1", SourceType: "scanner"}, Tool: &ctis.Tool{Name: "katana"},
		Endpoints: []ctis.Endpoint{
			{Origin: "https://shop.web-ex.test", Method: "GET", Path: "/admin/debug/vars", Source: ctis.EndpointSourceJS},
			{Origin: "https://shop.web-ex.test", Method: "GET", Path: "/orders/1"},
			{Origin: "https://shop.web-ex.test", Method: "POST", Path: "/orders/1"},
			{Origin: "https://shop.web-ex.test", Method: "GET", Path: "/catalog"},
		},
	}
	out, err := h.ingest.Ingest(context.Background(), agt, ingest.Input{Report: report})
	if err != nil {
		t.Fatal(err)
	}
	if out.EndpointsCreated != 4 {
		t.Fatalf("created %d, want 4 (excluded endpoints are recorded, not dropped); errors %v", out.EndpointsCreated, out.Errors)
	}
	want := map[string]struct {
		inScope bool
		excl    string
	}{
		"GET /admin/debug/vars": {false, all.String()},
		"GET /orders/{int}":     {true, ""},
		"POST /orders/{int}":    {false, writes.String()},
		"GET /catalog":          {true, ""},
	}
	rows, err := h.db.Query(`SELECT method || ' ' || path_template, in_scope, COALESCE(exclusion_id::text, '')
		FROM web_endpoints WHERE tenant_id = $1`, h.tenantID)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	n := 0
	for rows.Next() {
		var key, excl string
		var in bool
		if err := rows.Scan(&key, &in, &excl); err != nil {
			t.Fatal(err)
		}
		n++
		w, ok := want[key]
		if !ok || w.inScope != in || w.excl != excl {
			t.Errorf("%s: in_scope=%v exclusion=%q, want %+v", key, in, excl, w)
		}
	}
	if err := rows.Err(); err != nil || n != 4 {
		t.Fatalf("rows %d, err %v", n, err)
	}
}
