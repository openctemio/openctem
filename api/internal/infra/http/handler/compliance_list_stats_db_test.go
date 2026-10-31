package handler

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"

	compliancesvc "github.com/openctemio/openctem/api/internal/app/compliance"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// TestComplianceFrameworkListStats: GET /compliance/frameworks?include=stats
// carries each listed framework's stats (the body of GET
// /frameworks/{id}/stats) counted on the caller's own assessments; another
// organization's custom framework is neither listed nor readable through
// GET /frameworks/{id}/stats.
func TestComplianceFrameworkListStats(t *testing.T) {
	dbURL := testdb.URL()
	if dbURL == "" {
		t.Skip("DATABASE_URL not set")
	}
	sqldb, err := sql.Open("postgres", dbURL)
	if err != nil {
		t.Skipf("open db: %v", err)
	}
	t.Cleanup(func() { _ = sqldb.Close() })
	if err := sqldb.PingContext(context.Background()); err != nil {
		t.Skipf("cannot reach DATABASE_URL: %v", err)
	}
	ctx := context.Background()
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := sqldb.ExecContext(ctx, q, args...); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}

	tenantA, tenantB := shared.NewID().String(), shared.NewID().String()
	for _, id := range []string{tenantA, tenantB} {
		exec(`INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $3)`, id, "compliance stats", "cs-"+id)
	}
	system, custom := shared.NewID().String(), shared.NewID().String()
	c1, c2, c3 := shared.NewID().String(), shared.NewID().String(), shared.NewID().String()
	exec(`INSERT INTO compliance_frameworks (id, tenant_id, name, slug, version, description, category, is_system) VALUES ($1, NULL, 'Stats system', $2, '1', '', 'test', true)`, system, "st-"+system[:8])
	exec(`INSERT INTO compliance_frameworks (id, tenant_id, name, slug, version, description, category) VALUES ($1, $2, 'B custom', $3, '1', '', 'test')`, custom, tenantB, "bc-"+custom[:8])
	t.Cleanup(func() {
		_, _ = sqldb.ExecContext(context.Background(), `DELETE FROM compliance_assessments WHERE tenant_id = ANY($1::uuid[])`, "{"+tenantA+","+tenantB+"}")
		_, _ = sqldb.ExecContext(context.Background(), `DELETE FROM compliance_controls WHERE framework_id = ANY($1::uuid[])`, "{"+system+","+custom+"}")
		_, _ = sqldb.ExecContext(context.Background(), `DELETE FROM compliance_frameworks WHERE id = ANY($1::uuid[])`, "{"+system+","+custom+"}")
		_, _ = sqldb.ExecContext(context.Background(), `DELETE FROM tenants WHERE id = ANY($1::uuid[])`, "{"+tenantA+","+tenantB+"}")
	})
	exec(`INSERT INTO compliance_controls (id, framework_id, control_id, title) VALUES ($1, $2, 'S-1', 'one'), ($3, $2, 'S-2', 'two')`, c1, system, c2)
	exec(`INSERT INTO compliance_controls (id, framework_id, control_id, title) VALUES ($1, $2, 'B-1', 'b one')`, c3, custom)
	exec(`INSERT INTO compliance_assessments (tenant_id, framework_id, control_id, status) VALUES ($1, $2, $3, 'implemented')`, tenantA, system, c1)
	exec(`INSERT INTO compliance_assessments (tenant_id, framework_id, control_id, status) VALUES ($1, $2, $3, 'partial')`, tenantB, system, c2)

	db := &postgres.DB{DB: sqldb}
	h := NewComplianceHandler(compliancesvc.NewComplianceService(
		postgres.NewComplianceFrameworkRepository(db), postgres.NewComplianceControlRepository(db),
		postgres.NewComplianceAssessmentRepository(db), postgres.NewComplianceMappingRepository(db),
		logger.NewNop()), logger.NewNop())

	call := func(fn http.HandlerFunc, tenant, path, id string) (int, []byte) {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		c := context.WithValue(req.Context(), middleware.TenantIDKey, tenant)
		if id != "" {
			rctx := chi.NewRouteContext()
			rctx.URLParams.Add("id", id)
			c = context.WithValue(c, chi.RouteCtxKey, rctx)
		}
		rec := httptest.NewRecorder()
		fn(rec, req.WithContext(c))
		return rec.Code, rec.Body.Bytes()
	}
	type stats struct{ TotalControls, Implemented, Partial, NotAssessed int64 }
	list := func(tenant, query string) map[string]*stats {
		t.Helper()
		code, body := call(h.ListFrameworks, tenant, "/api/v1/compliance/frameworks?per_page=100"+query, "")
		if code != http.StatusOK {
			t.Fatalf("list: %d %s", code, body)
		}
		var out struct {
			Data []struct {
				ID    string `json:"id"`
				Stats *stats `json:"stats"`
			} `json:"data"`
		}
		if err := json.Unmarshal(body, &out); err != nil {
			t.Fatal(err)
		}
		m := map[string]*stats{}
		for _, f := range out.Data {
			m[f.ID] = f.Stats
		}
		return m
	}

	a := list(tenantA, "&include=stats")
	if s := a[system]; s == nil || s.TotalControls != 2 || s.Implemented != 1 || s.Partial != 0 || s.NotAssessed != 1 {
		t.Errorf("tenant A system stats = %+v, want 2 controls, 1 implemented, 1 not assessed", s)
	}
	if _, ok := a[custom]; ok {
		t.Error("tenant A lists tenant B's custom framework")
	}
	b := list(tenantB, "&include=stats")
	if s := b[system]; s == nil || s.Implemented != 0 || s.Partial != 1 {
		t.Errorf("tenant B system stats = %+v, want only its own partial", s)
	}
	if s := b[custom]; s == nil || s.TotalControls != 1 || s.NotAssessed != 1 {
		t.Errorf("tenant B custom stats = %+v", s)
	}
	// The list's stats equal the per-framework endpoint's.
	code, body := call(h.GetFrameworkStats, tenantA, "/api/v1/compliance/frameworks/"+system+"/stats", system)
	var one stats
	_ = json.Unmarshal(body, &one)
	if code != http.StatusOK || one != *a[system] {
		t.Errorf("per-framework stats %d %+v != list %+v", code, one, a[system])
	}
	// Without include: no stats.
	if s := list(tenantA, "")[system]; s != nil {
		t.Errorf("stats without include: %+v", s)
	}
	// Another organization's custom framework: not found, no control count.
	if code, body := call(h.GetFrameworkStats, tenantA, "/api/v1/compliance/frameworks/"+custom+"/stats", custom); code != http.StatusNotFound {
		t.Errorf("tenant A reading tenant B's framework stats: %d %s, want 404", code, body)
	}
}
