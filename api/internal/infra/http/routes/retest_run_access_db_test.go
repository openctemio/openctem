package routes

// A run about a finding (kind retest) exposes the finding's target and the
// check's output: it needs findings:read on top of scans:read. Without it the
// run, its tasks, stages and logs are not found, and the Runs list leaves it
// out (research/62 §8: retest logs need findings read on the subject).

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/scanrun"
	infrahttp "github.com/openctemio/openctem/api/internal/infra/http"
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/domain/permission"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

func TestRetestRuns_NeedFindingsRead(t *testing.T) {
	dbURL := testdb.URL()
	if dbURL == "" {
		t.Skip("DATABASE_URL not set to a test database")
	}
	sqldb, err := sql.Open("postgres", dbURL)
	if err != nil {
		t.Skipf("open db: %v", err)
	}
	t.Cleanup(func() { _ = sqldb.Close() })
	ctx := context.Background()
	if err := sqldb.PingContext(ctx); err != nil {
		t.Skipf("cannot reach DATABASE_URL: %v", err)
	}
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := sqldb.ExecContext(ctx, q, args...); err != nil {
			t.Fatalf("%v\n%s", err, q)
		}
	}

	tenant := shared.NewID().String()
	retestRun, scanRun, tpl := shared.NewID().String(), shared.NewID().String(), shared.NewID().String()
	exec(`INSERT INTO tenants (id, name, slug) VALUES ($1, 'retest-runs', $2)`, tenant, "retest-runs-"+tenant)
	t.Cleanup(func() {
		for _, q := range []string{`DELETE FROM scan_runs WHERE tenant_id = $1`, `DELETE FROM scan_workflows WHERE tenant_id = $1`, `DELETE FROM tenants WHERE id = $1`} {
			_, _ = sqldb.ExecContext(ctx, q, tenant)
		}
	})
	exec(`INSERT INTO scan_workflows (id, tenant_id, name) VALUES ($1, $2, 'retest-runs')`, tpl, tenant)
	exec(`INSERT INTO scan_runs (id, tenant_id, scan_workflow_id, trigger_type) VALUES ($1, $2, $3, 'manual')`, scanRun, tenant, tpl)
	exec(`INSERT INTO scan_runs (id, tenant_id, kind, subject, trigger_type, status)
	      VALUES ($1, $2, 'retest', jsonb_build_object('finding_id', $3::text), 'manual', 'running')`,
		retestRun, tenant, shared.NewID().String())
	validationRun := shared.NewID().String()
	exec(`INSERT INTO scan_runs (id, tenant_id, kind, subject, trigger_type, status)
	      VALUES ($1, $2, 'validation', jsonb_build_object('finding_id', $3::text), 'manual', 'running')`,
		validationRun, tenant, shared.NewID().String())

	db := &postgres.DB{DB: sqldb}
	svc := scanrun.NewService(postgres.NewScanWorkflowRepository(db), postgres.NewScanWorkflowStepRepository(db),
		postgres.NewScanRunRepository(db), postgres.NewStepRunRepository(db), nil, postgres.NewCommandRepository(db), nil, logger.NewNop())
	serve := func(perms []string, path string) (int, string) {
		router := infrahttp.NewChiRouter()
		as := func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				c := context.WithValue(r.Context(), middleware.IsAdminKey, false)
				c = context.WithValue(c, middleware.PermissionsKey, perms)
				c = context.WithValue(c, middleware.TenantIDKey, tenant)
				next.ServeHTTP(w, r.WithContext(c))
			})
		}
		registerScanWorkflowRoutes(router, handler.NewScanWorkflowHandler(svc, nil, logger.NewNop()), as, nil, nil)
		mux := router.(interface{ Handler() http.Handler }).Handler()
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		return rec.Code, rec.Body.String()
	}
	listIDs := func(perms []string) map[string]bool {
		t.Helper()
		code, body := serve(perms, "/api/v1/scan-runs/?per_page=100")
		if code != http.StatusOK {
			t.Fatalf("list: %d %s", code, body)
		}
		var resp struct {
			Items []struct {
				ID   string `json:"id"`
				Kind string `json:"kind"`
			} `json:"items"`
			Data []struct {
				ID   string `json:"id"`
				Kind string `json:"kind"`
			} `json:"data"`
		}
		_ = json.Unmarshal([]byte(body), &resp)
		out := map[string]bool{}
		for _, r := range append(resp.Items, resp.Data...) {
			out[r.ID] = true
		}
		return out
	}

	scansOnly := []string{permission.ScansRead.String()}
	withFindings := []string{permission.ScansRead.String(), permission.FindingsRead.String()}

	for _, p := range []string{"", "/tasks", "/stages", "/events", "/tasks/" + shared.NewID().String() + "/logs"} {
		if code, body := serve(scansOnly, "/api/v1/scan-runs/"+retestRun+p); code != http.StatusNotFound {
			t.Errorf("retest run%s without findings:read: %d %s, want 404", p, code, body)
		}
	}
	if code, body := serve(scansOnly, "/api/v1/scan-runs/"+validationRun); code != http.StatusNotFound {
		t.Errorf("validation run without findings:read: %d %s, want 404", code, body)
	}
	if code, body := serve(withFindings, "/api/v1/scan-runs/"+retestRun); code != http.StatusOK {
		t.Fatalf("retest run with findings:read: %d %s, want 200", code, body)
	}
	if code, _ := serve(scansOnly, "/api/v1/scan-runs/"+scanRun); code != http.StatusOK {
		t.Fatalf("a scan run needs only scans:read: %d", code)
	}

	if got := listIDs(scansOnly); got[retestRun] || got[validationRun] || !got[scanRun] {
		t.Errorf("list without findings:read = %v, want the scan run only", got)
	}
	if got := listIDs(withFindings); !got[retestRun] || !got[scanRun] {
		t.Errorf("list with findings:read = %v, want both runs", got)
	}
}
