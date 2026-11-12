package routes

// "Rebuild dashboard data": owners and administrators only, one request per
// organization per hour (429 + Retry-After, shared with the console), each
// accepted request audited in that organization's log, and an organization's
// limit never touched by another's request.

import (
	"context"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"

	_ "github.com/lib/pq"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	factsapp "github.com/openctemio/openctem/api/internal/app/dashboard/facts"
	infrahttp "github.com/openctemio/openctem/api/internal/infra/http"
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/internal/testdb"
	auditdom "github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

type recordedAudit struct {
	mu     sync.Mutex
	events []auditapp.AuditContext
	acts   []auditdom.Action
	origin []any
}

func (a *recordedAudit) LogEvent(_ context.Context, actx auditapp.AuditContext, ev auditapp.AuditEvent) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.events = append(a.events, actx)
	a.acts = append(a.acts, ev.Action)
	a.origin = append(a.origin, ev.Metadata["origin"])
	return nil
}

func TestDashboardDataRoutes_AdminOnlyRateLimitedAudited_DB(t *testing.T) {
	url := testdb.URL()
	if url == "" {
		t.Skip("DATABASE_URL not set")
	}
	db, err := sql.Open("postgres", url)
	if err != nil {
		testdb.Skipf(t, "open db: %v", err)
	}
	defer db.Close()
	ctx := context.Background()
	newTenant := func() shared.ID {
		id := shared.NewID()
		if _, err := db.ExecContext(ctx, `INSERT INTO tenants (id, name, slug) VALUES ($1, 'dash data', $2)`,
			id.String(), "dash-data-"+id.String()); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _, _ = db.Exec(`DELETE FROM tenants WHERE id = $1`, id.String()) })
		return id
	}
	tenantA, tenantB := newTenant(), newTenant()

	rec := &recordedAudit{}
	svc := factsapp.NewService(postgres.NewDashboardFactsRepository(&postgres.DB{DB: db}), rec, logger.NewNop())
	h := handler.NewDashboardFactsHandler(svc, logger.NewNop())

	// The caller's organization and admin flag come from these headers in
	// this test only (the real chain reads the verified token).
	auth := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := context.WithValue(r.Context(), middleware.TenantIDKey, r.Header.Get("X-Test-Tenant"))
			ctx = context.WithValue(ctx, middleware.UserIDKey, shared.NewID().String())
			ctx = context.WithValue(ctx, middleware.IsAdminKey, r.Header.Get("X-Test-Admin") == "1")
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
	router := infrahttp.NewChiRouter()
	registerDashboardDataRoutes(router, h, auth, nil)
	// The console path: AdminTenantScope sets the path organization.
	exists := func(context.Context, shared.ID) error { return nil }
	router.POST("/api/v1/admin/tenants/{tenantId}/dashboard-data/rebuild", h.ConsoleRequestRebuild, middleware.AdminTenantScope(exists))
	mux := router.(interface{ Handler() http.Handler }).Handler()

	call := func(method, path string, tenant shared.ID, admin bool) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, nil)
		req.Header.Set("X-Test-Tenant", tenant.String())
		if admin {
			req.Header.Set("X-Test-Admin", "1")
		}
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)
		return w
	}

	if w := call(http.MethodPost, "/api/v1/dashboard-data/rebuild", tenantA, false); w.Code != http.StatusForbidden {
		t.Fatalf("member rebuild: %d, want 403", w.Code)
	}
	if w := call(http.MethodGet, "/api/v1/dashboard-data/", tenantA, false); w.Code != http.StatusForbidden {
		t.Fatalf("member status: %d, want 403", w.Code)
	}
	if len(rec.acts) != 0 {
		t.Fatalf("a refused request was audited: %v", rec.acts)
	}

	if w := call(http.MethodPost, "/api/v1/dashboard-data/rebuild", tenantA, true); w.Code != http.StatusAccepted {
		t.Fatalf("admin rebuild: %d %s, want 202", w.Code, w.Body.String())
	}
	w := call(http.MethodPost, "/api/v1/dashboard-data/rebuild", tenantA, true)
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("second rebuild: %d, want 429", w.Code)
	}
	if secs, err := strconv.Atoi(w.Header().Get("Retry-After")); err != nil || secs < 3500 || secs > 3600 {
		t.Fatalf("Retry-After %q, want about an hour", w.Header().Get("Retry-After"))
	}
	// The console shares the organization's limit.
	if w := call(http.MethodPost, "/api/v1/admin/tenants/"+tenantA.String()+"/dashboard-data/rebuild", shared.ID{}, false); w.Code != http.StatusTooManyRequests {
		t.Fatalf("console rebuild within the hour: %d, want 429", w.Code)
	}
	// Another organization is not limited by the first.
	if w := call(http.MethodPost, "/api/v1/admin/tenants/"+tenantB.String()+"/dashboard-data/rebuild", shared.ID{}, false); w.Code != http.StatusAccepted {
		t.Fatalf("console rebuild of another organization: %d, want 202", w.Code)
	}
	if w := call(http.MethodGet, "/api/v1/dashboard-data/", tenantA, true); w.Code != http.StatusOK {
		t.Fatalf("admin status: %d", w.Code)
	}

	if len(rec.acts) != 2 {
		t.Fatalf("audited %d requests, want 2 (accepted only)", len(rec.acts))
	}
	if rec.events[0].TenantID != tenantA.String() || rec.origin[0] != string(factsapp.OriginOrganization) ||
		rec.events[1].TenantID != tenantB.String() || rec.origin[1] != string(factsapp.OriginConsole) {
		t.Fatalf("audit rows went to the wrong organization or origin: %+v %v", rec.events, rec.origin)
	}
	for _, a := range rec.acts {
		if a != auditdom.ActionDashboardDataRebuildRequested {
			t.Fatalf("audit action %q", a)
		}
	}
}
