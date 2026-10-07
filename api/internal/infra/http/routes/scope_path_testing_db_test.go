package routes

// PUT /api/v1/scope/exclusions/{id}/testing (RFC-056): how a path exclusion
// may be tested. It needs the exclusion approval permission and a recent
// sign-in (step-up), is audited, notifies every administrator, and is
// tenant-scoped (another tenant's id answers 404).

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	scopeapp "github.com/openctemio/openctem/api/internal/app/scope"
	infrahttp "github.com/openctemio/openctem/api/internal/infra/http"
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/internal/testdb"
	notificationdom "github.com/openctemio/openctem/api/pkg/domain/notification"
	"github.com/openctemio/openctem/api/pkg/domain/permission"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/validator"
)

type fixedAdmins struct{ ids []shared.ID }

func (f fixedAdmins) ActiveAdminIDs(context.Context, shared.ID) ([]shared.ID, error) {
	return f.ids, nil
}

type capturedNotices struct {
	n []notificationdom.NotificationParams
}

func (c *capturedNotices) Notify(_ context.Context, p notificationdom.NotificationParams) error {
	c.n = append(c.n, p)
	return nil
}

type pathTestingHarness struct {
	t                 *testing.T
	db                *sql.DB
	srv               *httptest.Server
	tenant, other     shared.ID
	user              shared.ID
	pathExcl, domExcl shared.ID
	otherExcl         shared.ID
	notices           *capturedNotices
	stepUpAt          *time.Time
}

func newPathTestingHarness(t *testing.T) *pathTestingHarness {
	t.Helper()
	dbURL := testdb.URL()
	if dbURL == "" {
		t.Skip("DATABASE_URL not set")
	}
	sqldb, err := sql.Open("postgres", dbURL)
	if err != nil {
		t.Skipf("open db: %v", err)
	}
	t.Cleanup(func() { _ = sqldb.Close() })
	h := &pathTestingHarness{t: t, db: sqldb, tenant: shared.NewID(), other: shared.NewID(), user: shared.NewID(), notices: &capturedNotices{}}
	for _, tn := range []shared.ID{h.tenant, h.other} {
		h.exec(`INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $2)`, tn.String(), "pt-"+tn.String())
		tid := tn
		t.Cleanup(func() { _, _ = sqldb.Exec(`DELETE FROM tenants WHERE id = $1`, tid.String()) })
	}
	h.exec(`INSERT INTO users (id, email, name) VALUES ($1, $2, $3)`, h.user.String(), h.user.String()+"@pt.test", "approver")
	t.Cleanup(func() { _, _ = sqldb.Exec(`DELETE FROM users WHERE id = $1`, h.user.String()) })
	h.pathExcl, h.domExcl, h.otherExcl = shared.NewID(), shared.NewID(), shared.NewID()
	ins := `INSERT INTO scope_exclusions (id, tenant_id, exclusion_type, pattern, reason, status, approved_by, approved_at, created_by, path_prefix)
		VALUES ($1, $2, $3, $4, 'r', 'active', 'a', NOW(), 'c', $5)`
	h.exec(ins, h.pathExcl.String(), h.tenant.String(), "path", "*/admin", "/admin")
	h.exec(ins, h.domExcl.String(), h.tenant.String(), "domain", "x.example.com", nil)
	h.exec(ins, h.otherExcl.String(), h.other.String(), "path", "*/admin", "/admin")

	db := &postgres.DB{DB: sqldb}
	log := logger.NewNop()
	svc := scopeapp.NewService(postgres.NewScopeTargetRepository(db), postgres.NewScopeExclusionRepository(db), postgres.NewAssetRepository(db), log)
	svc.SetNotifications(fixedAdmins{ids: []shared.ID{shared.NewID(), shared.NewID()}}, h.notices)
	sh := handler.NewScopeHandler(svc, validator.New(), log)
	sh.SetAuditService(auditapp.NewAuditService(postgres.NewAuditRepository(db), log))

	saved := stepUpChecker
	t.Cleanup(func() { stepUpChecker = saved })
	stepUpChecker = recentAuthFunc(func() time.Time {
		if h.stepUpAt == nil {
			return time.Time{}
		}
		return *h.stepUpAt
	})

	router := infrahttp.NewChiRouter()
	auth := Middleware(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := context.WithValue(r.Context(), middleware.UserIDKey, h.user.String())
			ctx = context.WithValue(ctx, middleware.TenantIDKey, h.tenant.String())
			ctx = context.WithValue(ctx, middleware.SessionIDKey, "sess-1")
			ctx = context.WithValue(ctx, middleware.PermissionsKey, strings.Split(r.Header.Get("X-Test-Perms"), ","))
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	})
	registerScopeRoutes(router, sh, auth, nil, passthrough)
	h.srv = httptest.NewServer(router.(interface{ Handler() http.Handler }).Handler())
	t.Cleanup(h.srv.Close)
	return h
}

type recentAuthFunc func() time.Time

func (f recentAuthFunc) RecentAuthAt(context.Context, string, string) (time.Time, error) {
	return f(), nil
}

func (h *pathTestingHarness) exec(q string, args ...any) {
	h.t.Helper()
	if _, err := h.db.Exec(q, args...); err != nil {
		h.t.Fatalf("%s: %v", q, err)
	}
}

func (h *pathTestingHarness) put(id shared.ID, perms []string, body any) (int, string) {
	h.t.Helper()
	b, _ := json.Marshal(body)
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPut, h.srv.URL+"/api/v1/scope/exclusions/"+id.String()+"/testing", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Test-Perms", strings.Join(perms, ","))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(out)
}

func (h *pathTestingHarness) testing(id shared.ID) string {
	var s string
	if err := h.db.QueryRow(`SELECT testing FROM scope_exclusions WHERE id = $1`, id.String()).Scan(&s); err != nil {
		h.t.Fatal(err)
	}
	return s
}

func TestScopeExclusionTesting_PermissionStepUpAuditNotify_DB(t *testing.T) {
	h := newPathTestingHarness(t)
	approve := []string{permission.ScopeExclusionsApprove.String()}
	until := time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339)
	body := map[string]any{"testing": "allowed", "testing_until": until}

	// Without the approval permission: refused, nothing changes.
	if st, _ := h.put(h.pathExcl, []string{permission.ScopeWrite.String()}, body); st != http.StatusForbidden {
		t.Fatalf("scope:write only = %d, want 403", st)
	}
	// With it but no recent sign-in: step-up required.
	if st, b := h.put(h.pathExcl, approve, body); st != http.StatusForbidden || !strings.Contains(b, "STEP_UP_REQUIRED") {
		t.Fatalf("no step-up = %d %s, want 403 STEP_UP_REQUIRED", st, b)
	}
	if got := h.testing(h.pathExcl); got != "blocked" {
		t.Fatalf("testing changed without authority: %s", got)
	}

	now := time.Now()
	h.stepUpAt = &now
	st, b := h.put(h.pathExcl, approve, body)
	if st != http.StatusOK || !strings.Contains(b, `"testing":"allowed"`) || !strings.Contains(b, `"testing_effective":"allowed"`) {
		t.Fatalf("set allowed = %d %s", st, b)
	}
	if got := h.testing(h.pathExcl); got != "allowed" {
		t.Fatalf("stored testing = %s", got)
	}
	if len(h.notices.n) != 2 {
		t.Fatalf("%d admin notices, want 2", len(h.notices.n))
	}
	var audits int
	if err := h.db.QueryRow(`SELECT count(*) FROM audit_logs WHERE tenant_id = $1 AND resource_id = $2 AND action = 'scope_exclusion.updated'`,
		h.tenant.String(), h.pathExcl.String()).Scan(&audits); err != nil || audits != 1 {
		t.Fatalf("audit rows = %d %v, want 1", audits, err)
	}

	// Validation and isolation.
	for name, c := range map[string]struct {
		id   shared.ID
		body any
		want int
	}{
		"bad mode":        {h.pathExcl, map[string]any{"testing": "everything"}, http.StatusUnprocessableEntity},
		"unknown member":  {h.pathExcl, map[string]any{"testing": "blocked", "x": 1}, http.StatusBadRequest},
		"not a path rule": {h.domExcl, map[string]any{"testing": "allowed"}, http.StatusBadRequest},
		"another tenant":  {h.otherExcl, map[string]any{"testing": "allowed"}, http.StatusNotFound},
	} {
		if st, b := h.put(c.id, approve, c.body); st != c.want {
			t.Errorf("%s = %d %s, want %d", name, st, b, c.want)
		}
	}
	if got := h.testing(h.otherExcl); got != "blocked" {
		t.Fatalf("another tenant's exclusion changed: %s", got)
	}
}
