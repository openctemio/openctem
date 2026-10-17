package routes

import (
	"context"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	supportapp "github.com/openctemio/openctem/api/internal/app/supportaccess"
	infrahttp "github.com/openctemio/openctem/api/internal/infra/http"
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/domain/admin"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

type bypassOrgs struct{}

func (bypassOrgs) ListOrganizations(context.Context, admin.OrganizationFilter) ([]*admin.Organization, int, error) {
	return nil, 0, nil
}

func (bypassOrgs) GetOrganization(context.Context, shared.ID) (*admin.Organization, error) {
	return &admin.Organization{}, nil
}

type recordingTenantAudit struct {
	mu     sync.Mutex
	events []auditapp.AuditEvent
	actors []string
	failed bool
}

func (r *recordingTenantAudit) LogEvent(_ context.Context, actx auditapp.AuditContext, e auditapp.AuditEvent) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.failed {
		return context.DeadlineExceeded
	}
	r.events = append(r.events, e)
	r.actors = append(r.actors, actx.ActorEmail)
	return nil
}

// The console routes that reach an organization's data without a support
// grant (user list, owner create or recovery, identity provider creation) are
// not blocked, but each use is written to the organization's audit log before
// the route runs, and a failed audit write refuses the use.
func TestGrantBypassRoutesAreNoticed(t *testing.T) {
	now := time.Now()
	a := admin.Reconstitute(shared.NewID(), "root@example.com", "Root", admin.AdminRoleSuperAdmin, true,
		nil, nil, "", 0, nil, nil, "", now, nil, now)
	build := func(audit *recordingTenantAudit) infrahttp.Router {
		var h Handlers
		hv := reflect.ValueOf(&h).Elem()
		for i := 0; i < hv.NumField(); i++ {
			f := hv.Field(i)
			if f.Kind() == reflect.Ptr && f.Type().Elem().Kind() == reflect.Struct &&
				strings.HasSuffix(f.Type().Elem().PkgPath(), "/http/handler") {
				f.Set(reflect.New(f.Type().Elem()))
			}
		}
		log := logger.NewNop()
		h.AdminAuthMiddleware = middleware.NewAdminAuthMiddleware(inventorySessions{a}, log)
		h.AdminStepUp = middleware.AdminStepUpFunc(func(context.Context, *admin.AdminUser, *admin.Session, string, string, middleware.AdminStepUpClient) error {
			return nil
		})
		h.AdminOrganization = handler.NewAdminOrganizationHandler(bypassOrgs{}, nil, nil, nil, log)
		h.AdminSupport = handler.NewAdminSupportHandler(supportapp.NewService(nil, nil, nil, audit, nil, nil, nil, nil, log), log)
		router := infrahttp.NewChiRouter()
		registerAdminRoutes(router, h, nil)
		return router
	}
	tenant := shared.NewID().String()
	for _, c := range []struct{ method, path, route string }{
		{"GET", "/api/v1/admin/tenants/" + tenant + "/users", "user list"},
		{"POST", "/api/v1/admin/tenants/" + tenant + "/users", "owner create or recovery"},
		{"POST", "/api/v1/admin/tenants/" + tenant + "/sso/identity-providers", "identity provider creation"},
	} {
		do := func(router infrahttp.Router) *httptest.ResponseRecorder {
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(c.method, c.path, strings.NewReader(`{}`))
			req.AddCookie(&http.Cookie{Name: middleware.AdminSessionCookie, Value: "s"})
			req.AddCookie(&http.Cookie{Name: middleware.AdminCSRFCookie, Value: "c"})
			req.Header.Set(middleware.CSRFHeaderName, middleware.AdminCSRFToken("s"))
			func() {
				defer func() { _ = recover() }() // a zero-value handler body may panic once reached
				router.Handler().ServeHTTP(rec, req)
			}()
			return rec
		}
		audit := &recordingTenantAudit{}
		do(build(audit))
		if len(audit.events) != 1 || audit.actors[0] != "console:root@example.com" {
			t.Errorf("%s %s: tenant audit events %d actors %v, want one by console:root@example.com", c.method, c.path, len(audit.events), audit.actors)
		}
		failing := &recordingTenantAudit{failed: true}
		if rec := do(build(failing)); rec.Code != http.StatusServiceUnavailable {
			t.Errorf("%s %s: with the audit down got %d, want 503 (no audit, no access)", c.method, c.path, rec.Code)
		}
	}
}
