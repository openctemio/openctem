package routes

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	auditdom "github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/permission"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/validator"
)

// The audit trail names assets and findings (resource names, messages), so a
// member with audit:read but a restricted data scope reads only their own
// activity; owners, admins and full-data roles read everything.
func TestAuditLogFollowsDataScope(t *testing.T) {
	h := newDSHarness(t)
	db := &postgres.DB{DB: h.db}
	log := logger.NewNop()
	svc := auditapp.NewAuditService(postgres.NewAuditRepository(db), log)
	registerAuditRoutes(h.router, handler.NewAuditHandler(svc, validator.New(), log).SetDataScope(h.enforcer), Middleware(h.dsAuth), nil)

	ev := auditapp.NewSuccessEvent(auditdom.ActionFindingUpdated, auditdom.ResourceTypeFinding, h.findingB.String()).
		WithResourceName(dsMarkerFindingB).
		WithMessage("status changed on " + dsMarkerAssetB)
	if err := svc.LogEvent(context.Background(), auditapp.AuditContext{TenantID: h.tenant.String(), ActorID: h.owner.String()}, ev); err != nil {
		t.Fatalf("log event: %v", err)
	}
	ownEv := auditapp.NewSuccessEvent(auditdom.ActionFindingUpdated, auditdom.ResourceTypeFinding, h.findingB.String()).
		WithResourceName("own-activity-marker")
	if err := svc.LogEvent(context.Background(), auditapp.AuditContext{TenantID: h.tenant.String(), ActorID: h.memberA.String()}, ownEv); err != nil {
		t.Fatalf("log own event: %v", err)
	}

	perms := strings.Join([]string{permission.AuditRead.String(), permission.FindingsRead.String()}, ",")
	leaks := func(b string) bool {
		return strings.Contains(b, dsMarkerFindingB) || strings.Contains(b, dsMarkerAssetB)
	}

	for _, path := range []string{
		"/api/v1/audit-logs/",
		"/api/v1/audit-logs/stats",
		"/api/v1/audit-logs/resource/finding/" + h.findingB.String(),
		"/api/v1/audit-logs/user/" + h.owner.String(),
	} {
		code, body := h.doPerms(h.memberA, perms, "GET", path)
		if code != http.StatusForbidden || leaks(body) {
			t.Errorf("restricted member GET %s = %d (leak=%v), want 403", path, code, leaks(body))
		}
		if code, _ := h.doPerms(h.memberFull, perms, "GET", path); code != http.StatusOK {
			t.Errorf("full-data role GET %s = %d, want 200", path, code)
		}
	}

	// Own activity stays readable for the restricted member.
	code, body := h.doPerms(h.memberA, perms, "GET", "/api/v1/audit-logs/user/"+h.memberA.String())
	if code != http.StatusOK || !strings.Contains(body, "own-activity-marker") || leaks(body) {
		t.Errorf("own activity = %d, want 200 with own rows only", code)
	}

	// An administrator reads everything.
	req, _ := newTestReq(h.srv.URL+"/api/v1/audit-logs/", "GET")
	req.Header.Set("X-Test-User", h.owner.String())
	req.Header.Set("X-Test-Admin", "1")
	req.Header.Set("X-Test-Perms", perms)
	if code, body := sendTestReq(t, req); code != http.StatusOK || !leaks(body) {
		t.Errorf("admin list = %d leaks=%v, want 200 with all rows", code, leaks(body))
	}
}

func (h *dsHarness) doPerms(user interface{ String() string }, perms, method, path string) (int, string) {
	h.t.Helper()
	req, _ := newTestReq(h.srv.URL+path, method)
	req.Header.Set("X-Test-User", user.String())
	req.Header.Set("Authorization", "Test "+user.String())
	req.Header.Set("X-Test-Perms", perms)
	return sendTestReq(h.t, req)
}

func newTestReq(url, method string) (*http.Request, error) {
	return http.NewRequestWithContext(context.Background(), method, url, nil)
}

func sendTestReq(t *testing.T, req *http.Request) (int, string) {
	t.Helper()
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}
