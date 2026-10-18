package middleware_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/domain/admin"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/pagination"
)

// fakeAuditRepo records audit logs written via Create. Create runs in a
// detached goroutine inside the middleware, so we signal on a channel.
type fakeAuditRepo struct {
	created chan *admin.AuditLog
}

func newFakeAuditRepo() *fakeAuditRepo {
	return &fakeAuditRepo{created: make(chan *admin.AuditLog, 8)}
}

func (f *fakeAuditRepo) Create(_ context.Context, log *admin.AuditLog) error {
	f.created <- log
	return nil
}

// --- unused AuditLogRepository methods ---
func (f *fakeAuditRepo) GetByID(context.Context, shared.ID) (*admin.AuditLog, error) {
	panic("unused")
}
func (f *fakeAuditRepo) List(context.Context, admin.AuditLogFilter, pagination.Pagination) (pagination.Result[*admin.AuditLog], error) {
	panic("unused")
}
func (f *fakeAuditRepo) ListByAdmin(context.Context, shared.ID, pagination.Pagination) (pagination.Result[*admin.AuditLog], error) {
	panic("unused")
}
func (f *fakeAuditRepo) ListByResource(context.Context, string, shared.ID, pagination.Pagination) (pagination.Result[*admin.AuditLog], error) {
	panic("unused")
}
func (f *fakeAuditRepo) Count(context.Context, admin.AuditLogFilter) (int64, error) { panic("unused") }
func (f *fakeAuditRepo) GetRecentActions(context.Context, int) ([]*admin.AuditLog, error) {
	panic("unused")
}
func (f *fakeAuditRepo) GetFailedActions(context.Context, time.Duration, int) ([]*admin.AuditLog, error) {
	panic("unused")
}
func (f *fakeAuditRepo) DeleteOlderThan(context.Context, time.Time) (int64, error) { panic("unused") }
func (f *fakeAuditRepo) CountOlderThan(context.Context, time.Time) (int64, error)  { panic("unused") }
func (f *fakeAuditRepo) VerifyChain(context.Context) (*admin.AuditChainReport, error) {
	panic("unused")
}

func waitForAudit(t *testing.T, ch chan *admin.AuditLog) *admin.AuditLog {
	t.Helper()
	select {
	case log := <-ch:
		return log
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for audit log to be written")
		return nil
	}
}

// TestAuditAdminDelete proves an admin-user delete request writes an audit row
// with the admin.delete action.
func TestAuditAdminDelete(t *testing.T) {
	auditRepo := newFakeAuditRepo()
	am := middleware.NewAuditMiddleware(auditRepo, logger.NewNop())

	sessions := newFakeSessions()
	sessions.add("key-super", admin.AdminRoleSuperAdmin)
	auth := middleware.NewAdminAuthMiddleware(sessions, logger.NewNop())

	stub := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	h := auth.Authenticate(am.AuditAdminDelete()(stub))

	h.ServeHTTP(httptest.NewRecorder(), adminRequest(http.MethodDelete, "/api/v1/admin/users/"+shared.NewID().String(), "key-super"))

	log := waitForAudit(t, auditRepo.created)
	if log.Action != admin.AuditActionAdminDelete {
		t.Errorf("audit action: got %q, want %q", log.Action, admin.AuditActionAdminDelete)
	}
}

// failingAuditRepo refuses every write.
type failingAuditRepo struct{ *fakeAuditRepo }

func (failingAuditRepo) Create(context.Context, *admin.AuditLog) error {
	return context.DeadlineExceeded
}

func writeAheadRequest(t *testing.T, repo admin.AuditLogRepository, role, method, body string) (*httptest.ResponseRecorder, bool) {
	t.Helper()
	m := middleware.NewAuditMiddleware(repo, logger.NewNop())
	called := false
	h := m.WriteAhead()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusNoContent)
	}))
	req := httptest.NewRequest(method, "/api/v1/admin/tenants", strings.NewReader(body))
	req = req.WithContext(context.WithValue(req.Context(), middleware.AdminRoleKey, role))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec, called
}

func TestWriteAheadRefusesSuperAdminWriteWhenAuditFails(t *testing.T) {
	rec, called := writeAheadRequest(t, failingAuditRepo{newFakeAuditRepo()}, "super_admin", http.MethodPost, `{"a":1}`)
	if called {
		t.Fatal("the handler must not run when the audit row cannot be written")
	}
	if rec.Code != http.StatusServiceUnavailable || !strings.Contains(rec.Body.String(), "AUDIT_UNAVAILABLE") {
		t.Fatalf("got %d %s", rec.Code, rec.Body.String())
	}
}

func TestWriteAheadRecordsRedactedBodyThenRunsHandler(t *testing.T) {
	repo := newFakeAuditRepo()
	rec, called := writeAheadRequest(t, repo, "super_admin", http.MethodPost, `{"name":"x","password":"hunter2"}`)
	if !called || rec.Code != http.StatusNoContent {
		t.Fatalf("handler must run: %d called=%v", rec.Code, called)
	}
	log := waitForAudit(t, repo.created)
	if log.Action != middleware.AuditActionWriteStarted || log.RequestMethod != http.MethodPost {
		t.Fatalf("row %+v", log)
	}
	if log.RequestBody["password"] != "[REDACTED]" || log.RequestBody["name"] != "x" {
		t.Fatalf("body not redacted: %v", log.RequestBody)
	}
}

func TestWriteAheadLeavesOtherRolesAndReadsAlone(t *testing.T) {
	for _, c := range []struct{ role, method string }{
		{"ops_admin", http.MethodPost},
		{"readonly", http.MethodDelete},
		{"super_admin", http.MethodGet},
		{"super_admin", http.MethodHead},
	} {
		rec, called := writeAheadRequest(t, failingAuditRepo{newFakeAuditRepo()}, c.role, c.method, "")
		if !called || rec.Code != http.StatusNoContent {
			t.Errorf("%s %s must be unaffected: %d called=%v", c.role, c.method, rec.Code, called)
		}
	}
}
