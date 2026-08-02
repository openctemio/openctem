package middleware_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/openctemio/api/internal/infra/http/middleware"
	"github.com/openctemio/api/pkg/domain/admin"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
	"github.com/openctemio/api/pkg/pagination"
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

// TestAuditAdminCreate proves an admin-user create request writes an audit row
// with the admin.create action.
func TestAuditAdminCreate(t *testing.T) {
	auditRepo := newFakeAuditRepo()
	am := middleware.NewAuditMiddleware(auditRepo, logger.NewNop())

	adminRepo := newFakeAdminRepo()
	adminRepo.add("key-super", admin.AdminRoleSuperAdmin)
	auth := middleware.NewAdminAuthMiddleware(adminRepo, logger.NewNop())

	stub := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusCreated) })
	h := auth.Authenticate(am.AuditAdminCreate()(stub))

	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/users/", http.NoBody)
	req.Header.Set(middleware.AdminAPIKeyHeader, "key-super")
	h.ServeHTTP(httptest.NewRecorder(), req)

	log := waitForAudit(t, auditRepo.created)
	if log.Action != admin.AuditActionAdminCreate {
		t.Errorf("audit action: got %q, want %q", log.Action, admin.AuditActionAdminCreate)
	}
}

// TestAuditAdminDelete proves an admin-user delete request writes an audit row
// with the admin.delete action.
func TestAuditAdminDelete(t *testing.T) {
	auditRepo := newFakeAuditRepo()
	am := middleware.NewAuditMiddleware(auditRepo, logger.NewNop())

	adminRepo := newFakeAdminRepo()
	adminRepo.add("key-super", admin.AdminRoleSuperAdmin)
	auth := middleware.NewAdminAuthMiddleware(adminRepo, logger.NewNop())

	stub := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	h := auth.Authenticate(am.AuditAdminDelete()(stub))

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/admin/users/"+shared.NewID().String(), http.NoBody)
	req.Header.Set(middleware.AdminAPIKeyHeader, "key-super")
	h.ServeHTTP(httptest.NewRecorder(), req)

	log := waitForAudit(t, auditRepo.created)
	if log.Action != admin.AuditActionAdminDelete {
		t.Errorf("audit action: got %q, want %q", log.Action, admin.AuditActionAdminDelete)
	}
}

// TestAuditAdminRotateKey proves the new rotate-key audit factory writes a row
// with the admin.rotate_key action.
func TestAuditAdminRotateKey(t *testing.T) {
	auditRepo := newFakeAuditRepo()
	am := middleware.NewAuditMiddleware(auditRepo, logger.NewNop())
	adminRepo := newFakeAdminRepo()
	adminRepo.add("key-super", admin.AdminRoleSuperAdmin)
	auth := middleware.NewAdminAuthMiddleware(adminRepo, logger.NewNop())

	stub := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	handler := auth.Authenticate(am.AuditAdminRotateKey()(stub))

	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/users/"+shared.NewID().String()+"/rotate-key", http.NoBody)
	req.Header.Set(middleware.AdminAPIKeyHeader, "key-super")
	handler.ServeHTTP(httptest.NewRecorder(), req)

	log := waitForAudit(t, auditRepo.created)
	if log.Action != admin.AuditActionAdminRotateKey {
		t.Errorf("audit action: got %q, want %q", log.Action, admin.AuditActionAdminRotateKey)
	}
}
