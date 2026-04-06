package unit

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/openctemio/api/internal/infra/http/middleware"
	"github.com/openctemio/api/pkg/domain/pentest"
)

// --- CampaignRoleKey context tests ---

func TestGetCampaignRole_FromContext(t *testing.T) {
	ctx := context.WithValue(context.Background(), middleware.CampaignRoleKey, pentest.CampaignRoleLead)
	role := middleware.GetCampaignRole(ctx)
	if role != pentest.CampaignRoleLead {
		t.Errorf("expected lead, got %s", role)
	}
}

func TestGetCampaignRole_Missing(t *testing.T) {
	role := middleware.GetCampaignRole(context.Background())
	if role != "" {
		t.Errorf("expected empty, got %s", role)
	}
}

// --- RequireCampaignRole middleware tests ---

func TestRequireCampaignRole_LeadAllowed(t *testing.T) {
	mw := middleware.RequireCampaignRole(pentest.CampaignRoleLead)
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	ctx := context.WithValue(context.Background(), middleware.CampaignRoleKey, pentest.CampaignRoleLead)
	req := httptest.NewRequest(http.MethodGet, "/test", nil).WithContext(ctx)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
}

func TestRequireCampaignRole_TesterDeniedWhenLeadRequired(t *testing.T) {
	mw := middleware.RequireCampaignRole(pentest.CampaignRoleLead)
	handler := mw(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		t.Error("handler should not be called")
	}))

	ctx := context.WithValue(context.Background(), middleware.CampaignRoleKey, pentest.CampaignRoleTester)
	req := httptest.NewRequest(http.MethodGet, "/test", nil).WithContext(ctx)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", rec.Code)
	}
}

func TestRequireCampaignRole_MultipleRolesAllowed(t *testing.T) {
	mw := middleware.RequireCampaignRole(pentest.CampaignRoleLead, pentest.CampaignRoleTester)
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	ctx := context.WithValue(context.Background(), middleware.CampaignRoleKey, pentest.CampaignRoleTester)
	req := httptest.NewRequest(http.MethodGet, "/test", nil).WithContext(ctx)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
}

func TestRequireCampaignRole_ObserverDenied(t *testing.T) {
	mw := middleware.RequireCampaignRole(pentest.CampaignRoleLead, pentest.CampaignRoleTester)
	handler := mw(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		t.Error("handler should not be called")
	}))

	ctx := context.WithValue(context.Background(), middleware.CampaignRoleKey, pentest.CampaignRoleObserver)
	req := httptest.NewRequest(http.MethodGet, "/test", nil).WithContext(ctx)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", rec.Code)
	}
}

func TestRequireCampaignRole_NoCampaignRole_Returns404(t *testing.T) {
	mw := middleware.RequireCampaignRole(pentest.CampaignRoleLead)
	handler := mw(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		t.Error("handler should not be called")
	}))

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	// No campaign role = not a member → 404 (don't reveal campaign existence)
	if rec.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", rec.Code)
	}
}

func TestRequireCampaignRole_AdminBypass(t *testing.T) {
	mw := middleware.RequireCampaignRole(pentest.CampaignRoleLead)
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Admin without campaign role should still pass
	ctx := context.WithValue(context.Background(), middleware.IsAdminKey, true)
	req := httptest.NewRequest(http.MethodGet, "/test", nil).WithContext(ctx)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 (admin bypass), got %d", rec.Code)
	}
}

// --- RequireCampaignWritable middleware tests ---

func TestRequireCampaignWritable_PlanningOK(t *testing.T) {
	mw := middleware.RequireCampaignWritable(false)
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	ctx := context.WithValue(context.Background(), middleware.CampaignStatusKey, pentest.CampaignStatusPlanning)
	req := httptest.NewRequest(http.MethodPost, "/test", nil).WithContext(ctx)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
}

func TestRequireCampaignWritable_CompletedBlocked(t *testing.T) {
	mw := middleware.RequireCampaignWritable(false)
	handler := mw(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		t.Error("handler should not be called")
	}))

	ctx := context.WithValue(context.Background(), middleware.CampaignStatusKey, pentest.CampaignStatusCompleted)
	req := httptest.NewRequest(http.MethodPost, "/test", nil).WithContext(ctx)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", rec.Code)
	}
}

func TestRequireCampaignWritable_CanceledBlocked(t *testing.T) {
	mw := middleware.RequireCampaignWritable(false)
	handler := mw(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		t.Error("handler should not be called")
	}))

	ctx := context.WithValue(context.Background(), middleware.CampaignStatusKey, pentest.CampaignStatusCanceled)
	req := httptest.NewRequest(http.MethodPost, "/test", nil).WithContext(ctx)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", rec.Code)
	}
}

func TestRequireCampaignWritable_OnHoldBlocksNew(t *testing.T) {
	mw := middleware.RequireCampaignWritable(false) // creating new item
	handler := mw(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		t.Error("handler should not be called")
	}))

	ctx := context.WithValue(context.Background(), middleware.CampaignStatusKey, pentest.CampaignStatusOnHold)
	req := httptest.NewRequest(http.MethodPost, "/test", nil).WithContext(ctx)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", rec.Code)
	}
}

func TestRequireCampaignWritable_OnHoldAllowsUpdates(t *testing.T) {
	mw := middleware.RequireCampaignWritable(true) // updating existing item
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	ctx := context.WithValue(context.Background(), middleware.CampaignStatusKey, pentest.CampaignStatusOnHold)
	req := httptest.NewRequest(http.MethodPut, "/test", nil).WithContext(ctx)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
}

func TestRequireCampaignWritable_InProgressOK(t *testing.T) {
	mw := middleware.RequireCampaignWritable(false)
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	ctx := context.WithValue(context.Background(), middleware.CampaignStatusKey, pentest.CampaignStatusInProgress)
	req := httptest.NewRequest(http.MethodPost, "/test", nil).WithContext(ctx)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
}
