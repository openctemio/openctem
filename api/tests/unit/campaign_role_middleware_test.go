package unit

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/domain/pentest"
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

// --- CampaignRoleResolver ---

type fakeCampaignRoles map[string]pentest.CampaignRole // userID -> role

func (f fakeCampaignRoles) GetUserRole(_ context.Context, _, _, userID string) (pentest.CampaignRole, error) {
	return f[userID], nil
}

// The campaign under test (resolvedRole's tenant and campaign) exists.
const (
	testTenant   = "11111111-1111-1111-1111-111111111111"
	testCampaign = "22222222-2222-2222-2222-222222222222"
)

func (f fakeCampaignRoles) CampaignExists(_ context.Context, tenantID, campaignID string) (bool, error) {
	return tenantID == testTenant && campaignID == testCampaign, nil
}

// resolverStatus runs the resolver for a caller with no campaign role and
// returns the response code and whether the handler ran.
func resolverStatus(t *testing.T, tenantID, campaignID string, admin bool) (int, bool) {
	t.Helper()
	ran := false
	h := middleware.CampaignRoleResolver(fakeCampaignRoles{})(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		ran = true
		w.WriteHeader(http.StatusOK)
	}))
	r := chi.NewRouter()
	r.Handle("/campaigns/{id}", h)
	ctx := context.WithValue(context.Background(), middleware.UserIDKey, "someone")
	ctx = context.WithValue(ctx, middleware.TenantIDKey, tenantID)
	if admin {
		ctx = context.WithValue(ctx, middleware.IsAdminKey, true)
	}
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/campaigns/"+campaignID, nil).WithContext(ctx))
	return rec.Code, ran
}

// Another organization's campaign is not found, for an admin too (who would
// otherwise pass RequireCampaignRole and read an empty list or zero stats).
func TestCampaignRoleResolver_OtherTenantCampaignNotFound(t *testing.T) {
	for _, admin := range []bool{true, false} {
		code, ran := resolverStatus(t, "33333333-3333-3333-3333-333333333333", testCampaign, admin)
		if code != http.StatusNotFound || ran {
			t.Errorf("admin=%v: other tenant's campaign: got %d (handler ran: %v), want 404", admin, code, ran)
		}
	}
}

func TestCampaignRoleResolver_UnknownOrMalformedCampaignNotFound(t *testing.T) {
	for _, id := range []string{"44444444-4444-4444-4444-444444444444", "not-a-uuid"} {
		code, ran := resolverStatus(t, testTenant, id, true)
		if code != http.StatusNotFound || ran {
			t.Errorf("campaign %q: got %d (handler ran: %v), want 404", id, code, ran)
		}
	}
}

// An admin who is not a member reaches their own organization's campaign.
func TestCampaignRoleResolver_AdminNonMemberOwnCampaign(t *testing.T) {
	if code, ran := resolverStatus(t, testTenant, testCampaign, true); code != http.StatusOK || !ran {
		t.Errorf("admin, own campaign: got %d (handler ran: %v), want 200", code, ran)
	}
}

func resolvedRole(t *testing.T, roles fakeCampaignRoles, userID string, admin bool) pentest.CampaignRole {
	t.Helper()
	var got pentest.CampaignRole
	h := middleware.CampaignRoleResolver(roles)(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		got = middleware.GetCampaignRole(r.Context())
	}))
	r := chi.NewRouter()
	r.Handle("/campaigns/{id}", h)
	ctx := context.WithValue(context.Background(), middleware.UserIDKey, userID)
	ctx = context.WithValue(ctx, middleware.TenantIDKey, "11111111-1111-1111-1111-111111111111")
	if admin {
		ctx = context.WithValue(ctx, middleware.IsAdminKey, true)
	}
	req := httptest.NewRequest(http.MethodGet, "/campaigns/22222222-2222-2222-2222-222222222222", nil).WithContext(ctx)
	r.ServeHTTP(httptest.NewRecorder(), req)
	return got
}

// An org admin who is a member keeps their campaign role, so handlers that
// need membership (test credentials, sign-off) accept an admin lead.
func TestCampaignRoleResolver_AdminMemberGetsRole(t *testing.T) {
	roles := fakeCampaignRoles{"admin-lead": pentest.CampaignRoleLead}
	if got := resolvedRole(t, roles, "admin-lead", true); got != pentest.CampaignRoleLead {
		t.Errorf("admin lead: expected lead, got %q", got)
	}
}

func TestCampaignRoleResolver_AdminNonMemberHasNoRole(t *testing.T) {
	if got := resolvedRole(t, fakeCampaignRoles{}, "admin", true); got != "" {
		t.Errorf("admin non-member: expected no role, got %q", got)
	}
}

func TestCampaignRoleResolver_Member(t *testing.T) {
	roles := fakeCampaignRoles{"tester": pentest.CampaignRoleTester}
	if got := resolvedRole(t, roles, "tester", false); got != pentest.CampaignRoleTester {
		t.Errorf("member: expected tester, got %q", got)
	}
}
