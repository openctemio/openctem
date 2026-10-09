package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/openctemio/openctem/api/internal/app/scope"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	scopedom "github.com/openctemio/openctem/api/pkg/domain/scope"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/pagination"
	"github.com/openctemio/openctem/api/pkg/validator"
)

// oneTargetRepo serves a single scope target (GetByID, tenant-checked).
type oneTargetRepo struct{ t *scopedom.Target }

func (r oneTargetRepo) Create(context.Context, *scopedom.Target) error { return nil }
func (r oneTargetRepo) GetByID(_ context.Context, tenantID, id shared.ID) (*scopedom.Target, error) {
	if r.t.TenantID() != tenantID || r.t.ID() != id {
		return nil, scopedom.ErrTargetNotFound
	}
	return r.t, nil
}
func (r oneTargetRepo) Update(context.Context, *scopedom.Target) error     { return nil }
func (r oneTargetRepo) Delete(context.Context, shared.ID, shared.ID) error { return nil }
func (r oneTargetRepo) List(context.Context, scopedom.TargetFilter, pagination.Pagination) (pagination.Result[*scopedom.Target], error) {
	return pagination.Result[*scopedom.Target]{}, nil
}
func (r oneTargetRepo) ListActive(context.Context, shared.ID) ([]*scopedom.Target, error) {
	return nil, nil
}
func (r oneTargetRepo) Count(context.Context, scopedom.TargetFilter) (int64, error) { return 0, nil }
func (r oneTargetRepo) ExistsByPattern(context.Context, shared.ID, scopedom.TargetType, string) (bool, error) {
	return false, nil
}

type staticApprovers []scopedom.Approver

func (s staticApprovers) ScopeApprovers(context.Context, shared.ID) ([]scopedom.Approver, error) {
	return s, nil
}

// A pending entry names its approvers only to a caller who may see the
// organization's members; everyone with scope:read sees the count. No email
// is ever returned.
func TestScopeTargetResponse_ApproverNamesFollowMemberVisibility(t *testing.T) {
	tenantID := shared.NewID()
	requester, approver := shared.NewID().String(), shared.NewID().String()
	exp := time.Now().Add(48 * time.Hour)
	e, err := scopedom.NewEntry(tenantID, scopedom.TargetTypeDomain, "t2.example.test", "", requester, scopedom.EntryOptions{
		Reason: "window", ExpiresAt: &exp, MaxTier: scopedom.TierIntrusive, ApprovalsRequired: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	svc := scope.NewService(oneTargetRepo{e}, nil, nil, logger.NewNop())
	svc.SetApprovers(staticApprovers{
		{UserID: requester, Name: "Rita", Email: "rita@example.test", Owner: true},
		{UserID: approver, Name: "Adam", Email: "adam@example.test"},
	}, nil, nil, nil, "")
	h := NewScopeHandler(svc, validator.New(), logger.NewNop())

	get := func(perms []string) map[string]any {
		ctx := context.WithValue(context.Background(), middleware.TenantIDKey, tenantID.String())
		ctx = context.WithValue(ctx, middleware.UserIDKey, shared.NewID().String())
		ctx = context.WithValue(ctx, middleware.IsAdminKey, false)
		ctx = context.WithValue(ctx, middleware.FetchedPermissionsKey, perms)
		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("id", e.ID().String())
		ctx = context.WithValue(ctx, chi.RouteCtxKey, rctx)
		rec := httptest.NewRecorder()
		h.GetTarget(rec, httptest.NewRequest(http.MethodGet, "/api/v1/scope/targets/x", nil).WithContext(ctx))
		if rec.Code != http.StatusOK {
			t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
		}
		if body := rec.Body.String(); strings.Contains(body, "@example.test") {
			t.Fatalf("an email address was returned: %s", body)
		}
		var out map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		ap, _ := out["approval"].(map[string]any)
		if ap == nil {
			t.Fatalf("no approval status on a pending entry: %v", out)
		}
		return ap
	}

	withNames := get([]string{"attack_surface:scope:read", "team:members:read"})
	names, _ := withNames["eligible_approvers"].([]any)
	if withNames["eligible_approver_count"] != float64(1) || len(names) != 1 {
		t.Fatalf("with team:members:read: %v, want one named approver (not the requester)", withNames)
	}
	if n := names[0].(map[string]any); n["id"] != approver || n["name"] != "Adam" {
		t.Fatalf("approver %v", n)
	}
	noNames := get([]string{"attack_surface:scope:read"})
	if _, ok := noNames["eligible_approvers"]; ok || noNames["eligible_approver_count"] != float64(1) {
		t.Fatalf("without team:members:read: %v, want the count only", noNames)
	}
	if noNames["self_approval_available"] != false {
		t.Fatal("self-approval offered to someone who did not request the entry")
	}
}
