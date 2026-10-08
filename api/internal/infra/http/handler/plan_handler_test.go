package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/internal/app/entitlement"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/domain/admin"
	"github.com/openctemio/openctem/api/pkg/domain/plan"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

type planMemRepo struct {
	mu        sync.Mutex
	defaults  plan.Defaults
	version   int
	plans     map[shared.ID]plan.Plan
	overrides map[shared.ID]map[plan.Key]plan.Override
	usage     map[plan.Key]int
}

func newPlanMemRepo() *planMemRepo {
	return &planMemRepo{plans: map[shared.ID]plan.Plan{}, overrides: map[shared.ID]map[plan.Key]plan.Override{}, usage: map[plan.Key]int{}}
}

func (m *planMemRepo) GetDefaults(context.Context) (plan.Defaults, int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.defaults == nil {
		return nil, 0, shared.ErrNotFound
	}
	return m.defaults, m.version, nil
}

func (m *planMemRepo) SaveDefaults(_ context.Context, d plan.Defaults, v int, _ shared.ID, _ time.Time) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if v != m.version {
		return 0, shared.ErrConflict
	}
	m.defaults, m.version = d, m.version+1
	return m.version, nil
}

func (m *planMemRepo) TenantPlan(_ context.Context, id shared.ID) (plan.Plan, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	p, ok := m.plans[id]
	return p, ok, nil
}

func (m *planMemRepo) SetTenantPlan(_ context.Context, id shared.ID, p plan.Plan, _ *shared.ID, _ time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.plans[id] = p
	return nil
}

func (m *planMemRepo) ListOverrides(_ context.Context, id shared.ID) ([]plan.Override, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := []plan.Override{}
	for _, o := range m.overrides[id] {
		out = append(out, o)
	}
	return out, nil
}

func (m *planMemRepo) SetOverride(_ context.Context, o plan.Override) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.overrides[o.TenantID] == nil {
		m.overrides[o.TenantID] = map[plan.Key]plan.Override{}
	}
	m.overrides[o.TenantID][o.Key] = o
	return nil
}

func (m *planMemRepo) DeleteOverride(_ context.Context, id shared.ID, k plan.Key) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.overrides[id][k]; !ok {
		return shared.ErrNotFound
	}
	delete(m.overrides[id], k)
	return nil
}

func (m *planMemRepo) Usage(context.Context, shared.ID) (map[plan.Key]int, error) {
	return m.usage, nil
}

func (m *planMemRepo) CountOwnedFreeTenants(context.Context, shared.ID) (int, error) { return 0, nil }

func planAdminRequest(t *testing.T, method, path string, body any, role admin.AdminRole) *http.Request {
	t.Helper()
	a, err := admin.NewAdminUser("op@op.example", "Op", role, nil)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if body != nil {
		_ = json.NewEncoder(&buf).Encode(body)
	}
	r := httptest.NewRequest(method, path, &buf)
	return r.WithContext(context.WithValue(r.Context(), middleware.AdminUserKey, a))
}

func decodeCode(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	var body struct {
		Code string `json:"code"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	return body.Code
}

func TestPlanHandler_Defaults(t *testing.T) {
	newH := func(stepErr error) (*PlanHandler, *planMemRepo) {
		repo := newPlanMemRepo()
		return NewPlanHandler(entitlement.NewService(repo, nil, nil, nil, nil), fakeStepUp{err: stepErr}, logger.NewNop()), repo
	}

	t.Run("get returns the built-in Free limits", func(t *testing.T) {
		h, _ := newH(nil)
		rec := httptest.NewRecorder()
		h.GetDefaults(rec, planAdminRequest(t, http.MethodGet, "/api/v1/admin/settings/plans", nil, admin.AdminRoleReadonly))
		var resp PlanDefaultsResponse
		_ = json.Unmarshal(rec.Body.Bytes(), &resp)
		if rec.Code != http.StatusOK || !resp.Unstored || resp.Plans["free"]["seats"] != 5 || resp.Plans["pro"]["seats"] != plan.Unlimited {
			t.Fatalf("%d %+v", rec.Code, resp)
		}
	})

	good := map[string]any{"plans": map[string]map[string]int{"free": {"seats": 3}}, "version": 0, "totp_code": "123456"}

	t.Run("no code: step-up required, nothing saved", func(t *testing.T) {
		h, repo := newH(nil)
		rec := httptest.NewRecorder()
		h.UpdateDefaults(rec, planAdminRequest(t, http.MethodPut, "/", map[string]any{"plans": good["plans"]}, admin.AdminRoleSuperAdmin))
		if rec.Code != http.StatusUnauthorized || decodeCode(t, rec) != string(codeStepUpRequired) || repo.defaults != nil {
			t.Fatalf("%d %s", rec.Code, rec.Body)
		}
	})
	t.Run("wrong code refused", func(t *testing.T) {
		h, repo := newH(admin.ErrInvalidMFACode)
		rec := httptest.NewRecorder()
		h.UpdateDefaults(rec, planAdminRequest(t, http.MethodPut, "/", good, admin.AdminRoleSuperAdmin))
		if rec.Code != http.StatusUnauthorized || repo.defaults != nil {
			t.Fatalf("%d %s", rec.Code, rec.Body)
		}
	})
	t.Run("no authenticator enrolled refused", func(t *testing.T) {
		h, repo := newH(admin.ErrStepUpUnavailable)
		rec := httptest.NewRecorder()
		h.UpdateDefaults(rec, planAdminRequest(t, http.MethodPut, "/", good, admin.AdminRoleSuperAdmin))
		if rec.Code != http.StatusForbidden || repo.defaults != nil {
			t.Fatalf("%d %s", rec.Code, rec.Body)
		}
	})
	t.Run("unknown plan, unknown key, value below -1 refused", func(t *testing.T) {
		for _, plans := range []map[string]map[string]int{
			{"gold": {"seats": 1}}, {"free": {"bogus": 1}}, {"free": {"seats": -2}},
		} {
			h, repo := newH(nil)
			rec := httptest.NewRecorder()
			h.UpdateDefaults(rec, planAdminRequest(t, http.MethodPut, "/", map[string]any{"plans": plans, "totp_code": "1"}, admin.AdminRoleSuperAdmin))
			if rec.Code != http.StatusBadRequest || repo.defaults != nil {
				t.Fatalf("%v: %d %s", plans, rec.Code, rec.Body)
			}
		}
	})
	t.Run("no administrator session refused", func(t *testing.T) {
		h, _ := newH(nil)
		rec := httptest.NewRecorder()
		h.UpdateDefaults(rec, httptest.NewRequest(http.MethodPut, "/", strings.NewReader(`{}`)))
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("%d", rec.Code)
		}
	})
	t.Run("saved, then a stale version conflicts", func(t *testing.T) {
		h, repo := newH(nil)
		rec := httptest.NewRecorder()
		h.UpdateDefaults(rec, planAdminRequest(t, http.MethodPut, "/", good, admin.AdminRoleSuperAdmin))
		if rec.Code != http.StatusOK || repo.version != 1 || repo.defaults.For(plan.Free).Get(plan.Seats) != 3 {
			t.Fatalf("%d %s", rec.Code, rec.Body)
		}
		rec = httptest.NewRecorder()
		h.UpdateDefaults(rec, planAdminRequest(t, http.MethodPut, "/", good, admin.AdminRoleSuperAdmin))
		if rec.Code != http.StatusConflict {
			t.Fatalf("stale: %d %s", rec.Code, rec.Body)
		}
	})
}

func TestPlanHandler_TenantPlan(t *testing.T) {
	repo := newPlanMemRepo()
	h := NewPlanHandler(entitlement.NewService(repo, nil, nil, nil, nil), fakeStepUp{}, logger.NewNop())
	id := shared.NewID()
	repo.plans[id] = plan.Free
	repo.usage[plan.Seats] = 7
	withID := func(r *http.Request, tid, key string) *http.Request {
		r.SetPathValue(middleware.AdminTenantParam, tid)
		if key != "" {
			r.SetPathValue("key", key)
		}
		return r
	}

	t.Run("bad organization id", func(t *testing.T) {
		rec := httptest.NewRecorder()
		h.GetTenantPlan(rec, withID(planAdminRequest(t, http.MethodGet, "/", nil, admin.AdminRoleReadonly), "nope", ""))
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("%d", rec.Code)
		}
	})
	t.Run("over limit is flagged, nothing removed", func(t *testing.T) {
		rec := httptest.NewRecorder()
		h.GetTenantPlan(rec, withID(planAdminRequest(t, http.MethodGet, "/", nil, admin.AdminRoleReadonly), id.String(), ""))
		var resp PlanSummaryResponse
		_ = json.Unmarshal(rec.Body.Bytes(), &resp)
		if rec.Code != http.StatusOK || resp.Plan != "free" || !resp.OverLimit || repo.usage[plan.Seats] != 7 {
			t.Fatalf("%d %+v", rec.Code, resp)
		}
	})
	t.Run("unknown plan refused", func(t *testing.T) {
		rec := httptest.NewRecorder()
		h.SetTenantPlan(rec, withID(planAdminRequest(t, http.MethodPut, "/", map[string]string{"plan": "gold"}, admin.AdminRoleOpsAdmin), id.String(), ""))
		if rec.Code != http.StatusBadRequest || repo.plans[id] != plan.Free {
			t.Fatalf("%d", rec.Code)
		}
	})
	t.Run("override refusals", func(t *testing.T) {
		past := time.Now().Add(-time.Hour)
		for name, c := range map[string]struct {
			key  string
			body SetPlanOverrideRequest
		}{
			"unknown key": {"bogus", SetPlanOverrideRequest{Value: 1, Reason: "r"}},
			"no reason":   {"seats", SetPlanOverrideRequest{Value: 1}},
			"below -1":    {"seats", SetPlanOverrideRequest{Value: -5, Reason: "r"}},
			"past expiry": {"seats", SetPlanOverrideRequest{Value: 9, Reason: "r", ExpiresAt: &past}},
		} {
			rec := httptest.NewRecorder()
			h.SetOverride(rec, withID(planAdminRequest(t, http.MethodPut, "/", c.body, admin.AdminRoleOpsAdmin), id.String(), c.key))
			if rec.Code != http.StatusBadRequest || len(repo.overrides[id]) != 0 {
				t.Fatalf("%s: %d %s", name, rec.Code, rec.Body)
			}
		}
	})
	t.Run("override wins, then removal", func(t *testing.T) {
		rec := httptest.NewRecorder()
		h.SetOverride(rec, withID(planAdminRequest(t, http.MethodPut, "/", SetPlanOverrideRequest{Value: 10, Reason: "pilot"}, admin.AdminRoleOpsAdmin), id.String(), "seats"))
		var resp PlanSummaryResponse
		_ = json.Unmarshal(rec.Body.Bytes(), &resp)
		if rec.Code != http.StatusOK || resp.OverLimit {
			t.Fatalf("%d %+v", rec.Code, resp)
		}
		for _, e := range resp.Limits {
			if e.Key == plan.Seats && (e.Limit != 10 || e.Source != plan.SourceOverride || e.Reason != "pilot") {
				t.Fatalf("seats %+v", e)
			}
		}
		rec = httptest.NewRecorder()
		h.DeleteOverride(rec, withID(planAdminRequest(t, http.MethodDelete, "/", nil, admin.AdminRoleOpsAdmin), id.String(), "seats"))
		if rec.Code != http.StatusOK {
			t.Fatalf("delete %d", rec.Code)
		}
		rec = httptest.NewRecorder()
		h.DeleteOverride(rec, withID(planAdminRequest(t, http.MethodDelete, "/", nil, admin.AdminRoleOpsAdmin), id.String(), "seats"))
		if rec.Code != http.StatusNotFound {
			t.Fatalf("delete again %d", rec.Code)
		}
	})
}

func TestWritePlanLimitError(t *testing.T) {
	rec := httptest.NewRecorder()
	if !WritePlanLimitError(rec, &plan.ErrLimitReached{Key: plan.Seats, Limit: 5, Used: 7}) {
		t.Fatal("not handled")
	}
	var body struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if rec.Code != http.StatusForbidden || body.Code != "PLAN_LIMIT" || body.Message != "Your plan allows 5 seats; you use 7. Remove some, or ask your administrator for more." {
		t.Fatalf("%d %+v", rec.Code, body)
	}
	rec = httptest.NewRecorder()
	WritePlanLimitError(rec, &plan.ErrLimitReached{Key: plan.Seats, Unavailable: true})
	if !strings.Contains(rec.Body.String(), "could not be checked") {
		t.Fatalf("unavailable: %s", rec.Body)
	}
	if WritePlanLimitError(httptest.NewRecorder(), shared.ErrForbidden) {
		t.Fatal("a plain forbidden error is not a plan limit")
	}
}
