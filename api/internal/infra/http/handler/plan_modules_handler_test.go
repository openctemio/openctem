package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/internal/app/entitlement"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/domain/admin"
	moduledom "github.com/openctemio/openctem/api/pkg/domain/module"
	"github.com/openctemio/openctem/api/pkg/domain/plan"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

type moduleMemRepo struct {
	mu     sync.Mutex
	grants map[string]plan.ModuleGrant
}

func (m *moduleMemRepo) GetPlanModules(context.Context) (plan.PlanModules, int, error) {
	return nil, 0, shared.ErrNotFound
}

func (m *moduleMemRepo) SavePlanModules(context.Context, plan.PlanModules, int, shared.ID, time.Time) (int, error) {
	return 1, nil
}

func (m *moduleMemRepo) ListModuleGrants(context.Context, shared.ID) ([]plan.ModuleGrant, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := []plan.ModuleGrant{}
	for _, g := range m.grants {
		out = append(out, g)
	}
	return out, nil
}

func (m *moduleMemRepo) SetModuleGrant(_ context.Context, g plan.ModuleGrant) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.grants[g.ModuleID] = g
	return nil
}

func (m *moduleMemRepo) DeleteModuleGrant(_ context.Context, _ shared.ID, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.grants[id]; !ok {
		return shared.ErrNotFound
	}
	delete(m.grants, id)
	return nil
}

// Granting, denying and removing a grant change what an organization may use:
// each needs a reason and a fresh authenticator code, checked before anything
// is written.
func TestPlanHandler_ModuleGrantsNeedStepUp(t *testing.T) {
	tenantID := shared.NewID()
	newH := func(stepErr error) (*PlanHandler, *moduleMemRepo) {
		repo := &moduleMemRepo{grants: map[string]plan.ModuleGrant{}}
		svc := entitlement.NewService(newPlanMemRepo(), nil, nil, nil, logger.NewNop())
		svc.SetModuleRepository(repo)
		return NewPlanHandler(svc, fakeStepUp{err: stepErr}, logger.NewNop()), repo
	}
	req := func(method string, body any) *http.Request {
		r := planAdminRequest(t, method, "/", body, admin.AdminRoleOpsAdmin)
		r.SetPathValue(middleware.AdminTenantParam, tenantID.String())
		r.SetPathValue("module_id", moduledom.ModulePentest)
		return r
	}
	grant := map[string]any{"kind": "grant", "reason": "14-day trial", "totp_code": "123456"}
	remove := map[string]any{"reason": "trial ended early", "totp_code": "123456"}

	t.Run("grant without a code: step-up required, nothing written", func(t *testing.T) {
		h, repo := newH(nil)
		rec := httptest.NewRecorder()
		h.SetModuleGrant(rec, req(http.MethodPut, map[string]any{"kind": "grant", "reason": "trial"}))
		if rec.Code != http.StatusUnauthorized || decodeCode(t, rec) != string(codeStepUpRequired) || len(repo.grants) != 0 {
			t.Fatalf("%d %s", rec.Code, rec.Body)
		}
	})
	t.Run("deny with a wrong code refused", func(t *testing.T) {
		h, repo := newH(admin.ErrInvalidMFACode)
		rec := httptest.NewRecorder()
		h.SetModuleGrant(rec, req(http.MethodPut, map[string]any{"kind": "deny", "reason": "contract", "totp_code": "000000"}))
		if rec.Code != http.StatusUnauthorized || len(repo.grants) != 0 {
			t.Fatalf("%d %s", rec.Code, rec.Body)
		}
	})
	t.Run("invalid input refused before the code is checked", func(t *testing.T) {
		h, repo := newH(admin.ErrInvalidMFACode)
		rec := httptest.NewRecorder()
		h.SetModuleGrant(rec, req(http.MethodPut, map[string]any{"kind": "grant", "reason": " ", "totp_code": "123456"}))
		if rec.Code != http.StatusBadRequest || len(repo.grants) != 0 {
			t.Fatalf("%d %s", rec.Code, rec.Body)
		}
	})
	t.Run("grant with a code, then removal needs a reason and a code", func(t *testing.T) {
		h, repo := newH(nil)
		rec := httptest.NewRecorder()
		h.SetModuleGrant(rec, req(http.MethodPut, grant))
		if rec.Code != http.StatusOK || len(repo.grants) != 1 {
			t.Fatalf("grant: %d %s", rec.Code, rec.Body)
		}
		rec = httptest.NewRecorder()
		h.DeleteModuleGrant(rec, req(http.MethodDelete, map[string]any{"totp_code": "123456"}))
		if rec.Code != http.StatusBadRequest || len(repo.grants) != 1 {
			t.Fatalf("remove without a reason: %d %s", rec.Code, rec.Body)
		}
		rec = httptest.NewRecorder()
		h.DeleteModuleGrant(rec, req(http.MethodDelete, map[string]any{"reason": "trial ended early"}))
		if rec.Code != http.StatusUnauthorized || decodeCode(t, rec) != string(codeStepUpRequired) || len(repo.grants) != 1 {
			t.Fatalf("remove without a code: %d %s", rec.Code, rec.Body)
		}
		rec = httptest.NewRecorder()
		h.DeleteModuleGrant(rec, req(http.MethodDelete, remove))
		if rec.Code != http.StatusOK || len(repo.grants) != 0 {
			t.Fatalf("remove: %d %s", rec.Code, rec.Body)
		}
	})
	t.Run("removal with an unenrolled authenticator refused", func(t *testing.T) {
		h, repo := newH(admin.ErrStepUpUnavailable)
		repo.grants[moduledom.ModulePentest] = plan.ModuleGrant{TenantID: tenantID, ModuleID: moduledom.ModulePentest, Kind: plan.GrantAdd, Reason: "x"}
		rec := httptest.NewRecorder()
		h.DeleteModuleGrant(rec, req(http.MethodDelete, remove))
		if rec.Code != http.StatusForbidden || len(repo.grants) != 1 {
			t.Fatalf("%d %s", rec.Code, rec.Body)
		}
	})
}

func (m *moduleMemRepo) ListModuleGrace(context.Context, shared.ID) (map[string]time.Time, error) {
	return map[string]time.Time{}, nil
}

func (m *moduleMemRepo) StartModuleGrace(context.Context, shared.ID, []string, time.Time) error {
	return nil
}

func (m *moduleMemRepo) EndModuleGrace(context.Context, shared.ID, []string) error { return nil }

func (m *moduleMemRepo) StartPlanModuleGrace(context.Context, plan.Plan, []string, time.Time) error {
	return nil
}

func (m *moduleMemRepo) EndPlanModuleGrace(context.Context, plan.Plan, []string) error { return nil }
