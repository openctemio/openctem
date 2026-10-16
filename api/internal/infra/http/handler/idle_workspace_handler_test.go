package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/internal/app/lifecycle"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/domain/admin"
	lifecycledom "github.com/openctemio/openctem/api/pkg/domain/lifecycle"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

type idleMemRepo struct {
	policy lifecycledom.Policy
}

func (m *idleMemRepo) Workspaces(context.Context) ([]lifecycledom.Workspace, error) {
	return nil, nil
}
func (m *idleMemRepo) SetStage(context.Context, shared.ID, lifecycledom.Stage, time.Time) error {
	return nil
}
func (m *idleMemRepo) Status(context.Context, shared.ID) (*lifecycledom.Status, error) {
	return &lifecycledom.Status{Stage: lifecycledom.StageActive, PolicyEnabled: m.policy.Enabled, PolicyReason: m.policy.Reason}, nil
}
func (m *idleMemRepo) SetPolicy(_ context.Context, _ shared.ID, p lifecycledom.Policy) error {
	m.policy = p
	return nil
}
func (m *idleMemRepo) ReadOnly(context.Context, shared.ID) (bool, error)       { return false, nil }
func (m *idleMemRepo) Recipients(context.Context, shared.ID) ([]string, error) { return nil, nil }

func TestIdleWorkspaceHandler(t *testing.T) {
	repo := &idleMemRepo{}
	h := NewIdleWorkspaceHandler(lifecycle.NewService(repo, nil, nil, nil, nil, nil), logger.NewNop())
	id := shared.NewID()
	req := func(method, tid, body string, withAdmin bool) *http.Request {
		r := httptest.NewRequest(method, "/", strings.NewReader(body))
		r.SetPathValue(middleware.AdminTenantParam, tid)
		if withAdmin {
			a, _ := admin.NewAdminUser("op@platform.test", "Op", admin.AdminRoleOpsAdmin, nil)
			r = r.WithContext(context.WithValue(r.Context(), middleware.AdminUserKey, a))
		}
		return r
	}

	rec := httptest.NewRecorder()
	h.Get(rec, req(http.MethodGet, "nope", "", true))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("bad id: %d", rec.Code)
	}
	rec = httptest.NewRecorder()
	h.SetPolicy(rec, req(http.MethodPut, id.String(), `{"enabled":true,"reason":"x"}`, false))
	if rec.Code != http.StatusUnauthorized || repo.policy.Enabled {
		t.Fatalf("no admin: %d", rec.Code)
	}
	rec = httptest.NewRecorder()
	h.SetPolicy(rec, req(http.MethodPut, id.String(), `{"enabled":true,"reason":"  "}`, true))
	if rec.Code != http.StatusBadRequest || repo.policy.Enabled {
		t.Fatalf("no reason: %d", rec.Code)
	}
	rec = httptest.NewRecorder()
	h.SetPolicy(rec, req(http.MethodPut, id.String(), `{"enabled":true,"reason":"hosted free tier"}`, true))
	var resp IdleWorkspaceResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if rec.Code != http.StatusOK || !resp.PolicyEnabled || resp.PolicyReason != "hosted free tier" || resp.Stage != "active" {
		t.Fatalf("enable: %d %+v", rec.Code, resp)
	}
}
