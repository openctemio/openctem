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
	exempt lifecycledom.Exemption
}

func (m *idleMemRepo) FreeWorkspaces(context.Context) ([]lifecycledom.Workspace, error) {
	return nil, nil
}
func (m *idleMemRepo) SetStage(context.Context, shared.ID, lifecycledom.Stage, time.Time) error {
	return nil
}
func (m *idleMemRepo) Status(context.Context, shared.ID) (*lifecycledom.Status, error) {
	return &lifecycledom.Status{Stage: lifecycledom.StageActive, Exempt: m.exempt.Exempt, ExemptReason: m.exempt.Reason}, nil
}
func (m *idleMemRepo) SetExemption(_ context.Context, _ shared.ID, e lifecycledom.Exemption) error {
	m.exempt = e
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
	h.SetExemption(rec, req(http.MethodPut, id.String(), `{"exempt":true,"reason":"x"}`, false))
	if rec.Code != http.StatusUnauthorized || repo.exempt.Exempt {
		t.Fatalf("no admin: %d", rec.Code)
	}
	rec = httptest.NewRecorder()
	h.SetExemption(rec, req(http.MethodPut, id.String(), `{"exempt":true,"reason":"  "}`, true))
	if rec.Code != http.StatusBadRequest || repo.exempt.Exempt {
		t.Fatalf("no reason: %d", rec.Code)
	}
	rec = httptest.NewRecorder()
	h.SetExemption(rec, req(http.MethodPut, id.String(), `{"exempt":true,"reason":"design partner"}`, true))
	var resp IdleWorkspaceResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if rec.Code != http.StatusOK || !resp.Exempt || resp.ExemptReason != "design partner" || resp.Stage != "active" {
		t.Fatalf("exempt: %d %+v", rec.Code, resp)
	}
}
