package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/domain/admin"
	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/tool"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// mappingRepoSpy records writes; any other call panics (the embedded nil
// interface), which proves a refused request never reached the store.
type mappingRepoSpy struct {
	tool.TargetMappingRepository
	stored *tool.TargetAssetTypeMapping
	writes int
}

func (s *mappingRepoSpy) Create(_ context.Context, m *tool.TargetAssetTypeMapping) error {
	s.writes++
	return nil
}
func (s *mappingRepoSpy) GetByID(context.Context, shared.ID) (*tool.TargetAssetTypeMapping, error) {
	return s.stored, nil
}
func (s *mappingRepoSpy) Update(context.Context, *tool.TargetAssetTypeMapping) error {
	s.writes++
	return nil
}
func (s *mappingRepoSpy) Delete(context.Context, shared.ID) error { s.writes++; return nil }

func mappingReq(method, body string, role admin.AdminRole, id shared.ID) *http.Request {
	now := time.Now()
	a := admin.Reconstitute(shared.NewID(), "a@x.io", "A", role, true,
		nil, nil, "", 0, nil, nil, "", now, nil, now)
	r := httptest.NewRequest(method, "/api/v1/admin/target-mappings/"+id.String(), strings.NewReader(body))
	rc := chi.NewRouteContext()
	rc.URLParams.Add("id", id.String())
	ctx := context.WithValue(r.Context(), chi.RouteCtxKey, rc)
	ctx = context.WithValue(ctx, middleware.AdminUserKey, a)
	return r.WithContext(ctx)
}

// A mapping change is a super admin decision that carries a reason (10 to 500
// characters, kept in the audit row). An operations or read-only administrator
// is refused whatever the body says, and a missing, short or over-long reason
// is a 400 before the store is touched.
func TestTargetMappingWritesNeedSuperAdminAndReason(t *testing.T) {
	id := shared.NewID()
	good := `"reason":"Mapping reviewed with the scanning team, ticket 4411"`
	long := `"reason":"` + strings.Repeat("x", 501) + `"`
	call := map[string]func(h *AdminTargetMappingHandler, w http.ResponseWriter, r *http.Request){
		http.MethodPost:   func(h *AdminTargetMappingHandler, w http.ResponseWriter, r *http.Request) { h.Create(w, r) },
		http.MethodPatch:  func(h *AdminTargetMappingHandler, w http.ResponseWriter, r *http.Request) { h.Update(w, r) },
		http.MethodDelete: func(h *AdminTargetMappingHandler, w http.ResponseWriter, r *http.Request) { h.Delete(w, r) },
	}
	bodyFor := func(method, reason string) string {
		extra := ""
		if method == http.MethodPost {
			extra = `"target_type":"url","asset_type":"website",`
		}
		if method == http.MethodPatch {
			extra = `"is_active":false,`
		}
		if reason == "" {
			return "{" + strings.TrimSuffix(extra, ",") + "}"
		}
		return "{" + extra + reason + "}"
	}
	for method, fn := range call {
		for _, role := range []admin.AdminRole{admin.AdminRoleReadonly, admin.AdminRoleOpsAdmin} {
			spy := &mappingRepoSpy{}
			h := NewAdminTargetMappingHandler(spy, logger.NewNop())
			w := httptest.NewRecorder()
			fn(h, w, mappingReq(method, bodyFor(method, good), role, id))
			if w.Code != http.StatusForbidden || spy.writes != 0 {
				t.Errorf("%s as %s: %d writes=%d, want 403 and no write", method, role, w.Code, spy.writes)
			}
		}
		for name, reason := range map[string]string{
			"missing":   "",
			"too short": `"reason":"too short"`,
			"too long":  long,
			"blank":     `"reason":"             "`,
		} {
			spy := &mappingRepoSpy{}
			h := NewAdminTargetMappingHandler(spy, logger.NewNop())
			w := httptest.NewRecorder()
			fn(h, w, mappingReq(method, bodyFor(method, reason), admin.AdminRoleSuperAdmin, id))
			if w.Code != http.StatusBadRequest || spy.writes != 0 {
				t.Errorf("%s with %s reason: %d writes=%d, want 400 and no write", method, name, w.Code, spy.writes)
			}
		}
		// A DELETE with no body at all is the same refusal.
		if method == http.MethodDelete {
			spy := &mappingRepoSpy{}
			h := NewAdminTargetMappingHandler(spy, logger.NewNop())
			w := httptest.NewRecorder()
			h.Delete(w, mappingReq(method, "", admin.AdminRoleSuperAdmin, id))
			if w.Code != http.StatusBadRequest || spy.writes != 0 {
				t.Errorf("DELETE without a body: %d writes=%d, want 400", w.Code, spy.writes)
			}
		}
		// With a reason a super admin's write goes through.
		spy := &mappingRepoSpy{stored: tool.NewTargetAssetTypeMapping("url", asset.AssetType("website"))}
		h := NewAdminTargetMappingHandler(spy, logger.NewNop())
		w := httptest.NewRecorder()
		fn(h, w, mappingReq(method, bodyFor(method, good), admin.AdminRoleSuperAdmin, id))
		if (w.Code != http.StatusCreated && w.Code != http.StatusOK && w.Code != http.StatusNoContent) || spy.writes != 1 {
			t.Errorf("%s as super admin with a reason: %d writes=%d (%s)", method, w.Code, spy.writes, w.Body.String())
		}
	}
}
