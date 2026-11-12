package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/cirun"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

type fakeRepoSettings struct{ calls int }

func (f *fakeRepoSettings) ResolveRepositoryPolicy(context.Context, shared.ID, shared.ID) (cirun.Resolution, error) {
	f.calls++
	org := cirun.DefaultGatePolicy()
	org.ID, org.ScopeType, org.FailOnSeverity, org.LockedFields = shared.NewID(), cirun.ScopeTenant, "medium", []string{cirun.FieldFailOnSeverity}
	return cirun.Resolve([]cirun.GatePolicy{org}, time.Now()), nil
}

// Out of the caller's data scope: 404 without reaching the service; in
// scope: every field with its value, source and lock.
func TestCIRepositorySettingsHandler(t *testing.T) {
	tenant := shared.NewID()
	svc := &fakeRepoSettings{}
	h := NewCIAdminHandler(&fakeCIService{}, scopeOnly{scope: &shared.DataScope{TenantID: tenant, UserID: shared.NewID()}}, logger.NewNop())
	h.SetRepositorySettingsService(svc)
	r := tenantRequest(http.MethodGet, "/", "", tenant)
	r.SetPathValue("id", shared.NewID().String())
	w := httptest.NewRecorder()
	h.GetRepositorySettings(w, r)
	if w.Code != http.StatusNotFound || svc.calls != 0 {
		t.Fatalf("out of scope: %d (service called %d)", w.Code, svc.calls)
	}
	open := NewCIAdminHandler(&fakeCIService{}, nil, logger.NewNop())
	open.SetRepositorySettingsService(svc)
	r = tenantRequest(http.MethodGet, "/", "", tenant)
	r.SetPathValue("id", shared.NewID().String())
	w = httptest.NewRecorder()
	open.GetRepositorySettings(w, r)
	var out CIRepositorySettingsResponse
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &out) != nil || len(out.Fields) != len(cirun.PolicyFields) {
		t.Fatalf("in scope: %d %s", w.Code, w.Body.String())
	}
	if f := out.Fields[1]; f.Field != cirun.FieldFailOnSeverity || f.Value != "medium" || f.Source != cirun.ScopeTenant || f.LockedBy != cirun.ScopeTenant {
		t.Fatalf("severity field: %+v", f)
	}
}
