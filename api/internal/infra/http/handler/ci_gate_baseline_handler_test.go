package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	cirunapp "github.com/openctemio/openctem/api/internal/app/cirun"
	"github.com/openctemio/openctem/api/pkg/domain/cirun"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

type fakeBaselineService struct{ calls int }

func (f *fakeBaselineService) GetGateBaseline(_ context.Context, t, id shared.ID) (*cirun.GateBaseline, error) {
	f.calls++
	return &cirun.GateBaseline{TenantID: t, RepositoryAssetID: id}, nil
}

func (f *fakeBaselineService) SetGateBaseline(_ context.Context, t, id shared.ID, _ cirunapp.Actor) (*cirun.GateBaseline, error) {
	f.calls++
	return &cirun.GateBaseline{TenantID: t, RepositoryAssetID: id}, nil
}

func (f *fakeBaselineService) DeleteGateBaseline(context.Context, shared.ID, shared.ID, cirunapp.Actor) error {
	f.calls++
	return nil
}

// A repository outside the caller's data scope: every baseline route is a
// 404 and never reaches the service; in scope it does.
func TestCIGateBaselineHandlerIsolation(t *testing.T) {
	tenant := shared.NewID()
	scope := &shared.DataScope{TenantID: tenant, UserID: shared.NewID()}
	svc := &fakeBaselineService{}
	h := NewCIAdminHandler(&fakeCIService{}, scopeOnly{scope: scope}, logger.NewNop())
	h.SetGateBaselineService(svc)
	routes := []struct {
		method string
		call   func(http.ResponseWriter, *http.Request)
		ok     int
	}{
		{http.MethodGet, h.GetGateBaseline, http.StatusOK},
		{http.MethodPut, h.SetGateBaseline, http.StatusOK},
		{http.MethodDelete, h.DeleteGateBaseline, http.StatusNoContent},
	}
	for _, rt := range routes {
		r := tenantRequest(rt.method, "/", "", tenant)
		r.SetPathValue("id", shared.NewID().String())
		w := httptest.NewRecorder()
		rt.call(w, r)
		if w.Code != http.StatusNotFound || svc.calls != 0 {
			t.Fatalf("%s out of scope: %d (service called %d)", rt.method, w.Code, svc.calls)
		}
	}
	open := NewCIAdminHandler(&fakeCIService{}, nil, logger.NewNop())
	open.SetGateBaselineService(svc)
	for i, rt := range []func(http.ResponseWriter, *http.Request){open.GetGateBaseline, open.SetGateBaseline, open.DeleteGateBaseline} {
		r := tenantRequest(routes[i].method, "/", "", tenant)
		r.SetPathValue("id", shared.NewID().String())
		w := httptest.NewRecorder()
		rt(w, r)
		if w.Code != routes[i].ok {
			t.Fatalf("%s in scope: %d", routes[i].method, w.Code)
		}
	}
	// Not wired: 404.
	bare := NewCIAdminHandler(&fakeCIService{}, nil, logger.NewNop())
	r := tenantRequest(http.MethodGet, "/", "", tenant)
	r.SetPathValue("id", shared.NewID().String())
	w := httptest.NewRecorder()
	bare.GetGateBaseline(w, r)
	if w.Code != http.StatusNotFound {
		t.Fatalf("unwired: %d", w.Code)
	}
}
