package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	easmapp "github.com/openctemio/openctem/api/internal/app/easm"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/domain/easmseed"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

type fakeSeeder struct {
	tenant shared.ID
	in     easmapp.CreateSeedInput
	err    error
}

func (f *fakeSeeder) List(_ context.Context, tid shared.ID) ([]easmapp.SeedView, error) {
	f.tenant = tid
	return []easmapp.SeedView{}, f.err
}

func (f *fakeSeeder) Create(_ context.Context, tid shared.ID, in easmapp.CreateSeedInput) (*easmapp.SeedView, error) {
	f.tenant, f.in = tid, in
	if f.err != nil {
		return nil, f.err
	}
	return &easmapp.SeedView{ID: shared.NewID().String(), Kind: in.Kind, Value: in.Value}, nil
}

func (f *fakeSeeder) Update(_ context.Context, tid, _ shared.ID, _ *string, _ *bool) (*easmapp.SeedView, error) {
	f.tenant = tid
	return nil, f.err
}

func (f *fakeSeeder) Delete(_ context.Context, tid, id shared.ID) (*easmseed.Seed, error) {
	f.tenant = tid
	if f.err != nil {
		return nil, f.err
	}
	return &easmseed.Seed{ID: id, Kind: easmseed.KindRootDomain, Value: "acme.com"}, nil
}

func seedReq(method, target, body string, tenant shared.ID, user string) *http.Request {
	req := httptest.NewRequest(method, target, strings.NewReader(body))
	ctx := context.WithValue(req.Context(), middleware.TenantIDKey, tenant.String())
	ctx = context.WithValue(ctx, middleware.UserIDKey, user)
	return req.WithContext(ctx)
}

func TestEASMSeedHandler_CreateAuditsWithTheTokenTenant(t *testing.T) {
	tenant, user := shared.NewID(), shared.NewID().String()
	svc := &fakeSeeder{}
	audit := &fakeAuditor{}
	h := NewEASMSeedHandler(svc, audit, logger.NewNop())

	rec := httptest.NewRecorder()
	h.Create(rec, seedReq(http.MethodPost, "/api/v1/easm/seeds",
		`{"kind":"root_domain","value":"acme.com","attested":true,"tenant_id":"`+shared.NewID().String()+`"}`, tenant, user))
	if rec.Code != http.StatusCreated {
		t.Fatalf("status %d: %s", rec.Code, rec.Body)
	}
	// The tenant comes from the token context; a tenant_id in the body is ignored.
	if svc.tenant != tenant || svc.in.ActorID != user || !svc.in.Attested {
		t.Fatalf("tenant %v input %+v", svc.tenant, svc.in)
	}
	if len(audit.events) != 1 {
		t.Fatalf("audit events = %d", len(audit.events))
	}
}

func TestEASMSeedHandler_ErrorsMap(t *testing.T) {
	tenant := shared.NewID()
	for name, tc := range map[string]struct {
		err  error
		code int
	}{
		"validation": {fmt.Errorf("%w: not a domain name", shared.ErrValidation), http.StatusBadRequest},
		"duplicate":  {fmt.Errorf("%w: exists", shared.ErrConflict), http.StatusConflict},
	} {
		rec := httptest.NewRecorder()
		NewEASMSeedHandler(&fakeSeeder{err: tc.err}, nil, logger.NewNop()).
			Create(rec, seedReq(http.MethodPost, "/x", `{"kind":"root_domain","value":"x","attested":true}`, tenant, ""))
		if rec.Code != tc.code {
			t.Errorf("%s: %d, want %d", name, rec.Code, tc.code)
		}
	}

	// Another tenant's seed id is a 404, with no audit record.
	audit := &fakeAuditor{}
	h := NewEASMSeedHandler(&fakeSeeder{err: shared.ErrNotFound}, audit, logger.NewNop())
	req := seedReq(http.MethodDelete, "/x", "", tenant, "")
	req.SetPathValue("id", shared.NewID().String())
	rec := httptest.NewRecorder()
	h.Delete(rec, req)
	if rec.Code != http.StatusNotFound || len(audit.events) != 0 {
		t.Fatalf("foreign delete: %d, %d audit events", rec.Code, len(audit.events))
	}

	rec = httptest.NewRecorder()
	h2 := NewEASMSeedHandler(&fakeSeeder{}, nil, logger.NewNop())
	h2.List(rec, seedReq(http.MethodGet, "/x", "", tenant, ""))
	var body EASMSeedListResponse
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &body) != nil || body.Data == nil {
		t.Fatalf("list: %d %s", rec.Code, rec.Body)
	}
}
