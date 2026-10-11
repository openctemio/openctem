package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	easmapp "github.com/openctemio/openctem/api/internal/app/easm"
	"github.com/openctemio/openctem/api/pkg/domain/easmseed"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

type fakeNetworkSeeds struct {
	tenants []shared.ID
	expand  error
}

func (f *fakeNetworkSeeds) List(_ context.Context, id shared.ID) ([]easmapp.SeedView, error) {
	f.tenants = append(f.tenants, id)
	return []easmapp.SeedView{}, nil
}
func (f *fakeNetworkSeeds) Create(_ context.Context, id shared.ID, _ *shared.ID, kind easmseed.Kind, value, _ string) (*easmapp.SeedView, error) {
	f.tenants = append(f.tenants, id)
	norm, err := easmseed.Normalize(kind, value)
	if err != nil {
		return nil, shared.ErrValidation
	}
	return &easmapp.SeedView{Seed: easmseed.Seed{ID: "s1", Kind: kind, Value: norm}}, nil
}
func (f *fakeNetworkSeeds) Delete(_ context.Context, _ shared.ID, id string) error {
	if id != "s1" {
		return shared.ErrNotFound
	}
	return nil
}
func (f *fakeNetworkSeeds) Expand(context.Context, shared.ID, string) error { return f.expand }

func TestEASMNetworkSeedHandler(t *testing.T) {
	tenantID := shared.NewID()
	svc := &fakeNetworkSeeds{}
	aud := &settingsAudit{}
	h := NewEASMNetworkSeedHandler(svc, aud, logger.NewNop())

	w := httptest.NewRecorder()
	h.Create(w, seedReq(http.MethodPost, "/", `{"kind":"asn","value":"13335"}`, tenantID, "u1"))
	if w.Code != http.StatusCreated || !strings.Contains(w.Body.String(), `"value":"AS13335"`) || svc.tenants[0] != tenantID {
		t.Fatalf("create: %d %s", w.Code, w.Body.String())
	}
	for _, body := range []string{`{"kind":"asn","value":"AS64512"}`, `{"kind":"cidr","value":"10.0.0.0/8"}`, `nope`} {
		w = httptest.NewRecorder()
		h.Create(w, seedReq(http.MethodPost, "/", body, tenantID, "u1"))
		if w.Code != http.StatusBadRequest {
			t.Errorf("%s: %d", body, w.Code)
		}
	}
	r := seedReq(http.MethodDelete, "/", "", tenantID, "u1")
	r.SetPathValue("id", "other")
	w = httptest.NewRecorder()
	h.Delete(w, r)
	if w.Code != http.StatusNotFound {
		t.Fatalf("delete unknown: %d", w.Code)
	}
	svc.expand = easmapp.ErrExpandTooSoon
	r = seedReq(http.MethodPost, "/", "", tenantID, "u1")
	r.SetPathValue("id", "s1")
	w = httptest.NewRecorder()
	h.Expand(w, r)
	if w.Code != http.StatusTooManyRequests || w.Header().Get("Retry-After") == "" {
		t.Fatalf("expand too soon: %d", w.Code)
	}
	if len(aud.actions) == 0 || aud.actions[0] != "easm_network_seed.added" {
		t.Fatal("create not audited")
	}
}
