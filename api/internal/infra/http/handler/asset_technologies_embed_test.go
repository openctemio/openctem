package handler

import (
	"context"
	"net/http/httptest"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/assettech"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

type fakeTechReader struct {
	tenant   shared.ID
	perAsset int
	rows     map[shared.ID][]assettech.Technology
}

func (f *fakeTechReader) ListByAsset(context.Context, shared.ID, shared.ID) ([]assettech.Technology, error) {
	return nil, nil
}

func (f *fakeTechReader) ListByAssets(_ context.Context, tenantID shared.ID, _ []shared.ID, perAsset int) (map[shared.ID][]assettech.Technology, error) {
	f.tenant, f.perAsset = tenantID, perAsset
	return f.rows, nil
}

func (f *fakeTechReader) Enrich(context.Context, shared.ID, []assettech.Technology) error { return nil }

// Asset responses carry the asset's technologies, read under the caller's
// tenant with the list or single-asset cap.
func TestAddTechnologies(t *testing.T) {
	tenant, a, b := shared.NewID(), shared.NewID(), shared.NewID()
	repo := &fakeTechReader{rows: map[shared.ID][]assettech.Technology{
		a: {{Name: "nginx", Version: "1.25.3", Category: assettech.CategoryWebServer}, {Name: "HSTS", Category: assettech.CategorySecurityHeader}},
	}}
	h := &AssetHandler{logger: logger.NewNop()}
	h.SetTechnologyReader(repo)
	out := []*AssetResponse{{ID: a.String()}, {ID: b.String()}}
	h.addTechnologies(httptest.NewRequest("GET", "/", nil), tenant.String(), listTechnologiesPerAsset, out)
	if repo.tenant != tenant || repo.perAsset != listTechnologiesPerAsset {
		t.Fatalf("read under %s cap %d", repo.tenant, repo.perAsset)
	}
	if len(out[0].Technologies) != 2 || out[0].Technologies[0].Version != "1.25.3" || out[0].Technologies[1].Category != "security_header" {
		t.Fatalf("asset a: %+v", out[0].Technologies)
	}
	if out[1].Technologies != nil {
		t.Fatalf("asset b: %+v", out[1].Technologies)
	}
}
