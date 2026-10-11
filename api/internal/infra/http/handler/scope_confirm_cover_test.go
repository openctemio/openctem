package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/scope"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/attribution"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

type fakeCover struct {
	tenant string
	ids    []string
	calls  int
}

func (f *fakeCover) CoverConfirmedAssets(_ context.Context, tenantID string, _ scope.Actor, ids []string) (*scope.ConfirmCoverage, error) {
	f.calls++
	f.tenant, f.ids = tenantID, ids
	return &scope.ConfirmCoverage{Added: 1}, nil
}

// A confirmation on an asset's attribution adds it to scope for the caller's
// own tenant and says so; a rejection and an out-of-scope asset do not.
func TestAssetAttributionHandler_ConfirmAddsToScope(t *testing.T) {
	tenant := shared.NewID()
	cover := &fakeCover{}
	reader := &fakeAttrReader{found: true, view: &postgres.AttributionView{Record: attribution.Record{State: attribution.StateNeedsReview}}}
	h := NewAssetAttributionHandler(reader, fakeScopedAssets{}, logger.NewNop())
	h.SetScopeCover(cover)

	rec := putAttribution(t, h, tenant, `{"state":"confirmed"}`)
	var body AssetAttributionResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if rec.Code != http.StatusOK || cover.calls != 1 || cover.tenant != tenant.String() || len(cover.ids) != 1 {
		t.Fatalf("confirm: %d, cover %+v", rec.Code, cover)
	}
	if body.Scope == nil || body.Scope.Added != 1 {
		t.Fatalf("response scope %+v, want added 1", body.Scope)
	}

	if rec := putAttribution(t, h, tenant, `{"state":"rejected"}`); rec.Code != http.StatusOK || cover.calls != 1 {
		t.Fatalf("a rejection widened scope: %d calls", cover.calls)
	}

	h = NewAssetAttributionHandler(&fakeAttrReader{}, fakeScopedAssets{err: shared.ErrForbidden}, logger.NewNop())
	h.SetScopeCover(cover)
	if rec := putAttribution(t, h, tenant, `{"state":"confirmed"}`); rec.Code != http.StatusNotFound || cover.calls != 1 {
		t.Fatalf("an out-of-scope asset reached scope: %d, calls %d", rec.Code, cover.calls)
	}
}
