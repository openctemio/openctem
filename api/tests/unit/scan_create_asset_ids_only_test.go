package unit

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	scanservice "github.com/openctemio/openctem/api/internal/app/scan"
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/validator"
)

// ownedNamed lets every target through and names assets by id.
type ownedNamed struct {
	allOwned
	names map[shared.ID]string
}

func (o ownedNamed) AssetTargets(_ context.Context, _ shared.ID, ids []shared.ID) (map[shared.ID][]string, error) {
	out := map[shared.ID][]string{}
	for _, id := range ids {
		if n, ok := o.names[id]; ok {
			out[id] = []string{n}
		}
	}
	return out, nil
}

// New Scan sends picked assets as asset_ids only when nothing is typed
// (#1613). The handler refused such a request ("Either asset_group_id ...
// or targets must be provided") before the service could name the assets.
func TestCreateScanHandler_AssetIDsOnly(t *testing.T) {
	assetID := shared.NewID()
	svc, deps := newTestScanService(scanservice.WithAttributionGate(ownedNamed{names: map[shared.ID]string{assetID: "app.example.com"}}))
	deps.toolRepo.addTool("nuclei", true)
	h := handler.NewScanHandler(svc, nil, nil, validator.New(), logger.NewNop())
	tenantID := shared.NewID()

	post := func(body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/scans", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		ctx := context.WithValue(req.Context(), middleware.TenantIDKey, tenantID.String())
		ctx = context.WithValue(ctx, middleware.UserIDKey, shared.NewID().String())
		w := httptest.NewRecorder()
		h.CreateScan(w, req.WithContext(ctx))
		return w
	}

	w := post(`{"name":"picked","scan_type":"single","scanner_name":"nuclei","asset_ids":["` + assetID.String() + `"]}`)
	if w.Code != http.StatusCreated {
		t.Fatalf("asset_ids only: status %d: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "app.example.com") {
		t.Errorf("the created scan does not target the named asset: %s", w.Body.String())
	}

	// Nothing at all is still refused.
	w = post(`{"name":"empty","scan_type":"single","scanner_name":"nuclei"}`)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("no targets: status %d, want 400: %s", w.Code, w.Body.String())
	}
}
