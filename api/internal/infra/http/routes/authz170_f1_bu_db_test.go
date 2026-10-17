package routes

// Research 170 (assets authz audit), fork 1: business-unit rollups are
// counted over every asset of the unit, not over the reader's data scope.
// Written to FAIL while the leak exists.

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/asset"
	infrahttp "github.com/openctemio/openctem/api/internal/infra/http"
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// TestAuthz170F1_BusinessUnitCountsTenantWide: a business unit holds only
// asset B1 (outside memberA's scope, with one open high finding). memberA
// lists business units and reads asset_count 1 and finding_count 1.
func TestAuthz170F1_BusinessUnitCountsTenantWide(t *testing.T) {
	h := newDSHarness(t)
	bu := shared.NewID()
	h.exec(`INSERT INTO business_units (id, tenant_id, name) VALUES ($1, $2, 'ds-bu-B')`, bu.String(), h.tenant.String())
	h.exec(`INSERT INTO business_unit_assets (id, tenant_id, business_unit_id, asset_id) VALUES ($1, $2, $3, $4)`,
		shared.NewID().String(), h.tenant.String(), bu.String(), h.assetB.String())
	db := &postgres.DB{DB: h.db}
	repo := postgres.NewBusinessUnitRepository(db)
	if err := repo.RecalculateCounts(t.Context(), h.tenant, bu); err != nil {
		t.Fatal(err)
	}
	svc := asset.NewBusinessUnitService(repo, postgres.NewAssetRepository(db), logger.NewNop())
	svc.SetDataScope(h.enforcer)
	router := infrahttp.NewChiRouter()
	registerBusinessUnitRoutes(router, handler.NewBusinessUnitHandler(svc, logger.NewNop()), Middleware(h.dsAuth), nil, passthrough)
	srv := httptest.NewServer(router.(interface{ Handler() http.Handler }).Handler())
	t.Cleanup(srv.Close)
	h.srv = srv

	status, body := h.do(h.memberA, false, http.MethodGet, "/api/v1/business-units/"+bu.String(), nil)
	if status != http.StatusOK {
		t.Fatalf("GET business unit = %d (%.200s)", status, body)
	}
	if strings.Contains(body, `"asset_count":1`) || strings.Contains(body, `"finding_count":1`) {
		t.Errorf("memberA reads rollups over an out-of-scope asset: %.400s", body)
	}
}
