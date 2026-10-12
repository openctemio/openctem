package routes

// Asset sub-resources under /api/v1/assets/{id}/... over the real routes,
// handlers and a migrated database (research doc 15). A data-scoped member
// must get 404 for every sub-resource of an asset outside their scope, read
// or write, so the reply never reveals that the asset exists; in-scope
// assets and full-data callers keep working.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	infrahttp "github.com/openctemio/openctem/api/internal/infra/http"
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/validator"
)

func (h *dsHarness) serviceCount(assetID shared.ID) int {
	h.t.Helper()
	var n int
	if err := h.db.QueryRowContext(context.Background(),
		`SELECT count(*) FROM asset_services WHERE asset_id = $1`, assetID.String()).Scan(&n); err != nil {
		h.t.Fatal(err)
	}
	return n
}

func dsServiceBody(port int) map[string]any {
	return map[string]any{"protocol": "tcp", "port": port, "service_type": "http", "name": "ds-svc"}
}

// TestDataScope_AssetServices_ListAndCreate covers GET and POST
// /assets/{id}/services for a scoped member, the owner and a full-data role.
func TestDataScope_AssetServices_ListAndCreate(t *testing.T) {
	h := newDSHarness(t)
	b := "/api/v1/assets/" + h.assetB.String() + "/services/"
	a := "/api/v1/assets/" + h.assetA.String() + "/services/"

	// Out of scope: 404 for both, and nothing is written.
	if status, body := h.do(h.memberA, false, http.MethodGet, b, nil); status != http.StatusNotFound {
		t.Errorf("memberA GET out-of-scope services = %d, want 404 (body %.200s)", status, body)
	}
	if status, body := h.do(h.memberA, false, http.MethodPost, b, dsServiceBody(8443)); status != http.StatusNotFound {
		t.Errorf("memberA POST out-of-scope service = %d, want 404 (body %.200s)", status, body)
	}
	if n := h.serviceCount(h.assetB); n != 0 {
		t.Errorf("out-of-scope member created %d service(s) on B1", n)
	}

	// In scope: the scoped member reads and adds.
	if status, body := h.do(h.memberA, false, http.MethodPost, a, dsServiceBody(443)); status != http.StatusCreated {
		t.Errorf("memberA POST in-scope service = %d, want 201 (body %.200s)", status, body)
	}
	if status, body := h.do(h.memberA, false, http.MethodGet, a, nil); status != http.StatusOK || !strings.Contains(body, `"total":1`) {
		t.Errorf("memberA GET in-scope services = %d, want 200 with 1 row (body %.200s)", status, body)
	}

	// Owner and a full-data role reach B1.
	for i, who := range []struct {
		name  string
		user  shared.ID
		admin bool
	}{{"owner", h.owner, true}, {"full-data role", h.memberFull, false}} {
		if status, body := h.do(who.user, who.admin, http.MethodPost, b, dsServiceBody(8000+i)); status != http.StatusCreated {
			t.Errorf("%s POST B1 service = %d, want 201 (body %.200s)", who.name, status, body)
		}
		if status, body := h.do(who.user, who.admin, http.MethodGet, b, nil); status != http.StatusOK {
			t.Errorf("%s GET B1 services = %d, want 200 (body %.200s)", who.name, status, body)
		}
	}
}

// TestDataScope_AssetServices_HandlerChecksScopeWithoutGuard mounts the
// handler with no DataScopeGuard: the handler itself must still hide an
// out-of-scope asset (defense in depth if the route moves to another chain).
func TestDataScope_AssetServices_HandlerChecksScopeWithoutGuard(t *testing.T) {
	h := newDSHarness(t)
	db := &postgres.DB{DB: h.db}
	svc := handler.NewAssetServiceHandler(postgres.NewAssetServiceRepository(db), postgres.NewAssetRepository(db),
		validator.New(), logger.NewNop()).SetDataScope(h.enforcer)
	router := infrahttp.NewChiRouter()
	router.Group("/api/v1/assets/{id}/services", func(r Router) {
		r.GET("/", svc.ListByAsset)
		r.POST("/", svc.Create)
	}, Middleware(h.dsAuth))
	h.srv = httptest.NewServer(router.(interface{ Handler() http.Handler }).Handler())
	t.Cleanup(h.srv.Close)

	b := "/api/v1/assets/" + h.assetB.String() + "/services/"
	if status, body := h.do(h.memberA, false, http.MethodGet, b, nil); status != http.StatusNotFound {
		t.Errorf("unguarded memberA GET out-of-scope services = %d, want 404 (body %.200s)", status, body)
	}
	if status, body := h.do(h.memberA, false, http.MethodPost, b, dsServiceBody(8443)); status != http.StatusNotFound {
		t.Errorf("unguarded memberA POST out-of-scope service = %d, want 404 (body %.200s)", status, body)
	}
	if n := h.serviceCount(h.assetB); n != 0 {
		t.Errorf("unguarded out-of-scope member created %d service(s) on B1", n)
	}
	if status, body := h.do(h.memberFull, false, http.MethodGet, b, nil); status != http.StatusOK {
		t.Errorf("unguarded full-data GET B1 services = %d, want 200 (body %.200s)", status, body)
	}
	a := "/api/v1/assets/" + h.assetA.String() + "/services/"
	if status, body := h.do(h.memberA, false, http.MethodPost, a, dsServiceBody(443)); status != http.StatusCreated {
		t.Errorf("unguarded memberA POST in-scope service = %d, want 201 (body %.200s)", status, body)
	}
}

// TestDataScope_EveryAssetSubresourceRouteIsGuarded walks every route the
// harness registers under /api/v1/assets/{param}/... and asks for it, as a
// scoped member, against an out-of-scope asset. Each one must answer 404: a
// route mounted on a chain without the data-scope guard (or a new
// sub-resource that skips the scope check) fails here.
func TestDataScope_EveryAssetSubresourceRouteIsGuarded(t *testing.T) {
	h := newDSHarness(t)
	firstParam := regexp.MustCompile(`^/api/v1/assets/\{[^}/]+\}`)
	otherParam := regexp.MustCompile(`\{[^}/]+\}`)
	var probed []string
	sawServices := false
	err := h.router.Walk(func(method, route string, _ http.Handler) error {
		if !firstParam.MatchString(route) {
			return nil
		}
		p := firstParam.ReplaceAllString(route, "/api/v1/assets/"+h.assetB.String())
		p = otherParam.ReplaceAllStringFunc(p, func(string) string { return shared.NewID().String() })
		var body any
		if method == http.MethodPost || method == http.MethodPut || method == http.MethodPatch {
			body = map[string]any{}
		}
		status, resp := h.do(h.memberA, false, method, p, body)
		if status != http.StatusNotFound {
			t.Errorf("memberA %s %s = %d, want 404 (body %.200s)", method, route, status, resp)
		}
		if strings.Contains(resp, dsMarkerAssetB) || strings.Contains(resp, dsMarkerFindingB) {
			t.Errorf("memberA %s %s leaked B1 data: %.200s", method, route, resp)
		}
		if strings.Contains(route, "/services") {
			sawServices = true
		}
		probed = append(probed, method+" "+route)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(probed) < 10 || !sawServices {
		t.Fatalf("walk probed %d asset sub-resource routes (services seen: %v); the harness lost its routes", len(probed), sawServices)
	}
}
