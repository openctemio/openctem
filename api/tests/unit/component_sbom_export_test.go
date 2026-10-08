package unit

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/asset"
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/domain/component"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/validator"
)

func TestListSBOMEntries_WholeInventory(t *testing.T) {
	repo := &mockComponentRepo{sbomEntries: []component.SBOMEntry{{ID: shared.NewID(), Name: "lodash"}}}
	svc := asset.NewComponentService(repo, nil, logger.NewNop())
	tenant := shared.NewID()

	out, err := svc.ListSBOMEntries(context.Background(), tenant.String(), "")
	if err != nil {
		t.Fatal(err)
	}
	if out.Subject != "" || len(out.Entries) != 1 {
		t.Fatalf("got %+v", out)
	}
	if len(repo.sbomCalls) != 1 || repo.sbomCalls[0].tenantID != tenant || repo.sbomCalls[0].assetID != nil {
		t.Fatalf("repository not asked for the caller's tenant only: %+v", repo.sbomCalls)
	}
	if repo.sbomCalls[0].limit != asset.MaxSBOMComponents+1 {
		t.Fatalf("limit %d, want cap+1 to detect an oversized inventory", repo.sbomCalls[0].limit)
	}
}

// An asset of another tenant (or out of scope: the checker answers not
// found) is never exported, and the repository is not even asked.
func TestListSBOMEntries_ForeignAssetNotFound(t *testing.T) {
	repo := &mockComponentRepo{}
	svc := asset.NewComponentService(repo, &stubAssetChecker{err: shared.ErrNotFound}, logger.NewNop())

	_, err := svc.ListSBOMEntries(context.Background(), shared.NewID().String(), shared.NewID().String())
	if !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("want not found, got %v", err)
	}
	if len(repo.sbomCalls) != 0 {
		t.Fatal("components were read for an asset the caller may not see")
	}
}

func TestListSBOMEntries_OneAsset(t *testing.T) {
	repo := &mockComponentRepo{}
	svc := asset.NewComponentService(repo, &stubAssetChecker{}, logger.NewNop())
	aid := shared.NewID()

	if _, err := svc.ListSBOMEntries(context.Background(), shared.NewID().String(), aid.String()); err != nil {
		t.Fatal(err)
	}
	if len(repo.sbomCalls) != 1 || repo.sbomCalls[0].assetID == nil || *repo.sbomCalls[0].assetID != aid {
		t.Fatalf("asset filter not passed: %+v", repo.sbomCalls)
	}
}

func TestListSBOMEntries_RefusesOversizedInventory(t *testing.T) {
	entries := make([]component.SBOMEntry, asset.MaxSBOMComponents+1)
	repo := &mockComponentRepo{sbomEntries: entries}
	svc := asset.NewComponentService(repo, nil, logger.NewNop())

	_, err := svc.ListSBOMEntries(context.Background(), shared.NewID().String(), "")
	if !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("an inventory above the cap must be refused, not cut short; got %v", err)
	}
}

func TestListSBOMEntries_InvalidIDs(t *testing.T) {
	svc := asset.NewComponentService(&mockComponentRepo{}, nil, logger.NewNop())
	if _, err := svc.ListSBOMEntries(context.Background(), "nope", ""); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("tenant: %v", err)
	}
	if _, err := svc.ListSBOMEntries(context.Background(), shared.NewID().String(), "nope"); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("asset: %v", err)
	}
}

func TestComponentHandler_ExportSBOM(t *testing.T) {
	repo := &mockComponentRepo{sbomEntries: []component.SBOMEntry{
		{ID: shared.NewID(), Name: "lodash", Version: "4.17.21", Ecosystem: "npm", PURL: "pkg:npm/lodash@4.17.21", Licenses: []string{"MIT"}},
	}}
	h := handler.NewComponentHandler(asset.NewComponentService(repo, nil, logger.NewNop()), nil, validator.New(), logger.NewNop())

	for _, tc := range []struct {
		query, contentType, marker string
	}{
		{"", "application/vnd.cyclonedx+json; version=1.6", `"bomFormat": "CycloneDX"`},
		{"?format=spdx", "application/spdx+json", `"spdxVersion": "SPDX-2.3"`},
	} {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/components/sbom"+tc.query, nil)
		req = req.WithContext(context.WithValue(req.Context(), middleware.TenantIDKey, shared.NewID().String()))
		rec := httptest.NewRecorder()
		h.ExportSBOM(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("%q: status %d %s", tc.query, rec.Code, rec.Body.String())
		}
		if got := rec.Header().Get("Content-Type"); got != tc.contentType {
			t.Fatalf("%q: content type %q", tc.query, got)
		}
		if !strings.Contains(rec.Header().Get("Content-Disposition"), "attachment") {
			t.Fatalf("%q: not an attachment", tc.query)
		}
		if !strings.Contains(rec.Body.String(), tc.marker) || !strings.Contains(rec.Body.String(), "pkg:npm/lodash@4.17.21") {
			t.Fatalf("%q: body %s", tc.query, rec.Body.String())
		}
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/components/sbom?format=xml", nil)
	req = req.WithContext(context.WithValue(req.Context(), middleware.TenantIDKey, shared.NewID().String()))
	rec := httptest.NewRecorder()
	h.ExportSBOM(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("unknown format: status %d", rec.Code)
	}
}
