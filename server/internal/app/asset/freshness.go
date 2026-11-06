package asset

// Asset freshness (docs/architecture/asset-freshness.md): when each
// enrichable attribute class of an asset was last observed, and whether it
// is live, stale, dead or never observed.

import (
	"context"
	"fmt"
	"time"

	assetdom "github.com/openctemio/openctem/api/pkg/domain/asset"
	freshdom "github.com/openctemio/openctem/api/pkg/domain/assetfreshness"
	"github.com/openctemio/openctem/api/pkg/domain/assetresolution"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// CreatedAssetsHook receives assets a person created (manual create, CSV
// import), so they are enriched like assets an ingest found.
type CreatedAssetsHook func(ctx context.Context, tenantID shared.ID, assets []*assetdom.Asset)

// SetCreatedAssetsHook wires the hook for manual creates.
func (s *AssetService) SetCreatedAssetsHook(h CreatedAssetsHook) { s.createdHook = h }

// SetCreatedAssetsHook wires the hook for CSV imports (called once per import
// with every asset it created).
func (s *AssetImportService) SetCreatedAssetsHook(h CreatedAssetsHook) { s.createdHook = h }

// SetEnrichmentRequests wires the requests the freshness view shows.
func (s *AssetService) SetEnrichmentRequests(r freshdom.RequestRepository) { s.enrichReqs = r }

// SetResolution wires the resolution states the freshness view shows.
func (s *AssetService) SetResolution(st assetresolution.Store) { s.resolution = st }

// SetFreshness wires the freshness records. Unwired, every asset shows its
// passive classes as never observed.
func (s *AssetService) SetFreshness(repo freshdom.Repository) {
	s.freshness = repo
}

// GetFreshness returns the freshness of an asset the caller may see (an
// asset outside the caller's data scope or of another tenant is not found).
func (s *AssetService) GetFreshness(ctx context.Context, tenantID, assetID string) (*freshdom.AssetView, error) {
	a, err := s.GetAssetInCallerScope(ctx, tenantID, assetID)
	if err != nil {
		return nil, err
	}
	var obs []freshdom.Observation
	if s.freshness != nil {
		if obs, err = s.freshness.ListForAsset(ctx, a.TenantID(), a.ID()); err != nil {
			return nil, fmt.Errorf("list asset freshness: %w", err)
		}
	}
	v := freshdom.View(a.Type(), freshdom.ImportanceOf(a), obs, time.Now())
	if s.enrichReqs != nil {
		if v.Enrichment, err = s.enrichReqs.Get(ctx, a.TenantID(), a.ID()); err != nil {
			return nil, fmt.Errorf("get enrichment request: %w", err)
		}
	}
	if s.resolution != nil {
		// Tenant-scoped on the asset the caller was just allowed to see.
		if v.Resolution, err = s.resolution.Get(ctx, a.TenantID(), a.ID()); err != nil {
			return nil, fmt.Errorf("get asset resolution: %w", err)
		}
	}
	return &v, nil
}
