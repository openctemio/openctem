package asset

// Asset freshness (docs/architecture/asset-freshness.md): when each
// enrichable attribute class of an asset was last observed, and whether it
// is live, stale, dead or never observed.

import (
	"context"
	"fmt"
	"time"

	freshdom "github.com/openctemio/openctem/api/pkg/domain/assetfreshness"
)

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
	return &v, nil
}
