package asset

// Asset coverage (docs/rfcs/RFC-093-asset-coverage.md): per capability its
// type needs, what was done, what is due and why something was skipped.

import (
	"context"
	"fmt"
	"time"

	covdom "github.com/openctemio/openctem/server/pkg/domain/coverage"
)

// SetCoverage wires the coverage ledger. Unwired, every rule of an asset
// shows as not planned.
func (s *AssetService) SetCoverage(repo covdom.Repository) { s.coverage = repo }

// SetCoverageInfoPolicy wires the organization's info pass setting, so an
// asset's coverage shows the info pass with the organization's interval (or
// not at all when it is off). Unwired, the default applies.
func (s *AssetService) SetCoverageInfoPolicy(r covdom.InfoPolicyReader) { s.coverageInfo = r }

// GetCoverage returns the coverage of an asset the caller may see (an asset
// outside the caller's data scope or of another tenant is not found).
func (s *AssetService) GetCoverage(ctx context.Context, tenantID, assetID string) (*covdom.AssetView, error) {
	a, err := s.GetAssetInCallerScope(ctx, tenantID, assetID)
	if err != nil {
		return nil, err
	}
	var rows []covdom.Row
	if s.coverage != nil {
		if rows, err = s.coverage.ListForAsset(ctx, a.TenantID(), a.ID()); err != nil {
			return nil, fmt.Errorf("list asset coverage: %w", err)
		}
	}
	pol := covdom.DefaultInfoPolicy()
	if s.coverageInfo != nil {
		if p, perr := s.coverageInfo.InfoPolicy(ctx, a.TenantID()); perr == nil {
			pol = p
		}
	}
	v := covdom.View(a.ID(), covdom.ApplyInfoPolicy(covdom.RulesFor(a.Type(), a.SubType()), pol), rows, time.Now())
	return &v, nil
}
