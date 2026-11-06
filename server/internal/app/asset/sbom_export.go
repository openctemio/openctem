package asset

import (
	"context"
	"fmt"

	componentdom "github.com/openctemio/openctem/api/pkg/domain/component"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// MaxSBOMComponents is the most components one SBOM export holds. A larger
// inventory is exported one asset at a time rather than cut short silently.
const MaxSBOMComponents = 10000

// SBOMExport is what an SBOM describes: its subject and the components.
type SBOMExport struct {
	// Subject is the asset name, or empty for the whole inventory.
	Subject string
	Entries []componentdom.SBOMEntry
}

// ListSBOMEntries collects the components for an SBOM export: every
// component the tenant uses, or those of one asset (not found when the asset
// is not the tenant's or not in the caller's data scope). A restricted
// caller gets only components used by assets in their scope.
func (s *ComponentService) ListSBOMEntries(ctx context.Context, tenantID, assetID string) (*SBOMExport, error) {
	tid, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id format", shared.ErrValidation)
	}
	out := &SBOMExport{}
	var assetFilter *shared.ID
	if assetID != "" {
		aid, err := shared.IDFromString(assetID)
		if err != nil {
			return nil, fmt.Errorf("%w: invalid asset id format", shared.ErrValidation)
		}
		out.Subject = aid.String()
		if s.assetChecker != nil {
			a, err := s.assetChecker.GetByID(ctx, tid, aid)
			if err != nil {
				return nil, err
			}
			if a != nil {
				out.Subject = a.Name()
			}
		}
		if err := s.assertInScope(ctx, tid, aid); err != nil {
			return nil, err
		}
		assetFilter = &aid
	}
	scope, err := s.callerScope(ctx, tid)
	if err != nil {
		return nil, err
	}
	entries, err := s.repo.ListSBOMEntries(ctx, tid, assetFilter, scope, MaxSBOMComponents+1)
	if err != nil {
		return nil, err
	}
	if len(entries) > MaxSBOMComponents {
		return nil, fmt.Errorf("%w: more than %d components; export one asset at a time", shared.ErrValidation, MaxSBOMComponents)
	}
	out.Entries = entries
	return out, nil
}
