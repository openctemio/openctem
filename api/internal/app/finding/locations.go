package finding

import (
	"context"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/softwarematch"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// Locations of a version-match finding (docs/architecture/vulnerability-matching.md,
// "Locations"): the services of its host it is observed on.

// LocationReader reads a finding's locations (postgres.SoftwareMatchRepository).
type LocationReader interface {
	FindingLocations(ctx context.Context, tenantID, findingID shared.ID) ([]softwarematch.Location, error)
}

// SetLocationReader wires the location reader. Without one a finding has no
// locations.
func (s *VulnerabilityService) SetLocationReader(r LocationReader) { s.locations = r }

// GetFindingLocations returns the locations of a finding the caller has
// already been authorized for (GetFindingWithScope), keeping only those on
// the finding's own asset or on assets inside the caller's data scope: a service the caller cannot see is
// left out, and nothing says it was. It reads by the finding's own tenant
// and id. Any error while checking the scope shows nothing (fail closed).
func (s *VulnerabilityService) GetFindingLocations(ctx context.Context, f *vulnerability.Finding, actingUserID string, isAdmin bool) ([]softwarematch.Location, error) {
	if s.locations == nil || f == nil {
		return nil, nil
	}
	locs, err := s.locations.FindingLocations(ctx, f.TenantID(), f.ID())
	if err != nil || len(locs) == 0 {
		return nil, err
	}
	if s.dataScope == nil {
		return locs, nil
	}
	scope, err := s.dataScope.ResolveActing(ctx, f.TenantID(), actingUserID, isAdmin)
	if err != nil {
		return nil, err
	}
	ids := make([]shared.ID, 0, len(locs))
	for _, l := range locs {
		ids = append(ids, l.AssetID)
	}
	in, err := s.dataScope.Filter(ctx, scope, ids)
	if err != nil {
		return nil, err
	}
	out := locs[:0]
	for _, l := range locs {
		// The finding's own asset is already what the caller reads.
		if l.AssetID == f.AssetID() || in(l.AssetID) {
			out = append(out, l)
		}
	}
	return out, nil
}
