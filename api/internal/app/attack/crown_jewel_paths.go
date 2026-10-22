package attack

import (
	"context"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// CrownJewelPath is one crown jewel the attack-path scoring reaches: from
// at least one public entry point, or an entry point itself.
type CrownJewelPath struct {
	AssetID       shared.ID
	Name          string
	AssetType     string
	Criticality   string
	ReachableFrom int
	IsEntryPoint  bool
	Depth         int
	PathScore     float64
}

// ReachableCrownJewels returns every reachable crown jewel of the tenant in
// path-score order, and whether the tenant has any relationship data (with
// none, "nothing reachable" is not a measurement). The graph is the whole
// tenant's (shared cache); the caller applies the reader's asset scope to
// the ids and shows nothing else of the graph (no entry point or hop names).
func (s *SurfaceService) ReachableCrownJewels(ctx context.Context, tenantID shared.ID) ([]CrownJewelPath, bool, error) {
	res, err := s.GetAttackPathScores(ctx, tenantID)
	if err != nil || res == nil {
		return nil, false, err
	}
	src := res.TopAssets
	var depth map[string]int
	if res.basis != nil {
		src, depth = res.basis.all, res.basis.depth
	}
	out := make([]CrownJewelPath, 0)
	for _, a := range src {
		if !a.IsCrownJewel || (a.ReachableFrom == 0 && !a.IsEntryPoint) {
			continue
		}
		id, perr := shared.IDFromString(a.AssetID)
		if perr != nil {
			continue
		}
		out = append(out, CrownJewelPath{AssetID: id, Name: a.Name, AssetType: a.AssetType, Criticality: a.Criticality,
			ReachableFrom: a.ReachableFrom, IsEntryPoint: a.IsEntryPoint, Depth: depth[a.AssetID], PathScore: a.PathScore})
	}
	return out, res.Summary.HasRelationshipData, nil
}
