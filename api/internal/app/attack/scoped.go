package attack

import (
	"context"
	"fmt"

	"github.com/openctemio/openctem/api/internal/app/datascope"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Layer 2 data scope for the attack-surface read endpoints.
//
// Reachability is a property of the whole tenant graph, so paths and chains
// are always computed over every asset; only what is shown to a restricted
// member is narrowed:
//
//   - attack paths: TopAssets keeps only in-scope assets;
//   - exposure chains: a chain is shown only when every hop is in scope, so
//     no out-of-scope asset name or id is revealed along the way;
//   - the Summary blocks stay tenant-wide counts (no row data).
//
// GetAttackPathScores / GetExposureChains stay unscoped: priority
// classification (reachability oracle) and threat models depend on the full
// graph and run on behalf of the tenant, not one member.

// SetDataScope wires the Layer 2 data-scope enforcer (nil = unrestricted).
func (s *SurfaceService) SetDataScope(e *datascope.Enforcer) {
	s.dataScope = e
}

// AttackPathScoresForCaller is GetAttackPathScores narrowed to the request
// caller's data scope.
func (s *SurfaceService) AttackPathScoresForCaller(ctx context.Context, tenantID shared.ID) (*PathScoringResult, error) {
	res, err := s.GetAttackPathScores(ctx, tenantID)
	if err != nil || res == nil {
		return res, err
	}
	scope, err := s.dataScope.Resolve(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("resolve data scope: %w", err)
	}
	if scope == nil {
		return res, nil
	}
	ids := make([]shared.ID, 0, len(res.TopAssets))
	for _, a := range res.TopAssets {
		if id, perr := shared.IDFromString(a.AssetID); perr == nil {
			ids = append(ids, id)
		}
	}
	keep, err := s.dataScope.Filter(ctx, scope, ids)
	if err != nil {
		return nil, err
	}
	top := make([]AssetPathScore, 0, len(res.TopAssets))
	for _, a := range res.TopAssets {
		if id, perr := shared.IDFromString(a.AssetID); perr == nil && keep(id) {
			top = append(top, a)
		}
	}
	res.TopAssets = top
	return res, nil
}

// ExposureChainsForCaller is GetExposureChains narrowed to the request
// caller's data scope (a chain is kept only when all its hops are in scope).
func (s *SurfaceService) ExposureChainsForCaller(ctx context.Context, tenantID shared.ID) (*ExposureChainResult, error) {
	res, err := s.GetExposureChains(ctx, tenantID)
	if err != nil || res == nil {
		return res, err
	}
	scope, err := s.dataScope.Resolve(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("resolve data scope: %w", err)
	}
	if scope == nil {
		return res, nil
	}
	var ids []shared.ID
	for _, c := range res.Chains {
		for _, h := range c.Hops {
			if id, perr := shared.IDFromString(h.AssetID); perr == nil {
				ids = append(ids, id)
			}
		}
	}
	keep, err := s.dataScope.Filter(ctx, scope, ids)
	if err != nil {
		return nil, err
	}
	chains := make([]ExposureChain, 0, len(res.Chains))
	for _, c := range res.Chains {
		if chainInScope(c, keep) {
			chains = append(chains, c)
		}
	}
	res.Chains = chains
	return res, nil
}

func chainInScope(c ExposureChain, keep func(shared.ID) bool) bool {
	if len(c.Hops) == 0 {
		return false
	}
	for _, h := range c.Hops {
		id, err := shared.IDFromString(h.AssetID)
		if err != nil || !keep(id) {
			return false
		}
	}
	return true
}
