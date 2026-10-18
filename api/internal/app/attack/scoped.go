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
//   - attack paths: TopAssets keeps only in-scope assets and the summary is
//     recomputed over them (a viewer with dashboard:aggregate keeps the
//     organization summary, no rows);
//   - exposure chains: a chain is shown only when every hop is in scope, so
//     no out-of-scope asset name or id is revealed along the way;
//   - the exposure-chain summary is recomputed from the chains kept; the
//     attack-path summary likewise.
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
	scope, err := s.dataScope.ResolveStrict(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("resolve data scope: %w", err)
	}
	res, err := s.GetAttackPathScores(ctx, tenantID)
	if err != nil || res == nil {
		return res, err
	}
	if scope == nil {
		return res, nil
	}
	basis := res.basis
	res.basis = nil
	var all []AssetPathScore
	if basis != nil {
		all = basis.all
	}
	ids := make([]shared.ID, 0, len(all)+len(res.TopAssets))
	for _, a := range all {
		if id, perr := shared.IDFromString(a.AssetID); perr == nil {
			ids = append(ids, id)
		}
	}
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
	// The summary follows the viewer: the assets they may see, unless they
	// hold dashboard:aggregate (organization totals, no rows).
	if basis != nil && !(scope.Restricted() && s.dataScope.AggregateViewer(ctx)) {
		res.Summary = summarizeKept(basis, keep)
	}
	return res, nil
}

// summarizeKept recomputes the summary over the assets keep admits: the same
// rules as ComputeAttackPathScores, applied to the kept assets only. The
// reachability itself stays that of the whole graph.
func summarizeKept(b *pathBasis, keep func(shared.ID) bool) PathSummary {
	out := PathSummary{}
	for _, a := range b.all {
		id, err := shared.IDFromString(a.AssetID)
		if err != nil || !keep(id) {
			continue
		}
		if a.IsEntryPoint {
			out.EntryPoints++
		}
		if d := b.depth[a.AssetID]; d > out.MaxDepth {
			out.MaxDepth = d
		}
		if b.edgeNodes[a.AssetID] {
			out.HasRelationshipData = true
		}
		if a.ReachableFrom > 0 {
			out.ReachableAssets++
			out.TotalPaths += a.ReachableFrom
			if a.Criticality == "critical" || a.Criticality == "high" {
				out.CriticalReachable++
			}
		}
		if a.IsCrownJewel && (a.ReachableFrom > 0 || a.IsEntryPoint) {
			out.CrownJewelsAtRisk++
		}
	}
	return out
}

// ExposureChainsForCaller is GetExposureChains narrowed to the request
// caller's data scope (a chain is kept only when all its hops are in scope).
func (s *SurfaceService) ExposureChainsForCaller(ctx context.Context, tenantID shared.ID) (*ExposureChainResult, error) {
	scope, err := s.dataScope.ResolveStrict(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("resolve data scope: %w", err)
	}
	res, err := s.GetExposureChains(ctx, tenantID)
	if err != nil || res == nil {
		return res, err
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
	// The summary follows the rows the caller may see: counts over the whole
	// graph would show how much exists outside their scope.
	entries, targets := map[string]struct{}{}, map[string]struct{}{}
	for _, c := range chains {
		entries[c.EntryPointID] = struct{}{}
		targets[c.TargetID] = struct{}{}
	}
	res.Summary.TotalChains = len(chains)
	res.Summary.EntryPoints = len(entries)
	res.Summary.TargetsAtRisk = len(targets)
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
