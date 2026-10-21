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
//   - attack paths: the in-scope assets are ranked and then the top 50 are
//     taken (scope before cap); the summary is recomputed over them (a viewer
//     with dashboards:org:view keeps the organization summary, no rows);
//   - exposure chains: a chain is shown when its target is in scope, ranked
//     and capped among those; a step the viewer may not see is returned as a
//     hidden step with no id, name or type, so an owner learns that their
//     asset is reachable without learning what lies in between;
//   - the exposure-chain summary is recomputed from the chains kept; the
//     attack-path summary likewise.
//
// GetAttackPathScores / GetExposureChains stay unscoped and uncapped: priority
// classification (reachability oracle) and threat models depend on the full
// graph and run on behalf of the tenant, not one member. The row cap of the
// chain list is applied here, after the scope.

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
	// Scope first, then the top-50 cap: the ranked list of every asset is
	// narrowed to the viewer's assets and only then cut, so a restricted member
	// whose assets rank below 50 tenant-wide still sees them.
	ranked := res.TopAssets
	if basis != nil {
		ranked = basis.all
	}
	ids := make([]shared.ID, 0, len(ranked))
	for _, a := range ranked {
		if id, perr := shared.IDFromString(a.AssetID); perr == nil {
			ids = append(ids, id)
		}
	}
	keep, err := s.dataScope.Filter(ctx, scope, ids)
	if err != nil {
		return nil, err
	}
	top := make([]AssetPathScore, 0, attackPathTopN)
	for _, a := range ranked {
		if len(top) == attackPathTopN {
			break
		}
		if id, perr := shared.IDFromString(a.AssetID); perr == nil && keep(id) {
			top = append(top, a)
		}
	}
	res.TopAssets = top
	// The summary follows the viewer: the assets they may see, unless they
	// hold dashboards:org:view (organization totals, no rows).
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
		res.Chains = capChains(res.Chains)
		return res, nil
	}
	// Scope first, then the cap, then the hops. A chain is shown when its
	// TARGET is in scope (an owner learns that their asset is reachable); the
	// steps on the way that the caller may not see are returned as hidden
	// steps without id, name or type.
	targetIDs := make([]shared.ID, 0, len(res.Chains))
	for _, c := range res.Chains {
		if id, perr := shared.IDFromString(c.TargetID); perr == nil {
			targetIDs = append(targetIDs, id)
		}
	}
	keepTarget, err := s.dataScope.Filter(ctx, scope, targetIDs)
	if err != nil {
		return nil, err
	}
	visible := make([]ExposureChain, 0, len(res.Chains))
	entries, targets := map[string]struct{}{}, map[string]struct{}{}
	for _, c := range res.Chains {
		if id, perr := shared.IDFromString(c.TargetID); perr != nil || !keepTarget(id) || len(c.Hops) == 0 {
			continue
		}
		visible = append(visible, c)
		entries[c.EntryPointID] = struct{}{}
		targets[c.TargetID] = struct{}{}
	}
	// The summary follows the rows the caller may see. The entry-point figure
	// is a count of distinct entries behind those rows (no identity), like
	// reachable_from on the attack-path scores.
	res.Summary.TotalChains = len(visible)
	res.Summary.EntryPoints = len(entries)
	res.Summary.TargetsAtRisk = len(targets)

	shown := capChains(visible)
	var hopIDs []shared.ID
	for _, c := range shown {
		for _, h := range c.Hops {
			if id, perr := shared.IDFromString(h.AssetID); perr == nil {
				hopIDs = append(hopIDs, id)
			}
		}
	}
	keepHop, err := s.dataScope.Filter(ctx, scope, hopIDs)
	if err != nil {
		return nil, err
	}
	out := make([]ExposureChain, len(shown))
	for i, c := range shown {
		out[i] = redactChain(c, keepHop)
	}
	res.Chains = out
	return res, nil
}

// redactChain returns c with every hop keep rejects replaced by a hidden step.
// The hop slice is copied: the input shares its hops with the cache.
func redactChain(c ExposureChain, keep func(shared.ID) bool) ExposureChain {
	hops := make([]ChainHop, len(c.Hops))
	for i, h := range c.Hops {
		if id, err := shared.IDFromString(h.AssetID); err == nil && keep(id) {
			hops[i] = h
			continue
		}
		hops[i] = ChainHop{Hidden: true}
	}
	c.Hops = hops
	if id, err := shared.IDFromString(c.EntryPointID); err != nil || !keep(id) {
		c.EntryPointID, c.EntryPointName = "", ""
	}
	return c
}

// capChains keeps the highest-ranked exposureChainCap chains (the list is
// already sorted by urgency).
func capChains(chains []ExposureChain) []ExposureChain {
	if len(chains) > exposureChainCap {
		return chains[:exposureChainCap]
	}
	return chains
}
