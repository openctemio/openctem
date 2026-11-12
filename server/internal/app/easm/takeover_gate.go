package easm

// The takeover exception to the active-scan ownership gate (research/22
// owner decision E13; RFC-036 §6.4: a dependency gets "T0 checks plus the
// takeover check"). A name the tenant marked as a dependency (typically a
// CNAME to a SaaS provider) is refused by the gate, except for a scan that
// runs only the nuclei `takeover` templates, and only while the DNS check
// has an open dangling_cname on that very asset. Every other state keeps the
// gate's answer. Architecture: docs/architecture/active-probe-gate.md.

import (
	"context"
	"fmt"

	"github.com/openctemio/openctem/api/internal/app/actscope"
	"github.com/openctemio/openctem/api/internal/app/easmdns"
	"github.com/openctemio/openctem/api/pkg/domain/attribution"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// ActiveGateDangling lists the tenant's open dangling_cname exposures of the
// DNS check (*postgres.EASMDNSRepository).
type ActiveGateDangling interface {
	OpenDanglingCNAMEs(ctx context.Context, tenantID shared.ID, assetIDs []shared.ID) ([]easmdns.OpenDangling, error)
}

// WithTakeoverEvidence wires the dangling-CNAME lookup the takeover
// exception needs. Unwired, the exception admits nothing.
func (g *ActiveGate) WithTakeoverEvidence(d ActiveGateDangling) *ActiveGate {
	g.dangling = d
	return g
}

// TakeoverAdmittedAssets returns the given assets that the gate refuses only
// because they are a dependency and that have an open dangling_cname: a
// takeover-only scan may probe them.
func (g *ActiveGate) TakeoverAdmittedAssets(ctx context.Context, tenantID shared.ID, assetIDs []string) (map[string]bool, error) {
	blocked, err := g.ActiveCheckBlocked(ctx, tenantID, assetIDs)
	if err != nil {
		return nil, err
	}
	deps := make(map[string]string, len(blocked)) // asset id -> itself
	for id, st := range blocked {
		if st == attribution.StateDependency {
			deps[id] = id
		}
	}
	return g.withOpenDangling(ctx, tenantID, deps)
}

// TakeoverAdmittedTargets is TakeoverAdmittedAssets for typed targets: a
// target that names one of the tenant's dependency assets with an open
// dangling_cname.
func (g *ActiveGate) TakeoverAdmittedTargets(ctx context.Context, tenantID shared.ID, targets []string) (map[string]bool, error) {
	blocked, err := g.BlockedTargets(ctx, tenantID, targets)
	if err != nil {
		return nil, err
	}
	var names []string
	forms := map[string][]string{}
	for t, st := range blocked {
		if st != attribution.StateDependency {
			continue
		}
		forms[t] = actscope.MatchForms(t)
		names = append(names, forms[t]...)
	}
	if len(names) == 0 {
		return map[string]bool{}, nil
	}
	found, err := g.assets.GetByNames(ctx, tenantID, names)
	if err != nil {
		return nil, fmt.Errorf("resolve targets for the takeover check: %w", err)
	}
	byTarget := map[string]string{} // target -> asset id
	for t, fs := range forms {
		for _, f := range fs {
			if a, ok := found[f]; ok && a != nil {
				byTarget[t] = a.ID().String()
				break
			}
		}
	}
	return g.withOpenDangling(ctx, tenantID, byTarget)
}

// withOpenDangling keeps the keys whose asset has an open dangling_cname.
func (g *ActiveGate) withOpenDangling(ctx context.Context, tenantID shared.ID, keyToAsset map[string]string) (map[string]bool, error) {
	out := map[string]bool{}
	if len(keyToAsset) == 0 || g.dangling == nil {
		return out, nil
	}
	ids := make([]shared.ID, 0, len(keyToAsset))
	seen := map[string]bool{}
	for _, raw := range keyToAsset {
		if seen[raw] {
			continue
		}
		seen[raw] = true
		id, err := shared.IDFromString(raw)
		if err != nil {
			return nil, fmt.Errorf("%w: invalid asset id", shared.ErrValidation)
		}
		ids = append(ids, id)
	}
	open, err := g.dangling.OpenDanglingCNAMEs(ctx, tenantID, ids)
	if err != nil {
		return nil, fmt.Errorf("load open dangling CNAMEs: %w", err)
	}
	has := map[string]bool{}
	for _, d := range open {
		has[d.AssetID.String()] = true
	}
	for k, a := range keyToAsset {
		if has[a] {
			out[k] = true
		}
	}
	return out, nil
}
