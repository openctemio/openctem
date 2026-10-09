package scan

// Scanning inventory assets by id (POST /scans asset_ids): the server names
// each asset (its inventory name, what a scan of it probes), so a client can
// neither send a name that is not the asset's nor scan an asset outside the
// creator's scope by id. The names then go through every check a typed
// target goes through.

import (
	"context"
	"fmt"
	"strings"

	"github.com/openctemio/openctem/api/internal/app/actscope"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// MaxDirectTargets is how many direct targets (typed targets and assets
// together) one scan takes.
const MaxDirectTargets = 1000

// errScanAssetsUnavailable is the one answer for any asset id the creator
// may not scan: unknown, another tenant's, deleted or outside their scope.
// The cases are indistinguishable, so the error confirms nothing about ids
// the caller cannot see.
var errScanAssetsUnavailable = fmt.Errorf("%w: one or more assets do not exist or are not in your scope", shared.ErrValidation)

// resolveAssetTargets returns the scan target of each asset id (its name),
// in order, de-duplicated. Every id must be an asset of the tenant that the
// creator may act on; otherwise nothing is returned and the create fails.
func (s *Service) resolveAssetTargets(ctx context.Context, tenantID shared.ID, creator *shared.ID, raw []string) ([]string, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	if len(raw) > MaxDirectTargets {
		return nil, fmt.Errorf("%w: asset_ids takes at most %d assets", shared.ErrValidation, MaxDirectTargets)
	}
	ids := make([]shared.ID, 0, len(raw))
	for _, r := range raw {
		id, err := shared.IDFromString(r)
		if err != nil {
			return nil, fmt.Errorf("%w: asset_ids must be UUIDs", shared.ErrValidation)
		}
		ids = append(ids, id)
	}
	ids = dedupeIDs(ids)

	// Act scope first: a restricted creator may name only assets they may
	// scan, and learns nothing about the others.
	if s.actScope != nil {
		d, err := s.actScope.Check(ctx, actscope.Input{TenantID: tenantID, FallbackUser: creator, AssetIDs: ids})
		if err != nil {
			return nil, fmt.Errorf("act-scope check failed, nothing saved: %w", err)
		}
		if len(d.RefusedAssets) > 0 {
			return nil, errScanAssetsUnavailable
		}
	}

	resolver, ok := s.attributionGate.(AssetTargetResolver)
	if !ok || resolver == nil {
		return nil, ErrAttributionGateUnavailable
	}
	named, err := resolver.AssetTargets(ctx, tenantID, ids)
	if err != nil {
		return nil, fmt.Errorf("asset lookup failed: %w", err)
	}
	out := make([]string, 0, len(ids))
	seen := make(map[string]bool, len(ids))
	for _, id := range ids {
		values := named[id]
		if len(values) == 0 || strings.TrimSpace(values[0]) == "" {
			return nil, errScanAssetsUnavailable
		}
		name := strings.TrimSpace(values[0])
		if key := strings.ToLower(name); !seen[key] {
			seen[key] = true
			out = append(out, name)
		}
	}
	return out, nil
}

// mergeDirectTargets appends the asset targets to the typed ones, keeping
// the first spelling of each (case-insensitive), and refuses more than
// MaxDirectTargets in all.
func mergeDirectTargets(typed, assets []string) ([]string, error) {
	if len(assets) == 0 {
		return typed, nil
	}
	out := make([]string, 0, len(typed)+len(assets))
	seen := make(map[string]bool, len(typed)+len(assets))
	for _, t := range append(append([]string{}, typed...), assets...) {
		key := strings.ToLower(strings.TrimSpace(t))
		if key == "" || seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, t)
	}
	if len(out) > MaxDirectTargets {
		return nil, fmt.Errorf("%w: a scan takes at most %d direct targets (targets and assets together); %d were given",
			shared.ErrValidation, MaxDirectTargets, len(out))
	}
	return out, nil
}
