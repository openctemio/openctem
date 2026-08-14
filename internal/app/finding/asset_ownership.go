package finding

import (
	"context"

	"github.com/openctemio/api/pkg/domain/asset"
	"github.com/openctemio/api/pkg/domain/shared"
	tenantdom "github.com/openctemio/api/pkg/domain/tenant"
)

// OwnershipFloorPolicy reports whether a tenant has opted into the CTEM
// "ownership unknown defaults to P2 minimum" floor. It is the toggle that keeps
// the floor from being a blanket, forced behavior change: the floor (and the
// owner-presence lookup that feeds it) runs ONLY for tenants that turned it on.
// Optional — a nil policy is read as "off" for every tenant (fail-safe: no
// floor, no owner lookup, no cost).
type OwnershipFloorPolicy interface {
	// FloorUnownedAtP2 returns true when the tenant enabled the floor. Any error
	// or missing setting resolves to false (off) so a lookup failure never starts
	// silently re-prioritizing findings.
	FloorUnownedAtP2(ctx context.Context, tenantID shared.ID) bool
}

// SetOwnershipFloorPolicy wires the per-tenant toggle for the CTEM ownership
// floor. Optional — nil keeps the floor off for every tenant (the conservative
// default). Safe to call after construction.
func (s *PriorityClassificationService) SetOwnershipFloorPolicy(p OwnershipFloorPolicy) {
	s.ownershipFloor = p
}

// ownershipFloorEnabled reports whether the tenant turned the ownership floor on.
// A nil policy (not wired) is off — so the floor is strictly opt-in and, when
// off, the classifier skips the owner-presence lookup entirely (no floor, no
// query, no explanation reason).
func (s *PriorityClassificationService) ownershipFloorEnabled(ctx context.Context, tenantID shared.ID) bool {
	if s.ownershipFloor == nil {
		return false
	}
	return s.ownershipFloor.FloorUnownedAtP2(ctx, tenantID)
}

// TenantOwnershipFloorPolicy reads the FloorUnownedAtP2 toggle from a tenant's
// risk-scoring settings. Mirrors asset.TenantScoringConfigProvider: one tenant
// lookup, and any error is treated as "off" (never a silent re-prioritization).
type TenantOwnershipFloorPolicy struct {
	tenantRepo tenantdom.Repository
}

// NewTenantOwnershipFloorPolicy builds the tenant-settings-backed floor policy.
func NewTenantOwnershipFloorPolicy(tenantRepo tenantdom.Repository) *TenantOwnershipFloorPolicy {
	return &TenantOwnershipFloorPolicy{tenantRepo: tenantRepo}
}

var _ OwnershipFloorPolicy = (*TenantOwnershipFloorPolicy)(nil)

// FloorUnownedAtP2 returns the tenant's toggle; false on any error or when the
// tenant / setting is absent.
func (p *TenantOwnershipFloorPolicy) FloorUnownedAtP2(ctx context.Context, tenantID shared.ID) bool {
	if p.tenantRepo == nil {
		return false
	}
	t, err := p.tenantRepo.GetByID(ctx, tenantID)
	if err != nil || t == nil {
		return false
	}
	return t.TypedSettings().RiskScoring.FloorUnownedAtP2
}

// assetIDsOf returns the single-element asset-ID slice for the given asset, or an
// empty slice when the asset is nil / zero. Used by the single-finding classify
// and explain paths to feed ownerPresence without a per-call nil dance.
func assetIDsOf(a *asset.Asset) []shared.ID {
	if a == nil || a.ID().IsZero() {
		return nil
	}
	return []shared.ID{a.ID()}
}

// AssetOwnerLookup reports, per asset, whether the asset has an assigned owner
// (a user or group in asset_owners). It is tenant-scoped and batch-first so the
// classification hot path (EnrichAndClassifyBatch + the reclassify sweep) never
// issues a per-finding query — mirroring BusinessContextLookup.
//
// It backs the CTEM "ownership unknown defaults to P2 minimum" rule: a finding
// on an unowned asset is floored at P2 (see vulnerability.applyOwnershipFloor).
// Optional — a nil lookup leaves classification unchanged (never a floor), so a
// deployment without the lookup wired behaves exactly as before.
type AssetOwnerLookup interface {
	// HasOwnerByAssetIDs returns, keyed by asset ID, true for each asset that has
	// at least one assigned owner. Assets with no owner may be absent from the
	// map (a missing key is read as "no owner"). Tenant-scoped in ONE query.
	HasOwnerByAssetIDs(ctx context.Context, tenantID shared.ID, assetIDs []shared.ID) (map[shared.ID]bool, error)
}

// SetAssetOwnerLookup wires the asset-owner-presence lookup used to floor unowned
// findings at P2. Optional — nil keeps classification unchanged (no floor). Safe
// to call after construction.
func (s *PriorityClassificationService) SetAssetOwnerLookup(l AssetOwnerLookup) {
	s.assetOwner = l
}

// ownerPresence fetches, for the given assets, which ones have an assigned owner.
// It returns a NON-NIL map only when the lookup actually ran successfully — that
// non-nil-ness is the signal buildPriorityContext uses to decide the floor may
// apply. A nil lookup, an empty input, or any error yields a nil map, which
// buildPriorityContext treats as "ownership unknown -> do NOT floor" (fail-safe:
// missing owner data never mislabels an owned asset as unowned).
func (s *PriorityClassificationService) ownerPresence(
	ctx context.Context,
	tenantID shared.ID,
	assetIDs []shared.ID,
) map[shared.ID]bool {
	if s.assetOwner == nil || len(assetIDs) == 0 {
		return nil
	}
	m, err := s.assetOwner.HasOwnerByAssetIDs(ctx, tenantID, assetIDs)
	if err != nil {
		s.logger.Warn("asset owner lookup failed",
			"tenant_id", tenantID.String(), "error", err.Error())
		return nil
	}
	return m
}
