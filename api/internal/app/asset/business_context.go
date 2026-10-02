package asset

import (
	"context"

	assetdom "github.com/openctemio/api/pkg/domain/asset"
	"github.com/openctemio/api/pkg/domain/shared"
)

// BusinessContextLookup resolves, per asset, the business-unit and
// business-service criticality used to compute an asset's EFFECTIVE
// (business-aligned) criticality for risk scoring. It is tenant-scoped and
// batch-first so the recalculation sweep never issues a per-asset query.
//
// It mirrors finding.BusinessContextLookup (same method, same batch shape) so
// asset risk scoring and finding-priority resolve effective criticality through
// the SAME data and the SAME rule (assetdom.EffectiveCriticality). The Postgres
// adapter internal/infra/postgres.BusinessContextLookupRepo satisfies both
// interfaces structurally — one lookup feeds both paths.
//
// Optional — a nil lookup leaves scoring on each asset's OWN criticality (a pure
// floor, never a downgrade).
type BusinessContextLookup interface {
	// GetForAssets returns the business context for the given assets, keyed by
	// asset ID. Assets with no BU / service membership may be absent from the
	// map (treated as the zero assetdom.BusinessContext).
	GetForAssets(ctx context.Context, tenantID shared.ID, assetIDs []shared.ID) (map[shared.ID]assetdom.BusinessContext, error)
}

// SetBusinessContextLookup wires the business-unit / business-service criticality
// lookup used to raise an asset's effective criticality during risk scoring.
// Safe to call after construction; nil keeps scoring on the asset's own
// criticality (current behavior).
func (s *AssetService) SetBusinessContextLookup(lookup BusinessContextLookup) {
	s.businessContext = lookup
}

// effectiveCriticality resolves an asset's business-aligned criticality — the
// MAX/floor of {own, its business unit, the business services it powers}. Nil
// lookup, a zero asset ID, or any lookup error yields the asset's OWN
// criticality, so scoring degrades to the pre-business-alignment behavior and
// never fails a save. Floor semantics guaranteed by assetdom.EffectiveCriticality
// (a lower BU/service never lowers the result).
func (s *AssetService) effectiveCriticality(ctx context.Context, tenantID shared.ID, a *assetdom.Asset) assetdom.Criticality {
	if s.businessContext == nil || a == nil || a.ID().IsZero() {
		if a == nil {
			return ""
		}
		return a.Criticality()
	}
	m, err := s.businessContext.GetForAssets(ctx, tenantID, []shared.ID{a.ID()})
	if err != nil {
		s.logger.Warn("business context lookup failed; scoring on own criticality",
			"tenant_id", tenantID.String(), "asset_id", a.ID().String(), "error", err.Error())
		return a.Criticality()
	}
	eff, _ := assetdom.EffectiveCriticality(a.Criticality(), m[a.ID()])
	return eff
}

// scoreAsset computes and sets the asset's risk score using the tenant scoring
// config and the asset's EFFECTIVE (business-aligned) criticality. It is the
// single seam through which the persist paths route scoring so the floor rule is
// applied consistently. Nil-safe (see effectiveCriticality): with no lookup
// wired, the score is byte-identical to the prior own-criticality behavior.
func (s *AssetService) scoreAsset(ctx context.Context, tenantID shared.ID, a *assetdom.Asset) {
	eff := s.effectiveCriticality(ctx, tenantID, a)
	a.CalculateRiskScoreWithConfigAndCriticality(s.getScoringConfig(ctx, tenantID), eff)
}

// effectiveCriticalityMap batch-resolves effective criticality for a slice of
// assets in ONE business-context lookup, keyed by asset ID. Every asset is
// present in the result (defaulting to its own criticality); the lookup only
// raises. A nil lookup or a lookup error leaves every asset on its own
// criticality. Used by the whole-tenant recalculation sweep so it stays a single
// batched query per page rather than one query per asset.
func (s *AssetService) effectiveCriticalityMap(ctx context.Context, tenantID shared.ID, assets []*assetdom.Asset) map[shared.ID]assetdom.Criticality {
	out := make(map[shared.ID]assetdom.Criticality, len(assets))
	ids := make([]shared.ID, 0, len(assets))
	for _, a := range assets {
		out[a.ID()] = a.Criticality()
		ids = append(ids, a.ID())
	}
	if s.businessContext == nil || len(ids) == 0 {
		return out
	}
	m, err := s.businessContext.GetForAssets(ctx, tenantID, ids)
	if err != nil {
		s.logger.Warn("batch business context lookup failed; scoring on own criticality",
			"tenant_id", tenantID.String(), "error", err.Error())
		return out
	}
	for _, a := range assets {
		eff, _ := assetdom.EffectiveCriticality(a.Criticality(), m[a.ID()])
		out[a.ID()] = eff
	}
	return out
}
