package finding

import (
	"context"

	"github.com/openctemio/api/pkg/domain/asset"
	"github.com/openctemio/api/pkg/domain/shared"
)

// AssetBusinessContext is the business-unit / business-service criticality that
// can RAISE an asset's effective criticality above its own. It aliases the
// shared domain type so this package and internal/app/asset resolve effective
// criticality through the SAME rule (asset.EffectiveCriticality) without a
// dependency cycle. Kept as a local name so the BusinessContextLookup interface
// and its postgres adapter read in finding terms.
type AssetBusinessContext = asset.BusinessContext

// BusinessContextLookup resolves, per asset, the business-unit and
// business-service criticality used to compute effective (business-aligned)
// criticality. It is tenant-scoped and batch-first so the classification hot
// path (EnrichAndClassifyBatch + the reclassify sweep) never issues a
// per-finding query. Optional — a nil lookup leaves classification on each
// asset's OWN criticality (never a downgrade).
type BusinessContextLookup interface {
	// GetForAssets returns the business context for the given assets, keyed by
	// asset ID. Assets with no BU / service membership may be absent from the
	// map (treated as the zero AssetBusinessContext).
	GetForAssets(ctx context.Context, tenantID shared.ID, assetIDs []shared.ID) (map[shared.ID]AssetBusinessContext, error)
}

// appendCriticalityReason appends the business-criticality explanation to a
// classification reason, when one is present. No-op when critReason is empty, so
// classifications with no business bump read exactly as before.
func appendCriticalityReason(reason, critReason string) string {
	if critReason == "" {
		return reason
	}
	if reason == "" {
		return critReason
	}
	return reason + " · " + critReason
}
