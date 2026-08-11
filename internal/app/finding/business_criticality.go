package finding

import (
	"context"
	"fmt"

	"github.com/openctemio/api/pkg/domain/asset"
	"github.com/openctemio/api/pkg/domain/shared"
)

// AssetBusinessContext carries the business-unit and business-service
// criticality that can RAISE an asset's effective criticality above its own.
// The zero value (empty criticalities) means "no business context" — a pure
// floor that never lowers the asset's own criticality.
type AssetBusinessContext struct {
	// BusinessUnitCriticality is the MAX criticality across every business unit
	// the asset belongs to ("" when the asset is in no BU).
	BusinessUnitCriticality asset.Criticality
	// BusinessUnitName names the BU that supplied BusinessUnitCriticality, for
	// the audit reason string.
	BusinessUnitName string
	// BusinessServiceCriticality is the MAX criticality across every business
	// service the asset powers ("" when the asset powers no service).
	BusinessServiceCriticality asset.Criticality
	// BusinessServiceName names the service that supplied
	// BusinessServiceCriticality, for the audit reason string.
	BusinessServiceName string
}

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

// criticalityRank orders the criticality enum for MAX comparison — higher is
// more critical. It reuses the domain Score() so the business-unit and
// business-service scales (which share the platform-wide critical/high/medium/
// low vocabulary) rank consistently with an asset's own criticality. Empty /
// unknown ranks lowest, so an absent business signal can never win the MAX.
func criticalityRank(c asset.Criticality) int { return c.Score() }

// effectiveCriticality returns the business-aligned criticality — the MAX of the
// asset's OWN criticality and any business-unit / business-service criticality —
// together with an audit reason when a business signal RAISED it above the
// asset's own. Floor semantics: the result is never below the asset's own
// criticality, and a lower-criticality BU/service leaves it unchanged (empty
// reason). When both a BU and a service raise it, the higher wins and the reason
// names that source.
func effectiveCriticality(own asset.Criticality, bctx AssetBusinessContext) (asset.Criticality, string) {
	eff := own
	reason := ""

	if bctx.BusinessUnitCriticality != "" && criticalityRank(bctx.BusinessUnitCriticality) > criticalityRank(eff) {
		eff = bctx.BusinessUnitCriticality
		reason = fmt.Sprintf("criticality raised to %s by business unit '%s'", eff, bctx.BusinessUnitName)
	}
	if bctx.BusinessServiceCriticality != "" && criticalityRank(bctx.BusinessServiceCriticality) > criticalityRank(eff) {
		eff = bctx.BusinessServiceCriticality
		reason = fmt.Sprintf("criticality raised to %s by business service '%s'", eff, bctx.BusinessServiceName)
	}

	return eff, reason
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
