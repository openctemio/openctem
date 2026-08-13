package asset

import "fmt"

// BusinessContext carries the business-unit and business-service criticality
// that can RAISE an asset's effective criticality above its own. The zero value
// (empty criticalities) means "no business context" — a pure floor that never
// lowers the asset's own criticality.
//
// It is the input to EffectiveCriticality, the shared MAX/floor rule used both
// by finding-priority classification and (upcoming) asset risk scoring.
type BusinessContext struct {
	// BusinessUnitCriticality is the MAX criticality across every business unit
	// the asset belongs to ("" when the asset is in no BU).
	BusinessUnitCriticality Criticality
	// BusinessUnitName names the BU that supplied BusinessUnitCriticality, for
	// the audit reason string.
	BusinessUnitName string
	// BusinessServiceCriticality is the MAX criticality across every business
	// service the asset powers ("" when the asset powers no service).
	BusinessServiceCriticality Criticality
	// BusinessServiceName names the service that supplied
	// BusinessServiceCriticality, for the audit reason string.
	BusinessServiceName string
}

// criticalityRank orders the criticality enum for MAX comparison — higher is
// more critical. It reuses Score() so the business-unit and business-service
// scales (which share the platform-wide critical/high/medium/low vocabulary)
// rank consistently with an asset's own criticality. Empty / unknown ranks
// lowest, so an absent business signal can never win the MAX.
func criticalityRank(c Criticality) int { return c.Score() }

// EffectiveCriticality returns the business-aligned criticality — the MAX of the
// asset's OWN criticality and any business-unit / business-service criticality —
// together with an audit reason when a business signal RAISED it above the
// asset's own. Floor semantics: the result is never below the asset's own
// criticality, and a lower-criticality BU/service leaves it unchanged (empty
// reason). When both a BU and a service raise it, the higher wins and the reason
// names that source.
func EffectiveCriticality(own Criticality, bctx BusinessContext) (Criticality, string) {
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
