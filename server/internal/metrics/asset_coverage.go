package metrics

// Asset coverage (docs/rfcs/RFC-093-asset-coverage.md). Labels carry the
// capability and the alert kind only, never a tenant: the operator sees
// fleet-wide gaps and output drops as aggregates (owner decision D4).

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	// AssetCoverageGapPairs is the number of asset and capability pairs
	// uncovered for more than twice their cadence, summed over tenants.
	AssetCoverageGapPairs = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "openctem_asset_coverage_gap_pairs",
			Help: "Asset and capability pairs without a success for more than twice their cadence, all organizations",
		},
		[]string{"capability"},
	)
	// AssetCoverageAlertsTotal counts coverage alerts raised, by kind
	// (gap, output_drop, failing) and capability.
	AssetCoverageAlertsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "openctem_asset_coverage_alerts_total",
			Help: "Coverage alerts raised for organizations, by kind and capability",
		},
		[]string{"kind", "capability"},
	)
	// AssetCoveragePlatformFailuresTotal counts coverage pairs settled as
	// failed on the platform side (the check did not run: no task carried
	// the target, the run stalled, the task, tool, sensor network or proxy
	// failed), by capability and outcome. Never a target's failure.
	AssetCoveragePlatformFailuresTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "openctem_asset_coverage_platform_failures_total",
			Help: "Coverage pairs settled as failed on the platform or sensor side (the check did not run), by capability and outcome",
		},
		[]string{"capability", "outcome"},
	)
	// AssetCoveragePlatformFailingPairs is the number of pairs with three
	// or more platform-side failures in a row, all organizations.
	AssetCoveragePlatformFailingPairs = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "openctem_asset_coverage_platform_failing_pairs",
			Help: "Coverage pairs failing 3 or more times in a row on the platform or sensor side, all organizations",
		},
		[]string{"capability", "outcome"},
	)
)
