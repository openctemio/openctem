package metrics

// Asset freshness and automatic enrichment (docs/architecture/asset-freshness.md).

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	// AssetFreshnessObservationsTotal counts class observations recorded
	// from ingest, by class.
	AssetFreshnessObservationsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "openctem_asset_freshness_observations_total",
			Help: "Asset attribute class observations recorded for freshness, by class",
		},
		[]string{"class"},
	)

	// AssetFreshnessRecordErrorsTotal counts batches whose freshness could
	// not be recorded. The ingest itself is not affected.
	AssetFreshnessRecordErrorsTotal = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "openctem_asset_freshness_record_errors_total",
			Help: "Ingest batches whose asset freshness could not be recorded",
		},
	)

	// AssetEnrichmentRequestsTotal counts enrichment requests opened, by reason.
	AssetEnrichmentRequestsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "openctem_asset_enrichment_requests_total",
			Help: "Automatic asset enrichment requests opened, by reason",
		},
		[]string{"reason"},
	)

	// AssetEnrichmentDispatchedTotal counts assets sent to an enrichment run, by profile.
	AssetEnrichmentDispatchedTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "openctem_asset_enrichment_dispatched_total",
			Help: "Assets sent to an automatic enrichment run, by profile",
		},
		[]string{"profile"},
	)

	// AssetEnrichmentSkippedTotal counts requests not dispatched, by reason:
	// disabled, budget, no_profile, refused, failed, request_error.
	AssetEnrichmentSkippedTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "openctem_asset_enrichment_skipped_total",
			Help: "Automatic asset enrichment requests not dispatched, by reason",
		},
		[]string{"reason"},
	)
)
