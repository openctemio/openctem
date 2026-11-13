package metrics

// Asset attribute reconciliation and change timeline (RFC-069).

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	// AssetAttributeObservationsTotal counts recorded attribute observations
	// by verdict: new | changed | refresh | resighted | out_of_order |
	// replay. A rise in out_of_order or replay means sources deliver late
	// or replay reports; they are ignored.
	AssetAttributeObservationsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "openctem_asset_attribute_observations_total",
			Help: "Asset attribute observations by what recording them did (out_of_order and replay are ignored)",
		},
		[]string{"verdict"},
	)

	// AssetChangeEventsTotal counts asset timeline events written (or folded
	// into a flapping event).
	AssetChangeEventsTotal = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "openctem_asset_change_events_total",
			Help: "Asset change timeline events written or coalesced",
		},
	)
)
