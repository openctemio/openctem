package ingest

// When an asset was last seen (docs/architecture/sensors.md, "Collector
// sensors"): an inventory source reports, per asset, when it last saw it
// (`last_seen_at`: the last event a log platform received from a host, the last
// poll a monitoring system answered). That time, not the report's, is the
// asset's last-seen time. It can only be earlier than the report (a source
// cannot have seen an asset after it reported); the store keeps the newer of
// two last-seen times, and an older observation never revives a stale asset
// (asset.ObserveAt).

import (
	"time"

	"github.com/openctemio/ctis/v2"
)

// earliestLastSeen bounds how old a reported last-seen time may be; an
// older value is a parse accident (an epoch in the wrong unit), not an
// observation.
var earliestLastSeen = time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)

// assetSeenAt is when the report's source last saw this asset: its
// last_seen_at when that is a time before the report's observation, else
// the report's observation time.
func assetSeenAt(ca *ctis.Asset, reportObserved time.Time) time.Time {
	if ca == nil || ca.LastSeenAt == nil {
		return reportObserved
	}
	t := ca.LastSeenAt.UTC()
	if t.Before(earliestLastSeen) || !t.Before(reportObserved) {
		return reportObserved
	}
	return t
}
