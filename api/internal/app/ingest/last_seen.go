package ingest

// When an asset was last seen (docs/architecture/sensors.md, "Collector
// sensors"): an inventory source reports, per asset, when it last saw it
// (`last_seen`: the last event a log platform received from a host, the last
// poll a monitoring system answered). That time, not the report's, is the
// asset's last-seen time. It can only be earlier than the report (a source
// cannot have seen an asset after it reported); the store keeps the newer of
// two last-seen times, and an older observation never revives a stale asset
// (asset.ObserveAt).

import (
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/openctemio/ctis"
)

// propLastSeen is the property in which a source reports when it last saw
// the asset.
const propLastSeen = "last_seen"

// earliestLastSeen bounds how old a reported last-seen time may be; an
// older value is a parse accident (an epoch in the wrong unit), not an
// observation.
var earliestLastSeen = time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)

// assetSeenAt is when the report's source last saw this asset: its
// last_seen property when that is a time before the report's observation,
// else the report's observation time.
func assetSeenAt(ca *ctis.Asset, reportObserved time.Time) time.Time {
	if ca == nil {
		return reportObserved
	}
	t, ok := parseLastSeen(ca.Properties[propLastSeen])
	if !ok || t.Before(earliestLastSeen) || !t.Before(reportObserved) {
		return reportObserved
	}
	return t
}

// parseLastSeen reads a time as RFC 3339, "2006-01-02 15:04:05" (UTC), or
// Unix seconds (a number or a decimal string).
func parseLastSeen(v any) (time.Time, bool) {
	switch x := v.(type) {
	case string:
		s := strings.TrimSpace(x)
		if s == "" {
			return time.Time{}, false
		}
		for _, layout := range []string{time.RFC3339Nano, "2006-01-02 15:04:05"} {
			if t, err := time.Parse(layout, s); err == nil {
				return t.UTC(), true
			}
		}
		if f, err := strconv.ParseFloat(s, 64); err == nil {
			return unixSeconds(f)
		}
	case float64:
		return unixSeconds(x)
	case int64:
		return unixSeconds(float64(x))
	case int:
		return unixSeconds(float64(x))
	}
	return time.Time{}, false
}

func unixSeconds(f float64) (time.Time, bool) {
	if math.IsNaN(f) || math.IsInf(f, 0) || f <= 0 || f > 1e11 {
		return time.Time{}, false
	}
	sec, frac := math.Modf(f)
	return time.Unix(int64(sec), int64(frac*1e9)).UTC(), true
}
