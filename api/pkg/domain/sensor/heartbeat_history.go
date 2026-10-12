package sensor

// Heartbeat history: a small, bounded record of how a sensor's heartbeats
// arrived, for the 24 h sparkline of the Control channel card
// (docs/rfcs/RFC-035-sensor-control-plane-under-load.md §5.5). One row per
// sensor per HeartbeatHistoryBucket, aggregated on write, deleted after
// HeartbeatHistoryRetention: at most 192 rows per sensor.

import (
	"context"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

const (
	// HeartbeatHistoryBucket is the width of one history bucket.
	HeartbeatHistoryBucket = 15 * time.Minute
	// HeartbeatHistoryRetention is how long buckets are kept.
	HeartbeatHistoryRetention = 48 * time.Hour
	// MaxHeartbeatHistoryWindow is the longest window a read returns.
	MaxHeartbeatHistoryWindow = 24 * time.Hour
	// MaxRecordedHeartbeatGap bounds the gap one heartbeat records: a sensor
	// back after days does not skew the averages (it is in the activity).
	MaxRecordedHeartbeatGap = 6 * time.Hour
)

// HeartbeatSample is what one heartbeat adds to its bucket. Gap is the time
// since the previous heartbeat as the platform saw it (0 on the first);
// LagMillis and Failures come from the sensor's control report (0 without).
type HeartbeatSample struct {
	TenantID  shared.ID
	SensorID  shared.ID
	At        time.Time
	Gap       time.Duration
	Interval  time.Duration
	LagMillis int64
	Failures  int64
}

// HeartbeatBucket is one bucket of the history.
type HeartbeatBucket struct {
	// Start is the bucket's start (aligned on HeartbeatHistoryBucket).
	Start time.Time `json:"at"`
	// Beats is the heartbeats received in the bucket.
	Beats int `json:"beats"`
	// AvgGapSeconds and MaxGapSeconds are over the heartbeats that had a
	// previous one (0 when none had).
	AvgGapSeconds float64 `json:"avg_gap_s"`
	MaxGapSeconds float64 `json:"max_gap_s"`
	// IntervalSeconds is the largest interval the sensor followed in the
	// bucket (what the gaps compare with).
	IntervalSeconds float64 `json:"interval_s"`
	// MaxLagMillis is the largest timer lag the sensor reported; Failures
	// the heartbeats it reported lost.
	MaxLagMillis int64 `json:"max_lag_ms"`
	Failures     int64 `json:"failures"`
}

// HeartbeatBucketStart is the start of the bucket at falls in.
func HeartbeatBucketStart(at time.Time) time.Time {
	return at.UTC().Truncate(HeartbeatHistoryBucket)
}

// Clamped bounds a sample before it is stored (the control values are
// untrusted; the gap is the platform's own measurement).
func (s HeartbeatSample) Clamped() HeartbeatSample {
	s.Gap = min(max(s.Gap, 0), MaxRecordedHeartbeatGap)
	s.Interval = min(max(s.Interval, 0), MaxRecordedHeartbeatGap)
	s.LagMillis = min(max(s.LagMillis, 0), int64(MaxRecordedHeartbeatGap/time.Millisecond))
	s.Failures = min(max(s.Failures, 0), 1_000_000)
	return s
}

// HeartbeatHistoryRepository stores and reads the heartbeat history.
type HeartbeatHistoryRepository interface {
	// RecordHeartbeat adds one heartbeat to its bucket.
	RecordHeartbeat(ctx context.Context, s HeartbeatSample) error
	// HeartbeatHistory returns the buckets of one tenant sensor since since,
	// oldest first.
	HeartbeatHistory(ctx context.Context, tenantID, sensorID shared.ID, since time.Time) ([]HeartbeatBucket, error)
	// DeleteHeartbeatHistoryBefore removes up to limit buckets that started
	// before before.
	DeleteHeartbeatHistoryBefore(ctx context.Context, before time.Time, limit int) (int64, error)
}
