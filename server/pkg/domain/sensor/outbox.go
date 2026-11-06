package sensor

import "time"

// OutboxStats is the state of a sensor's durable outbox (the on-disk queue of
// results waiting to be delivered), as the sensor last reported it on the
// heartbeat.
//
// It is display data from an untrusted process: it is clamped on ingest
// (Clamp) and nothing authorizes, schedules or bills on it.
type OutboxStats struct {
	// PendingCount is the number of items waiting to be delivered.
	PendingCount int64 `json:"pending_count"`
	// PendingBytes is the size on disk of those items.
	PendingBytes int64 `json:"pending_bytes"`
	// OldestAgeSeconds is the age of the oldest pending item; 0 when empty.
	OldestAgeSeconds int64 `json:"oldest_age_seconds"`
	// DeadLetterCount is the number of items the platform refused for good,
	// kept in the sensor's dead-letter folder.
	DeadLetterCount int64 `json:"dead_letter_count"`
	// EvictedCount is the number of items dropped by the size/age cap since
	// the sensor process started.
	EvictedCount int64 `json:"evicted_count"`

	// ReportedAt is when the snapshot was stored. Set by the repository from
	// the database clock, never by the sensor.
	ReportedAt time.Time `json:"-"`
}

// Upper bounds applied by Clamp. They are far above anything a real sensor
// reports; they only stop a buggy or hostile sensor from storing nonsense.
const (
	MaxOutboxCount      int64 = 10_000_000
	MaxOutboxBytes      int64 = 1 << 50                 // 1 PiB
	MaxOutboxAgeSeconds int64 = 10 * 365 * 24 * 60 * 60 // 10 years
)

// OutboxWarnOldestAgeSeconds is the oldest-pending-item age above which the
// outbox is flagged: an item an hour old means the sensor has not been able to
// deliver for an hour.
const OutboxWarnOldestAgeSeconds int64 = 3600

// Clamp returns a copy with every value in [0, its maximum].
func (o OutboxStats) Clamp() OutboxStats {
	o.PendingCount = clampInt64(o.PendingCount, MaxOutboxCount)
	o.PendingBytes = clampInt64(o.PendingBytes, MaxOutboxBytes)
	o.OldestAgeSeconds = clampInt64(o.OldestAgeSeconds, MaxOutboxAgeSeconds)
	o.DeadLetterCount = clampInt64(o.DeadLetterCount, MaxOutboxCount)
	o.EvictedCount = clampInt64(o.EvictedCount, MaxOutboxCount)
	return o
}

// Warning reports whether the outbox needs an operator's attention: something
// was dead-lettered or evicted (results were lost or refused), or the oldest
// pending item is older than OutboxWarnOldestAgeSeconds (delivery is stuck).
func (o OutboxStats) Warning() bool {
	return o.DeadLetterCount > 0 || o.EvictedCount > 0 || o.OldestAgeSeconds > OutboxWarnOldestAgeSeconds
}

func clampInt64(v, maxV int64) int64 {
	if v < 0 {
		return 0
	}
	if v > maxV {
		return maxV
	}
	return v
}
