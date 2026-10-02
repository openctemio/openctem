package sensor

// Heartbeat deadline and suspicion ladder
// (docs/rfcs/RFC-035-sensor-control-plane-under-load.md §5.6).
//
// Every heartbeat stores the interval the sensor follows and the deadline of
// its next heartbeat. A sensor is judged against its own deadline, not a
// global timeout: one told "come back in 45 s" is not late at 40 s, and one
// told "5 s" (work waiting) is noticed sooner. Past the deadline it walks
// online -> late -> stale -> offline (SWIM's suspect state):
//
//	grace   = max(10 s, 0.2 × interval)
//	online  : now ≤ due + grace
//	late    : now ≤ due + 2 × interval + grace   (still dispatchable)
//	stale   : now ≤ due + max(3 × interval, 90 s) (not dispatchable; pins released)
//	offline : beyond                              (sensor.offline is notified)
//
// Ladder is the one place that math lives: the health controller writes the
// state it computes into sensors.health, and the fleet view (AssessHealth)
// computes it on read.

import (
	"math"
	"time"
)

// Health values the ladder adds to SensorHealth (entity.go).
const (
	// SensorHealthLate: past its deadline and grace. Still dispatchable.
	SensorHealthLate SensorHealth = "late"
	// SensorHealthStale: well past its deadline. Not dispatchable, and its
	// pending pinned work is released.
	SensorHealthStale SensorHealth = "stale"
)

// Ladder bounds.
const (
	// DefaultHeartbeatInterval is the interval of a sensor that does not
	// follow the platform's advice (the SDK default), and of a sensor whose
	// row has no stored interval yet.
	DefaultHeartbeatInterval = 60 * time.Second
	// MinHeartbeatInterval and MaxHeartbeatInterval bound the stored
	// interval: a sensor cannot stretch its own deadline beyond five minutes
	// by reporting a long interval.
	MinHeartbeatInterval = time.Second
	MaxHeartbeatInterval = 5 * time.Minute
	// LadderGraceFloor is the smallest grace past the deadline.
	LadderGraceFloor = 10 * time.Second
	// LadderOfflineFloor is the smallest time from the deadline to offline.
	LadderOfflineFloor = 90 * time.Second
)

// HeartbeatDeadline is what the platform stored about a sensor's next
// heartbeat.
type HeartbeatDeadline struct {
	// LastSeenAt is the sensor's last authenticated request (heartbeat,
	// poll, result). nil: never.
	LastSeenAt *time.Time
	// DueAt is when the next heartbeat is due (heartbeat_due_at). nil on rows
	// that have not heartbeated since the column was added.
	DueAt *time.Time
	// Interval is the interval the sensor follows (heartbeat_interval_seconds);
	// 0 when unknown (DefaultHeartbeatInterval applies).
	Interval time.Duration
}

// LadderPosition is where a sensor stands on the ladder at one instant.
type LadderPosition struct {
	// State is online, late, stale or offline.
	State SensorHealth
	// Interval is the interval the thresholds were computed from.
	Interval time.Duration
	// Due is the effective deadline; LateAt, StaleAt and OfflineAt are the
	// instants after which the sensor is late, stale and offline. All zero
	// when the sensor was never seen.
	Due, LateAt, StaleAt, OfflineAt time.Time
}

// ClampHeartbeatInterval bounds an interval to [MinHeartbeatInterval,
// MaxHeartbeatInterval]; zero or negative is DefaultHeartbeatInterval.
func ClampHeartbeatInterval(d time.Duration) time.Duration {
	switch {
	case d <= 0:
		return DefaultHeartbeatInterval
	case d < MinHeartbeatInterval:
		return MinHeartbeatInterval
	case d > MaxHeartbeatInterval:
		return MaxHeartbeatInterval
	}
	return d
}

// LadderGrace is the grace past the deadline before a sensor is late.
func LadderGrace(interval time.Duration) time.Duration {
	return max(LadderGraceFloor, interval/5)
}

// OfflineDistance is how long after its last heartbeat a sensor that follows
// interval is convicted offline: one interval to the deadline, then
// max(3 × interval, 90 s).
func OfflineDistance(interval time.Duration) time.Duration {
	interval = ClampHeartbeatInterval(interval)
	return interval + max(3*interval, LadderOfflineFloor)
}

// FollowedHeartbeatInterval is the interval a sensor will follow after this
// heartbeat, which its deadline is computed from:
//
//   - the interval the sensor reports it follows (control.interval_s),
//   - or, when the sensor follows the platform's advice (doorbell-aware), the
//     interval just advised, whichever is longer: the report describes the
//     interval it followed until now, the advice the one it follows next, so
//     the longer one never convicts a sensor for obeying fresh advice;
//   - else DefaultHeartbeatInterval (a sensor that ignores hints).
//
// The result is bounded by ClampHeartbeatInterval.
func FollowedHeartbeatInterval(control *ControlReport, advisedSeconds int, aware bool) time.Duration {
	var d time.Duration
	if control != nil && control.IntervalSeconds > 0 {
		d = secondsDuration(control.IntervalSeconds)
	}
	if aware && advisedSeconds > 0 {
		d = max(d, time.Duration(advisedSeconds)*time.Second)
	}
	return ClampHeartbeatInterval(d)
}

// Ladder places a sensor on the suspicion ladder at now. The effective
// deadline is the later of the stored one and last_seen_at + interval: any
// authenticated request proves the sensor alive, and a row without a stored
// deadline falls back to last_seen_at + DefaultHeartbeatInterval. A sensor
// never seen at all is offline.
func Ladder(now time.Time, d HeartbeatDeadline) LadderPosition {
	interval := ClampHeartbeatInterval(d.Interval)
	pos := LadderPosition{State: SensorHealthOffline, Interval: interval}

	var due time.Time
	if d.LastSeenAt != nil {
		due = d.LastSeenAt.Add(interval)
	}
	if d.DueAt != nil && d.DueAt.After(due) {
		due = *d.DueAt
	}
	if due.IsZero() {
		return pos
	}

	grace := LadderGrace(interval)
	pos.Due = due
	pos.LateAt = due.Add(grace)
	pos.StaleAt = due.Add(2*interval + grace)
	pos.OfflineAt = due.Add(max(3*interval, LadderOfflineFloor))

	switch {
	case !now.After(pos.LateAt):
		pos.State = SensorHealthOnline
	case !now.After(pos.StaleAt):
		pos.State = SensorHealthLate
	case !now.After(pos.OfflineAt):
		pos.State = SensorHealthStale
	default:
		pos.State = SensorHealthOffline
	}
	return pos
}

// HeartbeatDeadline returns the sensor's stored deadline.
func (a *Sensor) HeartbeatDeadline() HeartbeatDeadline {
	return HeartbeatDeadline{LastSeenAt: a.LastSeenAt, DueAt: a.HeartbeatDueAt, Interval: a.HeartbeatInterval}
}

// IsDispatchable reports whether a sensor in this health may be handed new
// work: online or late. Stale and offline sensors get none.
func (h SensorHealth) IsDispatchable() bool {
	return h == SensorHealthOnline || h == SensorHealthLate
}

// IsLive reports whether the health controller still watches the sensor's
// deadline: online, late or stale.
func (h SensorHealth) IsLive() bool {
	return h == SensorHealthOnline || h == SensorHealthLate || h == SensorHealthStale
}

func secondsDuration(s float64) time.Duration {
	if math.IsNaN(s) || math.IsInf(s, 0) || s <= 0 {
		return 0
	}
	if s > MaxReportedControlSeconds {
		s = MaxReportedControlSeconds
	}
	return time.Duration(s * float64(time.Second))
}
