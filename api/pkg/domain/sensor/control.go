package sensor

// Control-channel report (docs/rfcs/RFC-035-sensor-control-plane-under-load.md
// §5.5). sdk-go sends it on every heartbeat:
//
//	"control": {"interval_s": 30, "gap_s": 30.004, "lag_ms": 1, "build_ms": 3, "rtt_ms": 9, "failures": 0}
//
// It says how well the sensor's heartbeat loop keeps time under load. The
// report is untrusted: it is read leniently (a member of the wrong type is
// ignored) and clamped before it is stored. Display and health reasons only,
// except interval_s, which feeds the sensor's deadline within
// [MinHeartbeatInterval, MaxHeartbeatInterval] (liveness.go).

import (
	"encoding/json"
	"math"
	"time"
)

// Bounds on a control report.
const (
	// MaxReportedControlSeconds bounds interval_s and gap_s (a day).
	MaxReportedControlSeconds = 24 * 3600
	// MaxReportedControlMillis bounds lag_ms, build_ms and rtt_ms (an hour).
	MaxReportedControlMillis = 3600 * 1000
	// MaxReportedControlFailures bounds failures.
	MaxReportedControlFailures = 1_000_000

	// ControlSlowMillis: a timer lag or report build above this is reported
	// as control_slow.
	ControlSlowMillis = 5000
	// HeartbeatLateGapFactor: a delivered heartbeat whose gap since the
	// previous one exceeds this many intervals is reported as heartbeat_late.
	HeartbeatLateGapFactor = 1.5
)

// ControlReport is the control-channel report of one heartbeat, or the one
// last stored.
type ControlReport struct {
	// IntervalSeconds is the interval the sensor follows (the advice).
	IntervalSeconds float64 `json:"interval_s"`
	// GapSeconds is the time since the previous delivered heartbeat.
	GapSeconds float64 `json:"gap_s"`
	// LagMillis is how late the heartbeat timer fired (CPU starvation).
	LagMillis int64 `json:"lag_ms"`
	// BuildMillis is how long building the report took.
	BuildMillis int64 `json:"build_ms"`
	// RTTMillis is the round trip of the previous heartbeat.
	RTTMillis int64 `json:"rtt_ms"`
	// Failures is the number of heartbeats lost since the previous one.
	Failures int64 `json:"failures"`
	// ReportedAt is when the stored report was written; nil on a heartbeat.
	ReportedAt *time.Time `json:"-"`
}

// ParseControlReport reads a heartbeat's control member leniently: it must
// be an object; each known member that is a number is taken, anything else
// is ignored. nil when the member is absent, not an object, or carries none
// of the known members. The result is clamped.
func ParseControlReport(raw json.RawMessage) *ControlReport {
	if len(raw) == 0 {
		return nil
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil || m == nil {
		return nil
	}
	num := func(key string) (float64, bool) {
		v, ok := m[key].(float64)
		return v, ok
	}
	var (
		c     ControlReport
		found bool
	)
	if v, ok := num("interval_s"); ok {
		c.IntervalSeconds, found = v, true
	}
	if v, ok := num("gap_s"); ok {
		c.GapSeconds, found = v, true
	}
	if v, ok := num("lag_ms"); ok {
		c.LagMillis, found = floatToInt64(v), true
	}
	if v, ok := num("build_ms"); ok {
		c.BuildMillis, found = floatToInt64(v), true
	}
	if v, ok := num("rtt_ms"); ok {
		c.RTTMillis, found = floatToInt64(v), true
	}
	if v, ok := num("failures"); ok {
		c.Failures, found = floatToInt64(v), true
	}
	if !found {
		return nil
	}
	clamped := c.Clamp()
	return &clamped
}

// Clamp returns the report with every value inside its bounds (negative,
// NaN and infinite values become 0).
func (c ControlReport) Clamp() ControlReport {
	c.IntervalSeconds = roundMillis(clampFloat(c.IntervalSeconds, MaxReportedControlSeconds))
	c.GapSeconds = roundMillis(clampFloat(c.GapSeconds, MaxReportedControlSeconds))
	c.LagMillis = clampInt64(c.LagMillis, MaxReportedControlMillis)
	c.BuildMillis = clampInt64(c.BuildMillis, MaxReportedControlMillis)
	c.RTTMillis = clampInt64(c.RTTMillis, MaxReportedControlMillis)
	c.Failures = clampInt64(c.Failures, MaxReportedControlFailures)
	return c
}

// IsSlow reports whether the timer lag or the report build exceeded
// ControlSlowMillis.
func (c *ControlReport) IsSlow() bool {
	return c != nil && (c.LagMillis > ControlSlowMillis || c.BuildMillis > ControlSlowMillis)
}

// GapLate reports whether the delivered heartbeat came more than
// HeartbeatLateGapFactor intervals after the previous one.
func (c *ControlReport) GapLate() bool {
	return c != nil && c.IntervalSeconds > 0 && c.GapSeconds > HeartbeatLateGapFactor*c.IntervalSeconds
}

func floatToInt64(v float64) int64 {
	if math.IsNaN(v) || v <= 0 {
		return 0
	}
	if v >= math.MaxInt64/2 {
		return math.MaxInt64 / 2
	}
	return int64(math.Round(v))
}

func roundMillis(v float64) float64 {
	return math.Round(v*1000) / 1000
}
