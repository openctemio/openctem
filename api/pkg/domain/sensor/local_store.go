package sensor

// Local store report (research/194 "local store", sdk-go
// core.LocalStoreReport). sdk-go sends it on every heartbeat to a platform
// that lists the "local_store" feature:
//
//	"local_store": {"level": "high", "stop_claiming": true,
//	  "reason": "9 % of the volume free, below 10 %",
//	  "bytes_by_class": {"outbox": 1048576, "workspace": 52428800},
//	  "total_bytes": 53477376, "quota_bytes": 1073741824, "disk_level": "low",
//	  "sweeps": 12, "last_sweep_at": "2026-10-25T08:00:00Z", "last_sweep_removed": 3,
//	  "boot": 4, "tampered": 0}
//
// It says how full the sensor's local data is and whether the sensor has
// stopped claiming new jobs because of it (storage high, disk low, or its
// outbox full of results the platform has not acknowledged). Without it a
// sensor that stopped claiming looks idle and its scans just wait.
//
// The report is untrusted: it is read leniently (a member of the wrong type
// is ignored), enums outside their set are dropped, sizes are clamped and the
// reason is reduced to one short line of printable text. Display, health and
// placement explanations only: the platform never dispatches more or less
// because of it (the sensor itself decides to claim or not).

import (
	"encoding/json"
	"fmt"
	"math"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// Bounds on a local store report.
const (
	// MaxLocalStoreReasonRunes bounds the reason text.
	MaxLocalStoreReasonRunes = 240
	// MaxLocalStoreBytes bounds every byte count (1 PiB).
	MaxLocalStoreBytes = int64(1) << 50
	// MaxLocalStoreCount bounds sweeps, removed items and tampered records.
	MaxLocalStoreCount = 1_000_000_000
)

// Local store watermarks ("level") and disk levels ("disk_level").
const (
	LocalStoreLevelOK       = "ok"
	LocalStoreLevelHigh     = "high"
	LocalStoreLevelCritical = "critical"

	LocalDiskOK       = "ok"
	LocalDiskLow      = "low"
	LocalDiskCritical = "critical"
	LocalDiskUnknown  = "unknown"
)

// localStoreClasses are the data classes sdk-go reports bytes for; any other
// key is dropped.
var localStoreClasses = map[string]bool{
	"outbox": true, "dead_letter": true, "journal": true, "workspace": true,
	"content_pack": true, "log": true, "state": true,
}

// LocalStoreReport is the local store report of one heartbeat, or the one
// last stored.
type LocalStoreReport struct {
	// Level is the store's watermark: ok, high or critical ("" when the
	// sensor sent something else).
	Level string `json:"level,omitempty"`
	// StopClaiming: the sensor claims no new jobs until the store recovers.
	StopClaiming bool `json:"stop_claiming"`
	// Reason is why, in the sensor's words (sanitized, one line).
	Reason string `json:"reason,omitempty"`
	// BytesByClass is the bytes held per known class; TotalBytes their sum
	// as the sensor counted it; QuotaBytes the store's quota (0 = none).
	BytesByClass map[string]int64 `json:"bytes_by_class,omitempty"`
	TotalBytes   int64            `json:"total_bytes"`
	QuotaBytes   int64            `json:"quota_bytes,omitempty"`
	// DiskLevel is the store volume's state: ok, low, critical or unknown.
	DiskLevel string `json:"disk_level,omitempty"`
	// Sweeps counts cleanup sweeps since the sensor started; LastSweepAt and
	// LastSweepRemoved describe the latest.
	Sweeps           int64      `json:"sweeps"`
	LastSweepAt      *time.Time `json:"last_sweep_at,omitempty"`
	LastSweepRemoved int64      `json:"last_sweep_removed,omitempty"`
	// BootReset: the store's boot record was lost or went back at this
	// start (an old copy may have been restored). Tampered counts records
	// that failed authentication since start.
	BootReset bool  `json:"boot_reset,omitempty"`
	Tampered  int64 `json:"tampered,omitempty"`
	// ReportedAt is when the stored report was written; nil on a heartbeat.
	ReportedAt *time.Time `json:"-"`
}

// ParseLocalStoreReport reads a heartbeat's local_store member leniently. nil
// when the member is absent, not an object, or carries none of the known
// members.
func ParseLocalStoreReport(raw json.RawMessage) *LocalStoreReport {
	if len(raw) == 0 {
		return nil
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil || m == nil {
		return nil
	}
	var (
		r     LocalStoreReport
		found bool
	)
	str := func(key string) (string, bool) {
		v, ok := m[key].(string)
		return v, ok
	}
	count := func(key string, hi int64) (int64, bool) {
		v, ok := m[key].(float64)
		if !ok {
			return 0, false
		}
		return clampInt64(floatToInt64(v), hi), true
	}
	if v, ok := str("level"); ok {
		found = true
		switch v {
		case LocalStoreLevelOK, LocalStoreLevelHigh, LocalStoreLevelCritical:
			r.Level = v
		}
	}
	if v, ok := m["stop_claiming"].(bool); ok {
		r.StopClaiming, found = v, true
	}
	if v, ok := str("reason"); ok {
		r.Reason = sanitizeStoreReason(v)
	}
	if v, ok := m["bytes_by_class"].(map[string]any); ok {
		for class, b := range v {
			n, isNum := b.(float64)
			if !isNum || !localStoreClasses[class] {
				continue
			}
			if r.BytesByClass == nil {
				r.BytesByClass = map[string]int64{}
			}
			r.BytesByClass[class] = clampInt64(floatToInt64(n), MaxLocalStoreBytes)
		}
	}
	if v, ok := count("total_bytes", MaxLocalStoreBytes); ok {
		r.TotalBytes, found = v, true
	}
	if v, ok := count("quota_bytes", MaxLocalStoreBytes); ok {
		r.QuotaBytes = v
	}
	if v, ok := str("disk_level"); ok {
		switch v {
		case LocalDiskOK, LocalDiskLow, LocalDiskCritical, LocalDiskUnknown:
			r.DiskLevel = v
		}
	}
	if v, ok := count("sweeps", MaxLocalStoreCount); ok {
		r.Sweeps = v
	}
	if v, ok := str("last_sweep_at"); ok {
		if t, err := time.Parse(time.RFC3339Nano, v); err == nil && !t.IsZero() {
			t = t.UTC()
			r.LastSweepAt = &t
		}
	}
	if v, ok := count("last_sweep_removed", MaxLocalStoreCount); ok {
		r.LastSweepRemoved = v
	}
	if v, ok := m["boot_reset"].(bool); ok {
		r.BootReset = v
	}
	if v, ok := count("tampered", MaxLocalStoreCount); ok {
		r.Tampered = v
	}
	if !found {
		return nil
	}
	return &r
}

// sanitizeStoreReason keeps one line of printable text: control, format
// (bidi overrides, zero-width) and line-break characters become spaces, runs
// of spaces collapse, and the result is cut to MaxLocalStoreReasonRunes.
func sanitizeStoreReason(s string) string {
	if !utf8.ValidString(s) {
		s = strings.ToValidUTF8(s, "")
	}
	var b strings.Builder
	space := false
	n := 0
	for _, r := range s {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || unicode.IsSpace(r) || !unicode.IsPrint(r) {
			if !space && b.Len() > 0 {
				b.WriteByte(' ')
				space = true
			}
			continue
		}
		if n >= MaxLocalStoreReasonRunes {
			break
		}
		b.WriteRune(r)
		space = false
		n++
	}
	return strings.TrimSpace(b.String())
}

// localStoreFreshFor is how long after the latest request a stored report
// still describes the sensor: a report older than that was left behind by a
// heartbeat that no longer carries one (an SDK without a store). A steady
// sensor's report reaches Postgres with the liveness checkpoint, so the
// window is longer than the checkpoint period; a change of stop_claiming or
// of a level is written at once (HeartbeatStateDigest).
func localStoreFreshFor(interval time.Duration) time.Duration {
	return max(3*ClampHeartbeatInterval(interval), LivenessCheckpointPeriod+5*time.Minute)
}

// CurrentLocalStore is the stored local store report while it still
// describes the sensor (reported with its latest heartbeats), else nil.
func (a *Sensor) CurrentLocalStore() *LocalStoreReport {
	r := a.LocalStore
	if r == nil || r.ReportedAt == nil || a.LastSeenAt == nil {
		return nil
	}
	if a.LastSeenAt.Sub(*r.ReportedAt) > localStoreFreshFor(a.HeartbeatInterval) {
		return nil
	}
	return r
}

// StoppedClaiming reports whether the sensor said, with its latest
// heartbeats, that it claims no new jobs because of its local store.
func (a *Sensor) StoppedClaiming() bool {
	r := a.CurrentLocalStore()
	return r != nil && r.StopClaiming
}

// localStoreReason is the health reason of a sensor that stopped claiming.
func (a *Sensor) localStoreReason() (HealthReason, bool) {
	if !a.StoppedClaiming() {
		return HealthReason{}, false
	}
	r := a.CurrentLocalStore()
	msg := "The sensor stopped claiming new jobs because its local storage is full, so its scans wait. Free disk space on the sensor host or raise its store quota; it resumes on its own."
	if r.DiskLevel == LocalDiskLow || r.DiskLevel == LocalDiskCritical {
		msg = "The sensor stopped claiming new jobs because the disk under its data directory is almost full, so its scans wait. Free disk space on the sensor host; it resumes on its own."
	}
	if r.Reason != "" {
		msg = fmt.Sprintf("%s The sensor reports: %s.", msg, strings.TrimSuffix(r.Reason, "."))
	}
	return HealthReason{Code: ReasonStoppedClaiming, Severity: SeverityCritical, Message: msg}, true
}

// UsedFraction is TotalBytes over QuotaBytes, 0 without a quota.
func (r *LocalStoreReport) UsedFraction() float64 {
	if r == nil || r.QuotaBytes <= 0 {
		return 0
	}
	return math.Min(1, float64(r.TotalBytes)/float64(r.QuotaBytes))
}
