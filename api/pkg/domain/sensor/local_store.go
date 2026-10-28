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
	"regexp"
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
	// Content is what the sensor says about the content packs it holds
	// (RFC-061 §3.7); nil when it reported none.
	Content *ContentReport `json:"content,omitempty"`
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
	if c := parseContentReport(m["content"]); c != nil {
		r.Content, found = c, true
	}
	if !found {
		return nil
	}
	return &r
}

// Bounds on a content report.
const (
	// MaxReportedPackDigests bounds ContentReport.Held.
	MaxReportedPackDigests = 200
	// MaxContentVersionLen bounds the desired-set version a sensor echoes.
	MaxContentVersionLen = 128
)

// ContentReport is the content packs a sensor holds, from its heartbeat
// (sdk-go core.ContentReport): digests, so the platform sees drift between
// what it wants held and what is held, and the cache's delivery counters. It
// is untrusted and display-only: the platform never dispatches differently
// because of it. It carries no tenant names, paths or file names.
type ContentReport struct {
	// Held are the pack digests held (sorted, at most MaxReportedPackDigests);
	// HeldCount is how many are held in all and HeldSetSHA256 the hex SHA-256
	// of the whole sorted list.
	Held          []string `json:"held,omitempty"`
	HeldCount     int64    `json:"held_count"`
	HeldSetSHA256 string   `json:"held_set_sha256,omitempty"`
	// Bytes is what the packs occupy.
	Bytes int64 `json:"bytes"`
	// Hits, Misses, BytesDownloaded and BytesSaved are the cache's delivery
	// counters since the sensor started.
	Hits            int64 `json:"hits"`
	Misses          int64 `json:"misses"`
	BytesDownloaded int64 `json:"bytes_downloaded"`
	BytesSaved      int64 `json:"bytes_saved"`
	// VerifyFailures counts packs that failed a check on load or install.
	VerifyFailures int64 `json:"verify_failures,omitempty"`
	// DesiredVersion is the content version the sensor last synced.
	DesiredVersion string `json:"desired_version,omitempty"`
}

var (
	packDigestRE  = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	sha256HexOnly = regexp.MustCompile(`^[0-9a-f]{64}$`)
	versionRE     = regexp.MustCompile(`^[0-9A-Za-z\-_:./"]+$`)
)

// parseContentReport reads the content member of a local store report
// leniently: a member of the wrong type is ignored, a digest that is not a
// sha256 digest is dropped, counts are clamped. nil when v is not an object.
func parseContentReport(v any) *ContentReport {
	m, ok := v.(map[string]any)
	if !ok || m == nil {
		return nil
	}
	var c ContentReport
	count := func(key string, hi int64) int64 {
		f, ok := m[key].(float64)
		if !ok {
			return 0
		}
		return clampInt64(floatToInt64(f), hi)
	}
	if held, ok := m["held"].([]any); ok {
		for _, h := range held {
			d, ok := h.(string)
			if !ok || !packDigestRE.MatchString(d) || len(c.Held) >= MaxReportedPackDigests {
				continue
			}
			c.Held = append(c.Held, d)
		}
	}
	c.HeldCount = max(count("held_count", MaxLocalStoreCount), int64(len(c.Held)))
	if h, ok := m["held_set_sha256"].(string); ok && sha256HexOnly.MatchString(h) {
		c.HeldSetSHA256 = h
	}
	c.Bytes = count("bytes", MaxLocalStoreBytes)
	c.Hits = count("hits", MaxLocalStoreCount)
	c.Misses = count("misses", MaxLocalStoreCount)
	c.BytesDownloaded = count("bytes_downloaded", MaxLocalStoreBytes)
	c.BytesSaved = count("bytes_saved", MaxLocalStoreBytes)
	c.VerifyFailures = count("verify_failures", MaxLocalStoreCount)
	if d, ok := m["desired_version"].(string); ok && len(d) <= MaxContentVersionLen && versionRE.MatchString(d) {
		c.DesiredVersion = d
	}
	return &c
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
