package sensor

import (
	"fmt"
	"time"
)

// State is a sensor's operational state as one value, for the fleet view. It
// combines the admin status, the heartbeat age and the problems a heartbeating
// sensor reports, so every client shows the same answer to "can this sensor
// take work right now, and if not, why". Computed on read (AssessHealth); it
// is never stored.
type State string

const (
	// StateOnline: heartbeat within the online window, nothing wrong.
	StateOnline State = "online"
	// StateDegraded: heartbeating, but something needs attention (see the
	// health reasons): results piling up, an expiring key, an unsupported
	// version, no scan tools, or an error the sensor reported.
	StateDegraded State = "degraded"
	// StateLate: past its heartbeat deadline and grace (liveness.go). Still
	// takes work; nobody is notified.
	StateLate State = "late"
	// StateStale: well past its deadline. Takes no new work and its pending
	// pinned work is released; nobody is notified yet.
	StateStale State = "stale"
	// StateOffline: past the offline step of the ladder and convicted by the
	// health checker (or past the heartbeat timeout).
	StateOffline State = "offline"
	// StateIdle: a one-shot (CI) sensor between runs. It only connects while
	// it runs, so a missing heartbeat is normal, not an outage.
	StateIdle State = "idle"
	// StateNeverConnected: created, but no heartbeat yet.
	StateNeverConnected State = "never_connected"
	// StateDisabled: an admin disabled it; it cannot authenticate.
	StateDisabled State = "disabled"
	// StateRevoked: access revoked for good.
	StateRevoked State = "revoked"
)

// AllStates lists every state, in ladder order (for stable breakdowns).
func AllStates() []State {
	return []State{
		StateOnline, StateDegraded, StateLate, StateStale, StateOffline,
		StateIdle, StateNeverConnected, StateDisabled, StateRevoked,
	}
}

// HealthReasonCode identifies one problem. Clients map codes to their own
// wording and fix actions; Message is a plain-English fallback.
type HealthReasonCode string

const (
	ReasonOutboxBacklog      HealthReasonCode = "outbox_backlog"
	ReasonOutboxDeadLetters  HealthReasonCode = "outbox_dead_letters"
	ReasonOutboxEvicted      HealthReasonCode = "outbox_evicted"
	ReasonKeyExpired         HealthReasonCode = "key_expired"
	ReasonKeyExpiring        HealthReasonCode = "key_expiring"
	ReasonIdentityCloned     HealthReasonCode = "identity_cloned"
	ReasonVersionUnsupported HealthReasonCode = "version_unsupported"
	ReasonSDKUnsupported     HealthReasonCode = "sdk_unsupported"
	ReasonNoTools            HealthReasonCode = "no_tools"
	ReasonErrorReported      HealthReasonCode = "error_reported"
	ReasonHeartbeatLate      HealthReasonCode = "heartbeat_late"
	ReasonControlSlow        HealthReasonCode = "control_slow"
	// Config report reasons (config_report.go): a setup check failed or
	// needs attention, or the stored report no longer matches the sensor.
	ReasonConfigCheckFailed  HealthReasonCode = "config_check_failed"
	ReasonConfigCheckWarning HealthReasonCode = "config_check_warning"
	ReasonConfigReportStale  HealthReasonCode = "config_report_stale"
)

// Reason severities.
const (
	SeverityWarning  = "warning"
	SeverityCritical = "critical"
)

// HealthReason is one problem found on a sensor.
type HealthReason struct {
	Code     HealthReasonCode
	Severity string
	Message  string
}

// Defaults for HealthPolicy.
const (
	// DefaultOnlineWindow is the online window at the default 30s idle
	// interval: the interval plus the ladder's 10s grace.
	DefaultOnlineWindow = 40 * time.Second
	// DefaultOfflineAfter matches WORKER_HEARTBEAT_TIMEOUT's default.
	DefaultOfflineAfter = 5 * time.Minute
	// DefaultKeyExpiryWarning: warn a week before a key stops working.
	DefaultKeyExpiryWarning = 7 * 24 * time.Hour
	// outboxBacklogAge: results older than this are "stuck" (the same
	// threshold as OutboxStats.Warning).
	outboxBacklogAge = 3600
)

// HealthPolicy holds the thresholds AssessHealth uses.
type HealthPolicy struct {
	// OnlineWindow is how long after its last heartbeat a sensor on the idle
	// interval stays online (interval + grace). Informational, for the stats
	// response: each sensor is judged against its own deadline (liveness.go).
	OnlineWindow time.Duration
	// OfflineAfter (WORKER_HEARTBEAT_TIMEOUT) is the backstop: a sensor past
	// the ladder's offline step that the health checker has not convicted
	// (it holds convictions while the platform is slow) shows stale until
	// its last heartbeat is this old, then offline.
	OfflineAfter time.Duration
	// KeyExpiryWarning: an API key expiring within this is reported.
	KeyExpiryWarning time.Duration
	// LatestVersion and MinVersion are the release channel
	// (SENSOR_LATEST_VERSION, SENSOR_MIN_VERSION); empty = not configured.
	LatestVersion string
	MinVersion    string
	// SDKLatestVersion and SDKMinVersion are the SDK policy
	// (SENSOR_SDK_LATEST_VERSION, SENSOR_SDK_MIN_VERSION); empty = not
	// configured. A heartbeating sensor below the minimum is degraded.
	SDKLatestVersion string
	SDKMinVersion    string
	// Content is the tenant's scanner content policy (content.go); nil uses
	// the platform default.
	Content *ContentPolicy
}

// DefaultHealthPolicy returns the default thresholds with no release channel.
func DefaultHealthPolicy() HealthPolicy {
	return HealthPolicy{}.Normalized()
}

// Normalized fills unset thresholds with the defaults, keeps the online window
// within the offline timeout, and normalizes the release versions (a value
// that is not a release version is dropped).
func (p HealthPolicy) Normalized() HealthPolicy {
	if p.OfflineAfter <= 0 {
		p.OfflineAfter = DefaultOfflineAfter
	}
	if p.OnlineWindow <= 0 {
		p.OnlineWindow = DefaultOnlineWindow
	}
	if p.OnlineWindow > p.OfflineAfter {
		p.OnlineWindow = p.OfflineAfter
	}
	if p.KeyExpiryWarning <= 0 {
		p.KeyExpiryWarning = DefaultKeyExpiryWarning
	}
	p.LatestVersion = releaseOrEmpty(p.LatestVersion)
	p.MinVersion = releaseOrEmpty(p.MinVersion)
	p.SDKLatestVersion = releaseOrEmpty(p.SDKLatestVersion)
	p.SDKMinVersion = releaseOrEmpty(p.SDKMinVersion)
	return p
}

func releaseOrEmpty(v string) string {
	if !IsReleaseVersion(v) {
		return ""
	}
	return NormalizeVersion(v)
}

// OnlineWindowFor is how long after its last heartbeat a sensor on the idle
// interval the platform advises (SENSOR_HEARTBEAT_INTERVAL) stays online: the
// interval plus the ladder's grace, at most the offline timeout.
func OnlineWindowFor(idleInterval, offlineAfter time.Duration) time.Duration {
	idleInterval = ClampHeartbeatInterval(idleInterval)
	w := idleInterval + LadderGrace(idleInterval)
	if offlineAfter > 0 && w > offlineAfter {
		w = offlineAfter
	}
	return w
}

// HealthAssessment is the computed view of one sensor.
type HealthAssessment struct {
	State State
	// Reasons lists every problem found, whatever the state (an expired key
	// matters on an offline sensor too). Never nil.
	Reasons []HealthReason
	// Version is the reported version in normalized form ("" if none).
	Version       string
	VersionStatus VersionStatus
	// SDKStatus compares the SDK version with the SDK policy.
	SDKStatus SDKStatus
	// UptimeSeconds is how long the sensor process had been running at its
	// last heartbeat; nil unless it is heartbeating and reported its uptime.
	UptimeSeconds *int64
}

// AssessHealth computes the sensor's state and problems at now.
func (a *Sensor) AssessHealth(now time.Time, p HealthPolicy) HealthAssessment {
	out := HealthAssessment{
		Version:       NormalizeVersion(a.Version),
		VersionStatus: ClassifyVersion(a.Version, p.LatestVersion, p.MinVersion),
		SDKStatus:     ClassifySDK(a.Build.SDKVersion, p.SDKLatestVersion, p.SDKMinVersion),
	}
	out.Reasons = a.healthReasons(now, p, out.VersionStatus, out.SDKStatus)

	heartbeating := false
	switch {
	case a.Status == SensorStatusRevoked:
		out.State = StateRevoked
	case a.Status == SensorStatusDisabled:
		out.State = StateDisabled
	case a.LastSeenAt == nil:
		out.State = StateNeverConnected
	default:
		pos := Ladder(now, a.HeartbeatDeadline())
		switch {
		case pos.State == SensorHealthOnline:
			heartbeating = true
			out.State = StateOnline
		case a.IsOneShot():
			out.State = StateIdle
		case a.Health == SensorHealthOffline:
			// Convicted by the health checker and silent since (any request
			// would have set health back to online).
			out.State = StateOffline
		case pos.State == SensorHealthLate:
			heartbeating = true
			out.State = StateLate
		case pos.State == SensorHealthStale || a.convictionPending(now, pos, p):
			heartbeating = true
			out.State = StateStale
		default:
			out.State = StateOffline
		}
		if (out.State == StateLate || out.State == StateStale) && !hasReason(out.Reasons, ReasonHeartbeatLate) {
			out.Reasons = append(out.Reasons, HealthReason{Code: ReasonHeartbeatLate, Severity: SeverityWarning,
				Message: fmt.Sprintf("The heartbeat due at %s has not arrived (the sensor heartbeats every %s). It goes offline at %s.",
					pos.Due.UTC().Format(time.RFC3339), humanDuration(pos.Interval), pos.OfflineAt.UTC().Format(time.RFC3339))})
		}
	}
	// A stale config report is only news while the sensor heartbeats.
	if out.State == StateOnline {
		if r, ok := a.configStaleReason(); ok {
			out.Reasons = append(out.Reasons, r)
		}
	}
	if out.State == StateOnline && len(out.Reasons) > 0 {
		out.State = StateDegraded
	}

	if heartbeating && a.StartedAt != nil && a.LastSeenAt != nil {
		if up := a.LastSeenAt.Sub(*a.StartedAt); up >= 0 {
			secs := int64(up.Seconds())
			out.UptimeSeconds = &secs
		}
	}
	return out
}

func hasReason(rs []HealthReason, code HealthReasonCode) bool {
	for _, r := range rs {
		if r.Code == code {
			return true
		}
	}
	return false
}

// convictionPending reports whether a sensor past the offline step of the
// ladder is still shown stale: the health checker has not convicted it
// (health is not offline), which it holds while the platform itself is slow
// (RFC-035 D3), and the heartbeat timeout has not passed either.
func (a *Sensor) convictionPending(now time.Time, pos LadderPosition, p HealthPolicy) bool {
	if a.Health == SensorHealthOffline || a.LastSeenAt == nil {
		return false
	}
	return now.Sub(*a.LastSeenAt) <= max(p.OfflineAfter, OfflineDistance(pos.Interval))
}

// healthReasons lists the problems that make a heartbeating sensor degraded.
func (a *Sensor) healthReasons(now time.Time, p HealthPolicy, vs VersionStatus, sdk SDKStatus) []HealthReason {
	reasons := make([]HealthReason, 0, 2)
	add := func(code HealthReasonCode, severity, msg string) {
		reasons = append(reasons, HealthReason{Code: code, Severity: severity, Message: msg})
	}

	if ob := a.Outbox; ob != nil {
		if ob.PendingCount > 0 && ob.OldestAgeSeconds > outboxBacklogAge {
			add(ReasonOutboxBacklog, SeverityWarning, fmt.Sprintf(
				"%d results are waiting to upload, the oldest for %s. Check that the sensor can reach the platform URL.",
				ob.PendingCount, humanDuration(time.Duration(ob.OldestAgeSeconds)*time.Second)))
		}
		if ob.DeadLetterCount > 0 {
			add(ReasonOutboxDeadLetters, SeverityCritical, fmt.Sprintf(
				"The platform refused %d results for good. Run openctemio-sensor -outbox-status on the host to see why.",
				ob.DeadLetterCount))
		}
		if ob.EvictedCount > 0 {
			add(ReasonOutboxEvicted, SeverityCritical, fmt.Sprintf(
				"%d results were dropped because the outbox reached its size or age limit.", ob.EvictedCount))
		}
	}

	if exp := a.KeyState().ExpiresAt; exp != nil {
		left := exp.Sub(now)
		switch {
		case left <= 0:
			add(ReasonKeyExpired, SeverityCritical,
				"The API key has expired, so the sensor can no longer connect. Rotate the key and update the sensor.")
		case left <= p.KeyExpiryWarning:
			add(ReasonKeyExpiring, SeverityWarning, fmt.Sprintf(
				"The API key expires in %s. The sensor renews it on its own; rotate it now if it cannot.",
				humanDuration(left)))
		}
	}

	if a.IdentityClonedAt != nil {
		add(ReasonIdentityCloned, SeverityCritical,
			"Two sensor processes are using this sensor's API key at the same time, so the key has been copied or is shared between replicas. Regenerate the key and give each sensor its own.")
	}

	if vs == VersionUnsupported {
		add(ReasonVersionUnsupported, SeverityCritical, fmt.Sprintf(
			"Version %s is older than the minimum supported version %s. Upgrade the sensor.",
			NormalizeVersion(a.Version), p.MinVersion))
	}

	if sdk == SDKUnsupported {
		name := a.Build.SDKName
		if name == "" {
			name = "SDK"
		}
		add(ReasonSDKUnsupported, SeverityWarning, fmt.Sprintf(
			"%s %s is below the minimum supported SDK version %s. Upgrade the sensor to a build with a newer SDK.",
			name, a.Build.SDKVersion, p.SDKMinVersion))
	}

	// A sensor that never connected has reported nothing yet: its state
	// (never_connected) already says so.
	if len(a.EffectiveTools()) == 0 && !a.Type.IsCollector() && a.IsDaemon() && a.LastSeenAt != nil {
		msg := "The sensor has not reported its tools, so the platform cannot dispatch scans to it. Upgrade it to a build that reports its tool manifest."
		if a.Reported.Tools != nil {
			// The sensor reported its inventory and nothing in it is installed.
			msg = "The sensor reports no installed scan tool, so the platform cannot dispatch scans to it."
		}
		add(ReasonNoTools, SeverityWarning, msg)
	}

	reasons = append(reasons, a.contentReasons(now, p.Content)...)

	if c := a.Control; c != nil {
		if c.GapLate() {
			add(ReasonHeartbeatLate, SeverityWarning, fmt.Sprintf(
				"The last heartbeat came %s after the previous one, more than %.1f times the %s interval. The sensor or its network may be overloaded.",
				humanDuration(secondsDuration(c.GapSeconds)), HeartbeatLateGapFactor, humanDuration(secondsDuration(c.IntervalSeconds))))
		}
		if c.IsSlow() {
			add(ReasonControlSlow, SeverityWarning, fmt.Sprintf(
				"The sensor's heartbeat loop is slow (timer lag %d ms, report build %d ms). Its host is short of CPU or a tool probe is hanging.",
				c.LagMillis, c.BuildMillis))
		}
	}

	reasons = append(reasons, a.configReasons()...)

	if a.Health == SensorHealthError {
		msg := "The sensor reported an error."
		if a.StatusMessage != "" {
			msg = "The sensor reported an error: " + a.StatusMessage
		}
		add(ReasonErrorReported, SeverityWarning, msg)
	}
	return reasons
}

// humanDuration renders a duration as "3d 4h", "2h 14m", "5m" or "40s".
func humanDuration(d time.Duration) string {
	if d < 0 {
		d = -d
	}
	switch {
	case d >= 24*time.Hour:
		days := int(d / (24 * time.Hour))
		hours := int((d % (24 * time.Hour)) / time.Hour)
		if hours == 0 {
			return fmt.Sprintf("%dd", days)
		}
		return fmt.Sprintf("%dd %dh", days, hours)
	case d >= time.Hour:
		hours := int(d / time.Hour)
		mins := int((d % time.Hour) / time.Minute)
		if mins == 0 {
			return fmt.Sprintf("%dh", hours)
		}
		return fmt.Sprintf("%dh %dm", hours, mins)
	case d >= time.Minute:
		return fmt.Sprintf("%dm", int(d/time.Minute))
	default:
		return fmt.Sprintf("%ds", int(d/time.Second))
	}
}
