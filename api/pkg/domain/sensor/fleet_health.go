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
	// StateStale: the last heartbeat is older than the online window but the
	// heartbeat timeout has not passed yet.
	StateStale State = "stale"
	// StateOffline: no heartbeat within the heartbeat timeout.
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
		StateOnline, StateDegraded, StateStale, StateOffline,
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
	// DefaultOnlineWindow: a sensor heartbeats every 30s by default, so 90s
	// is three missed heartbeats.
	DefaultOnlineWindow = 90 * time.Second
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
	// OnlineWindow: a heartbeat at most this old is online.
	OnlineWindow time.Duration
	// OfflineAfter: a heartbeat older than this is offline
	// (WORKER_HEARTBEAT_TIMEOUT, the same timeout the health checker uses).
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

// OnlineWindowFor derives the online window from the idle heartbeat interval
// the platform advises (SENSOR_HEARTBEAT_INTERVAL): three intervals, at least
// DefaultOnlineWindow, at most the offline timeout.
func OnlineWindowFor(idleInterval, offlineAfter time.Duration) time.Duration {
	w := 3 * idleInterval
	if w < DefaultOnlineWindow {
		w = DefaultOnlineWindow
	}
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
		age := now.Sub(*a.LastSeenAt)
		switch {
		case age <= p.OnlineWindow:
			heartbeating = true
			out.State = StateOnline
			if len(out.Reasons) > 0 {
				out.State = StateDegraded
			}
		case a.IsOneShot():
			out.State = StateIdle
		case age <= p.OfflineAfter && a.Health != SensorHealthOffline:
			heartbeating = true
			out.State = StateStale
		default:
			out.State = StateOffline
		}
	}

	if heartbeating && a.StartedAt != nil && a.LastSeenAt != nil {
		if up := a.LastSeenAt.Sub(*a.StartedAt); up >= 0 {
			secs := int64(up.Seconds())
			out.UptimeSeconds = &secs
		}
	}
	return out
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

	if a.KeyExpiresAt != nil {
		left := a.KeyExpiresAt.Sub(now)
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

	if len(a.EffectiveTools()) == 0 && !a.Type.IsCollector() && a.IsDaemon() {
		msg := "No scan tools are configured, so the platform cannot dispatch scans to this sensor."
		if a.Reported.Tools != nil {
			// The sensor reported its inventory: nothing it has installed is
			// allowed by its tool limit (or it has nothing installed).
			msg = "None of the sensor's installed tools is allowed by its tool limit (or none is installed), so the platform cannot dispatch scans to this sensor."
		}
		add(ReasonNoTools, SeverityWarning, msg)
	}

	reasons = append(reasons, a.contentReasons(now, p.Content)...)

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
