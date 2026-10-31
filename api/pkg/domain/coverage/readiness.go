package coverage

// Readiness (docs/rfcs/RFC-093-asset-coverage.md): before a coverage run is
// created, the planner asks whether the capability could run for the tenant
// at all. When it could not, no run is created and the capability's pairs
// whose time has come are paused with one reason from this closed set; the
// first pass where the capability is ready again resumes them.

import (
	"slices"
	"time"
)

// Readiness reasons. Each maps to exactly one action for the organization.
const (
	// ReadyPolicyDisabled: an organization or platform policy refuses the
	// run (the tool is switched off, scan approval holds it, its window
	// never opens, the managed scan is paused).
	ReadyPolicyDisabled = "policy_disabled"
	// ReadyNoScope: the organization has no active scope entry, so the
	// gate would refuse every target.
	ReadyNoScope = "no_scope"
	// ReadyToolMissing: no sensor of the organization reports the tool.
	ReadyToolMissing = "tool_missing"
	// ReadyToolNotAllowed: sensors have the tool but their grant or local
	// policy does not allow it.
	ReadyToolNotAllowed = "tool_not_allowed"
	// ReadySensorOffline: sensors have the tool and none takes work now.
	ReadySensorOffline = "sensor_offline"
	// ReadySensorOutdated: every online sensor with the tool reports a
	// version below the catalog's minimum.
	ReadySensorOutdated = "sensor_outdated"
	// ReadyNoEligibleSensor: no sensor may take the run (none installed,
	// none online for the organization, none in a zone that can place it).
	ReadyNoEligibleSensor = "no_eligible_sensor"
	// ReadyCredentialsMissing: the capability needs a credential (an API
	// key) that is not configured. Reserved: no capability declares one
	// yet.
	ReadyCredentialsMissing = "credentials_missing"
	// ReadyQuotaExhausted: the organization's share of shared scanning for
	// today is used up. Reserved: coverage runs need an organization
	// sensor today.
	ReadyQuotaExhausted = "quota_exhausted"
	// ReadyNotClaimed: the capability's last NotClaimedStreak coverage runs
	// ended with no sensor taking the work (NO_SENSOR: every sensor's
	// claim or dispatch gate kept it). It resumes when the tenant's sensor
	// fleet changes, or at a probe after NotClaimedRetry.
	ReadyNotClaimed = "not_claimed"
	// ReadyContentMissing: the capability's tool reads a list the platform
	// supplies (a wordlist pack) and the platform has none yet; an instance
	// administrator imports it.
	ReadyContentMissing = "content_missing"
)

// The not_claimed pause: after NotClaimedStreak runs in a row that no
// sensor took, the capability waits NotClaimedRetry before one probe run.
const (
	NotClaimedStreak   = 3
	NotClaimedProbe    = 2 * time.Hour
	NotClaimedProbeMax = 48 * time.Hour
)

// NotClaimedRetry is how long a capability paused after streak unclaimed
// runs waits before its probe: NotClaimedProbe at the streak, doubled per
// further unclaimed run, at most NotClaimedProbeMax.
func NotClaimedRetry(streak int) time.Duration {
	d := NotClaimedProbe
	for i := NotClaimedStreak; i < streak && d < NotClaimedProbeMax; i++ {
		d *= 2
	}
	return min(d, NotClaimedProbeMax)
}

// Hold is a capability's unclaimed-run state for one tenant.
type Hold struct {
	Capability string
	// Streak counts its coverage runs in a row that no sensor took.
	Streak int
	// Fingerprint is the tenant's sensor fleet when the pause was last
	// recorded ("" when it could not be read).
	Fingerprint string
	// ProbeAt is when the paused capability runs once again.
	ProbeAt *time.Time
}

// Active reports whether the hold pauses the capability.
func (h Hold) Active() bool { return h.Streak >= NotClaimedStreak }

var readinessReasons = []string{
	ReadyPolicyDisabled, ReadyNoScope, ReadyToolMissing, ReadyToolNotAllowed, ReadySensorOffline,
	ReadySensorOutdated, ReadyNoEligibleSensor, ReadyCredentialsMissing, ReadyQuotaExhausted,
	ReadyNotClaimed, ReadyContentMissing,
}

// ReadinessReasons returns the closed set of readiness reasons.
func ReadinessReasons() []string { return slices.Clone(readinessReasons) }

// IsReadinessReason reports whether r is one of the readiness reasons.
func IsReadinessReason(r string) bool { return slices.Contains(readinessReasons, r) }
