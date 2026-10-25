package coverage

// Readiness (docs/rfcs/RFC-093-asset-coverage.md): before a coverage run is
// created, the planner asks whether the capability could run for the tenant
// at all. When it could not, no run is created and the capability's pairs
// whose time has come are paused with one reason from this closed set; the
// first pass where the capability is ready again resumes them.

import "slices"

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
)

var readinessReasons = []string{
	ReadyPolicyDisabled, ReadyNoScope, ReadyToolMissing, ReadyToolNotAllowed, ReadySensorOffline,
	ReadySensorOutdated, ReadyNoEligibleSensor, ReadyCredentialsMissing, ReadyQuotaExhausted,
}

// ReadinessReasons returns the closed set of readiness reasons.
func ReadinessReasons() []string { return slices.Clone(readinessReasons) }

// IsReadinessReason reports whether r is one of the readiness reasons.
func IsReadinessReason(r string) bool { return slices.Contains(readinessReasons, r) }
