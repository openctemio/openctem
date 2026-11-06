package tenant

import (
	tenantdom "github.com/openctemio/openctem/api/pkg/domain/tenant"
)

// Loosening of an organization policy needs a recent re-authentication and is
// audited at high severity; tightening needs neither. The three checks below
// cover the asset lifecycle, CTEM cycle and attack-surface settings. They
// compare effective values, so a stored zero (the default) and the default
// written out count the same.

// lifecycleLoosened reports a change that lets the lifecycle worker demote
// more assets sooner, or with fewer guards: turning it on, a shorter stale
// threshold or grace period, running while an integration is unhealthy, or
// fewer source types left out of it.
func lifecycleLoosened(before, after tenantdom.AssetLifecycleSettings) bool {
	if !after.Enabled {
		return false
	}
	if !before.Enabled {
		return true
	}
	if after.EffectiveStaleThresholdDays() < before.EffectiveStaleThresholdDays() ||
		after.EffectiveGracePeriodDays() < before.EffectiveGracePeriodDays() ||
		after.EffectiveManualReactivationGraceDays() < before.EffectiveManualReactivationGraceDays() {
		return true
	}
	if before.PauseOnIntegrationFailure && !after.PauseOnIntegrationFailure {
		return true
	}
	kept := make(map[string]struct{}, len(after.EffectiveExcludedSourceTypes()))
	for _, st := range after.EffectiveExcludedSourceTypes() {
		kept[st] = struct{}{}
	}
	for _, st := range before.EffectiveExcludedSourceTypes() {
		if _, ok := kept[st]; !ok {
			return true
		}
	}
	return false
}

// cycleLoosened reports turning the coverage requirement for closing a cycle off.
func cycleLoosened(before, after tenantdom.CycleSettings) bool {
	return before.EnforceCoverageSLO && !after.EnforceCoverageSLO
}

// easmLoosened reports a change that reduces what the attack-surface
// monitoring sees or how often (a monitor or enrichment turned off, a longer
// interval, a longer "reappeared" window, the weekly digest off) or that
// keeps more data (web screenshots on).
func easmLoosened(before, after tenantdom.EASMSettings) bool {
	switch {
	case !before.CTDisabled && after.CTDisabled,
		!before.DNSChecksDisabled && after.DNSChecksDisabled,
		!before.EnrichmentDisabled && after.EnrichmentDisabled,
		!before.LookalikeCTDisabled && after.LookalikeCTDisabled,
		!before.NetworkLookupsDisabled && after.NetworkLookupsDisabled,
		!before.WeeklyDigestDisabled && after.WeeklyDigestDisabled,
		!before.WebScreenshotsEnabled && after.WebScreenshotsEnabled:
		return true
	}
	return easmIntervalLonger(before.CTIntervalHours, after.CTIntervalHours) ||
		easmIntervalLonger(before.DNSIntervalHours, after.DNSIntervalHours) ||
		after.ReappearAfter() > before.ReappearAfter()
}

// easmDefaultIntervalHours is the shipped platform default (24 hours); an
// operator can change it per install, so a stored 0 is compared as this value.
const easmDefaultIntervalHours = 24

// easmIntervalLonger compares two stored intervals, 0 being the platform
// default (the shortest allowed is below it, so a default is not "longest").
func easmIntervalLonger(before, after int) bool {
	if before == after {
		return false
	}
	eff := func(v int) int {
		if v == 0 {
			return easmDefaultIntervalHours
		}
		return v
	}
	return eff(after) > eff(before)
}
