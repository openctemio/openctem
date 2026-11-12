package asset

// One monitoring state per asset (docs/architecture/exposure-taxonomy.md,
// "Monitoring state"): a label derived from what already exists (the
// attribution state and confidence, the scope exclusions and their kind, the
// scope status, the asset's own status and the tenant's unclassified-scans
// mode). Nothing is stored. The SQL form (postgres.assetMonitoringStateSQL)
// mirrors MonitoringStateOf and is what the list filter and the row label
// read; a DB test checks the two agree.

// MonitoringState is where an asset stands in the external attack surface
// lifecycle.
type MonitoringState string

// Monitoring states, in precedence order: the first that applies wins.
const (
	// MonitoringIrrelevant: someone else's (attribution rejected, or a
	// not_ours exclusion).
	MonitoringIrrelevant MonitoringState = "irrelevant"
	// MonitoringOutOfScope: the organization's, but excluded from scanning
	// (a do_not_scan or retired exclusion).
	MonitoringOutOfScope MonitoringState = "out_of_scope"
	// MonitoringInactive: the asset is inactive or archived.
	MonitoringInactive MonitoringState = "inactive"
	// MonitoringPendingDecision: attribution needs a person's review.
	MonitoringPendingDecision MonitoringState = "pending_decision"
	// MonitoringUnvalidated: a candidate, or discovered below the
	// auto-confirm confidence.
	MonitoringUnvalidated MonitoringState = "unvalidated"
	// MonitoringNotMonitored: kept for reference only (monitor_only), or no
	// scope entry covers it and unclassified assets are not scanned.
	MonitoringNotMonitored MonitoringState = "not_monitored"
	// MonitoringMonitored: everything else; the platform watches it.
	MonitoringMonitored MonitoringState = "monitored"
)

// MonitoringStates returns every state in precedence order.
func MonitoringStates() []MonitoringState {
	return []MonitoringState{
		MonitoringIrrelevant, MonitoringOutOfScope, MonitoringInactive, MonitoringPendingDecision,
		MonitoringUnvalidated, MonitoringNotMonitored, MonitoringMonitored,
	}
}

// ValidMonitoringState reports whether s is a monitoring state.
func ValidMonitoringState(s string) bool {
	for _, m := range MonitoringStates() {
		if string(m) == s {
			return true
		}
	}
	return false
}

// MonitoringConfirmThreshold is the attribution confidence from which a
// discovered asset counts as validated (the auto-confirm bar).
const MonitoringConfirmThreshold = 90

// MonitoringInputs are the facts the state is derived from.
type MonitoringInputs struct {
	// AttributionState is "" for an asset with no attribution record (a
	// legacy asset, treated as confirmed).
	AttributionState string
	Confidence       int
	// ExclusionKinds are the kinds of the in-effect exclusions that match the
	// asset (do_not_scan, not_ours, retired).
	ExclusionKinds []string
	// Status is the asset status (active, stale, inactive, archived).
	Status string
	// ScopeStatus is in_scope, not_covered, excluded or internal.
	ScopeStatus string
	// UnclassifiedScanned: the tenant scans assets no scope entry covers
	// (its unclassified-scans mode is not off).
	UnclassifiedScanned bool
}

// MonitoringStateOf derives the state from its inputs.
func MonitoringStateOf(in MonitoringInputs) MonitoringState {
	has := func(kind string) bool {
		for _, k := range in.ExclusionKinds {
			if k == kind {
				return true
			}
		}
		return false
	}
	switch {
	case in.AttributionState == "rejected" || has("not_ours"):
		return MonitoringIrrelevant
	case has("do_not_scan") || has("retired"):
		return MonitoringOutOfScope
	case in.Status == string(StatusInactive) || in.Status == string(StatusArchived):
		return MonitoringInactive
	case in.AttributionState == "needs_review":
		return MonitoringPendingDecision
	case in.AttributionState == "candidate" ||
		(in.AttributionState == "discovered" && in.Confidence < MonitoringConfirmThreshold):
		return MonitoringUnvalidated
	case in.AttributionState == "monitor_only":
		return MonitoringNotMonitored
	case in.ScopeStatus == "not_covered" && !in.UnclassifiedScanned:
		return MonitoringNotMonitored
	default:
		return MonitoringMonitored
	}
}
