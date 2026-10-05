// Package easmalert decides how a new or reopened EASM exposure is announced
// through the notification outbox (research/22 decision E4; design:
// docs/rfcs/RFC-036-easm.md, architecture: docs/architecture/easm.md).
//
// The rule:
//   - an exposure on an asset a person rejected ("Not ours") or on a deleted
//     asset is never announced;
//   - medium or higher on an approved asset (confirmed, dependency, or an
//     asset the tenant made itself, which has no attribution record) goes
//     out immediately, as new_exposure, unless the tenant's hourly budget of
//     immediate alerts is spent;
//   - everything else (low and info, unverified assets, monitor-only assets,
//     exposures not linked to an asset, and immediate alerts over the
//     budget) goes into the tenant's daily digest, labeled.
package easmalert

import "time"

// Decision is what happens to one exposure.
type Decision string

const (
	// Skip: never announced.
	Skip Decision = "skip"
	// Immediate: one new_exposure notification now.
	Immediate Decision = "immediate"
	// Digest: counted in the tenant's next daily digest.
	Digest Decision = "digest"
)

// Reason says why an exposure is announced at all.
type Reason string

const (
	// ReasonNew: the exposure row was inserted.
	ReasonNew Reason = "new"
	// ReasonReopened: an exposure the check had resolved itself was found
	// again.
	ReasonReopened Reason = "reopened"
)

// Attribution labels carried in the payload.
const (
	// LabelUnverified marks an exposure on an asset nobody has confirmed yet.
	LabelUnverified = "unverified"
	// LabelUnlinked marks an exposure not linked to any asset.
	LabelUnlinked = "unlinked"
)

// Defaults.
const (
	// DefaultHourlyImmediateBudget is how many immediate alerts one tenant
	// gets per rolling hour before the rest go to the digest.
	DefaultHourlyImmediateBudget = 30
	// DigestHourUTC is when the daily digest becomes due.
	DigestHourUTC = 8
	// MaxDigestItems bounds how many exposures one digest lists by name; the
	// count is always exact.
	MaxDigestItems = 25
)

// Exposure is what the policy needs to know about one exposure.
type Exposure struct {
	Severity string
	// HasAsset is false when the exposure is not linked to an asset.
	HasAsset bool
	// AssetDeleted is true when the linked asset is soft-deleted.
	AssetDeleted bool
	// Attribution is the asset's attribution state; "" when the asset has no
	// record (an asset the tenant created itself).
	Attribution string
}

// Classify decides one exposure, before the hourly budget is applied.
func Classify(e Exposure) Decision {
	if e.AssetDeleted || e.Attribution == "rejected" {
		return Skip
	}
	if !e.HasAsset {
		return Digest
	}
	if Approved(e.Attribution) && SeverityRank(e.Severity) >= SeverityRank("medium") {
		return Immediate
	}
	return Digest
}

// Approved reports whether an attribution state counts as the tenant's own
// for alerting: confirmed, dependency, or no record.
func Approved(state string) bool {
	switch state {
	case "", "confirmed", "dependency":
		return true
	}
	return false
}

// Label is the attribution label an alert carries: the state, or
// "unverified" for a state nobody confirmed, or "unlinked".
func Label(e Exposure) string {
	switch {
	case !e.HasAsset:
		return LabelUnlinked
	case e.Attribution == "":
		return "unrecorded"
	case e.Attribution == "needs_review" || e.Attribution == "candidate":
		return LabelUnverified
	}
	return e.Attribution
}

// MaxSeverity returns the higher of two severities.
func MaxSeverity(a, b string) string {
	if SeverityRank(b) > SeverityRank(a) {
		return b
	}
	return a
}

// SeverityRank orders severities: critical 5 ... info 1, anything else 0.
func SeverityRank(s string) int {
	switch s {
	case "critical":
		return 5
	case "high":
		return 4
	case "medium":
		return 3
	case "low":
		return 2
	case "info":
		return 1
	}
	return 0
}

// NextDigestAt returns when the digest that collects an exposure seen at
// now is due: the next DigestHourUTC strictly after now.
func NextDigestAt(now time.Time) time.Time {
	now = now.UTC()
	due := time.Date(now.Year(), now.Month(), now.Day(), DigestHourUTC, 0, 0, 0, time.UTC)
	if !due.After(now) {
		due = due.Add(24 * time.Hour)
	}
	return due
}
