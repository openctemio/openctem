package threatmodel

import (
	"sort"

	"github.com/openctemio/api/pkg/domain/shared"
	tmdom "github.com/openctemio/api/pkg/domain/threatmodel"
)

// Finding status buckets used by the derivation rules. These mirror
// vulnerability.FindingStatus values but are kept as local string constants so
// status.go stays a pure, dependency-light unit.
const (
	fsNew           = "new"
	fsConfirmed     = "confirmed"
	fsInProgress    = "in_progress"
	fsFixApplied    = "fix_applied"
	fsResolved      = "resolved"
	fsVerified      = "verified"
	fsAccepted      = "accepted"
	fsAcceptedRisk  = "accepted_risk"
	fsFalsePositive = "false_positive"
)

// findingMatches reports whether a finding is evidence for the technique on the
// asset. Primary match is an exact mitre_technique_id equality; the fallback
// matches any CWE the technique is known to manifest (cweHints) against the
// finding's CWE ids. cweHints is empty until the catalog carries technique→CWE
// mappings, so the fallback is dormant in production today (documented hook) but
// fully exercised by the unit tests.
func findingMatches(techniqueID string, cweHints []string, f tmdom.FindingFact) bool {
	if techniqueID != "" && f.TechniqueID == techniqueID {
		return true
	}
	if len(cweHints) == 0 || len(f.CWEIDs) == 0 {
		return false
	}
	for _, hint := range cweHints {
		for _, cwe := range f.CWEIDs {
			if cwe == hint {
				return true
			}
		}
	}
	return false
}

// live-risk precedence for choosing a status when several findings match one
// technique: a live-open finding outranks an accepted risk, which outranks an
// applied/verified fix. Higher wins.
func statusRank(s tmdom.ThreatStatus) int {
	switch s {
	case tmdom.StatusOpen:
		return 4
	case tmdom.StatusAccepted:
		return 3
	case tmdom.StatusMitigated:
		return 2
	case tmdom.StatusCovered:
		return 1
	default:
		return 0
	}
}

// findingStatusToThreat maps a finding workflow status to the threat status it
// contributes, or ("", false) when the finding is not status-relevant (draft,
// duplicate, false_positive, …).
func findingStatusToThreat(s string) (tmdom.ThreatStatus, bool) {
	switch s {
	case fsNew, fsConfirmed, fsInProgress:
		return tmdom.StatusOpen, true
	case fsAccepted, fsAcceptedRisk:
		return tmdom.StatusAccepted, true
	case fsFixApplied, fsResolved, fsVerified:
		return tmdom.StatusMitigated, true
	default:
		// false_positive, duplicate, draft, in_review, etc. are not evidence.
		return "", false
	}
}

// deriveStatus computes the live status of an enumerated threat: the technique
// techniqueID applying on asset assetID, given the findings on that asset and
// whether a compensating control (protected_by / monitors edge) covers it.
//
// Rules (in precedence order):
//   - open       — a matching finding is new / confirmed / in_progress.
//   - accepted   — a matching finding is an accepted risk acceptance / exception.
//   - mitigated  — a matching finding is fix_applied / resolved / verified, OR
//     no matching finding but the asset is covered by a compensating control.
//   - covered    — reserved for a validation/BAS record that blocked/detected the
//     technique; not derivable until that data is wired (RFC-011/012 hook).
//   - theoretical — applicable but no finding / validation exists.
//
// It is pure and deterministic: findings are considered in id order so the
// chosen evidence finding is stable across runs. The returned id points at the
// finding that determined the status (nil for a control-only mitigation).
func deriveStatus(
	techniqueID string,
	cweHints []string,
	assetID string,
	findings []tmdom.FindingFact,
	hasCompensatingControl bool,
) (tmdom.ThreatStatus, string, *shared.ID) {
	// Stable ordering so ties pick a deterministic evidence finding.
	matched := make([]tmdom.FindingFact, 0, len(findings))
	for _, f := range findings {
		if f.AssetID.String() != assetID {
			continue
		}
		if !findingMatches(techniqueID, cweHints, f) {
			continue
		}
		matched = append(matched, f)
	}
	sort.Slice(matched, func(i, j int) bool { return matched[i].ID.String() < matched[j].ID.String() })

	var (
		best       tmdom.ThreatStatus
		bestRank   int
		bestEvid   *shared.ID
		bestReason string
	)
	for i := range matched {
		st, ok := findingStatusToThreat(matched[i].Status)
		if !ok {
			continue
		}
		if statusRank(st) > bestRank {
			bestRank = statusRank(st)
			best = st
			id := matched[i].ID
			bestEvid = &id
			bestReason = reasonForFinding(st, matched[i])
		}
	}
	if best != "" {
		return best, bestReason, bestEvid
	}

	if hasCompensatingControl {
		return tmdom.StatusMitigated, "covered by a compensating control (protected_by/monitors edge)", nil
	}

	// Applicable technique with no finding and no control: a theoretical exposure
	// the attacker profile could attempt but which nothing observes yet.
	return tmdom.StatusTheoretical, "technique is applicable but no finding or validation evidence exists", nil
}

func reasonForFinding(st tmdom.ThreatStatus, f tmdom.FindingFact) string {
	switch st {
	case tmdom.StatusOpen:
		return "open finding on the hop asset matches the technique (status " + f.Status + ")"
	case tmdom.StatusAccepted:
		return "risk-accepted finding matches the technique (status " + f.Status + ")"
	case tmdom.StatusMitigated:
		return "finding matching the technique is fixed (status " + f.Status + ")"
	default:
		return ""
	}
}
