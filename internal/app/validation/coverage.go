package validation

import (
	"errors"
	"fmt"
)

// validation coverage SLO.
//
// Scope note to avoid confusion with the validation/ package:
//
//   - internal/app/validation/  answers "EXECUTE this technique via an
//     agent and capture Evidence". That package owns the orchestration
//     contract (TechniqueExecutor, ValidationJob, Dispatcher,
//     EvidenceStore).
//
//   - THIS file answers "OF THE FINDINGS WE ALREADY CLOSED this
//     period, what percentage had a validation evidence attached?" —
//     an SLO / measurement concern, not an orchestration concern.
//
// They are paired (no evidence → no coverage), but the package split
// is intentional: coverage lives in internal/app/ because it
// cross-cuts the cycle-close handler, while validation/ is the
// Stage-4 domain.
//
// Every P0/P1 finding that reaches a terminal state (resolved |
// verified | accepted) MUST have at least one Evidence record
// attached. P2 has a softer target (80%). Breach of the SLO blocks
// cycle close — you cannot tick "cycle complete" if your flagship
// critical findings have no validation evidence.
//
// This file is the pure computation; the actual query
// (Evidence count per finding) lives in the repo/store layer.

// ValidationCoverage aggregates per-priority coverage for a tenant
// or cycle window.
type ValidationCoverage struct {
	P0Total     int
	P0WithEvidence int
	P1Total     int
	P1WithEvidence int
	P2Total     int
	P2WithEvidence int
	P3Total     int
	P3WithEvidence int
}

// Pct returns the coverage ratio for a priority class in [0, 100].
// Zero-total returns 100 (nothing to cover = trivially met).
func (c ValidationCoverage) Pct(class string) float64 {
	var tot, wev int
	switch class {
	case "P0":
		tot, wev = c.P0Total, c.P0WithEvidence
	case "P1":
		tot, wev = c.P1Total, c.P1WithEvidence
	case "P2":
		tot, wev = c.P2Total, c.P2WithEvidence
	case "P3":
		tot, wev = c.P3Total, c.P3WithEvidence
	default:
		return 0
	}
	if tot == 0 {
		return 100
	}
	return float64(wev) / float64(tot) * 100
}

// CoverageThresholds define the SLO targets per priority class.
// Exported so tenants can override later (per-tenant-config).
type CoverageThresholds struct {
	P0 float64
	P1 float64
	P2 float64
	P3 float64
}

// DefaultThresholds matches the commitment: full coverage
// on P0/P1, 80% on P2, optional on P3.
var DefaultThresholds = CoverageThresholds{
	P0: 100,
	P1: 100,
	P2: 80,
	P3: 0,
}

// ErrCoverageBelowSLO is returned by Enforce when any class is under
// its threshold. Message enumerates the offending classes so the
// operator sees exactly which P0s are missing evidence.
var ErrCoverageBelowSLO = errors.New("validation coverage below SLO")

// Enforce returns nil when every class meets its threshold, else
// ErrCoverageBelowSLO wrapped with a human-readable breakdown. Used
// by the cycle-close handler: no close if coverage is under.
func Enforce(c ValidationCoverage, t CoverageThresholds) error {
	type miss struct {
		class string
		got   float64
		want  float64
	}
	var misses []miss
	for _, class := range []string{"P0", "P1", "P2", "P3"} {
		var want float64
		switch class {
		case "P0":
			want = t.P0
		case "P1":
			want = t.P1
		case "P2":
			want = t.P2
		case "P3":
			want = t.P3
		}
		if want == 0 {
			continue // class not enforced
		}
		got := c.Pct(class)
		if got < want {
			misses = append(misses, miss{class: class, got: got, want: want})
		}
	}
	if len(misses) == 0 {
		return nil
	}
	msg := ""
	for i, m := range misses {
		if i > 0 {
			msg += "; "
		}
		msg += fmt.Sprintf("%s %.1f%% (need %.0f%%)", m.class, m.got, m.want)
	}
	return fmt.Errorf("%w: %s", ErrCoverageBelowSLO, msg)
}
