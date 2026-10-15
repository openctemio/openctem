package cirun

// The gate baseline of a repository
// (docs/rfcs/RFC-051-ci-runner-identity-and-gate.md, "Gate baseline").

import (
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Where a gate baseline came from.
const (
	BaselineSourceManual   = "manual"
	BaselineSourceFirstRun = "first_run"
)

// GateBaseline is the set of findings open on a repository's default branch
// when it was recorded. A default-branch run is judged against it: a finding
// in it is pre-existing, every other finding is new. Nothing a run reports
// changes it; only a person with the policy permission records or removes
// it.
type GateBaseline struct {
	TenantID          shared.ID
	RepositoryAssetID shared.ID
	Source            string
	Branch            string
	FindingsCount     int
	SetBy             *shared.ID
	SetAt             time.Time
}

// Covers reports whether a finding of the baseline still counts as
// pre-existing: it was not reopened after the baseline was recorded (a
// finding fixed and brought back is new again).
func (b GateBaseline) Covers(f RunFinding) bool {
	return f.LastReopenedAt == nil || !f.LastReopenedAt.After(b.SetAt)
}
