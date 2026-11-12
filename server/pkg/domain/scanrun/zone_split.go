package scanrun

// A workflow scan whose targets fall in several scan zones runs as one child
// run per zone under a parent run. Architecture: docs/architecture/scan-zones.md
// ("Workflow runs over several zones").

import (
	"context"

	"github.com/openctemio/openctem/server/pkg/domain/shared"
)

// RunContextKeyZoneSplit is the run context key that describes a split: on
// the parent, the zone groups and their child runs; on a child, its parent,
// zone and position. Never sent to a sensor.
const RunContextKeyZoneSplit = "zone_split"

// ZoneSplitStore reads and settles the runs of a split. Every method is
// scoped to one tenant except SettleSplitParents, the reaper's sweep, which
// joins a parent only with children of its own tenant.
type ZoneSplitStore interface {
	// ListChildRuns returns the children of parentID in tenantID (none for
	// another tenant's parent).
	ListChildRuns(ctx context.Context, tenantID, parentID shared.ID) ([]*Run, error)
	// SettleSplitParent moves parentID to its outcome once every child
	// finished: completed when all completed, canceled when all were
	// canceled, failed when none produced results, partial otherwise. It
	// reports the status it set and whether this call set it.
	SettleSplitParent(ctx context.Context, tenantID, parentID shared.ID) (RunStatus, bool, error)
	// SettleSplitParents settles every open parent whose children all
	// finished (children the reapers closed). It returns how many it
	// settled.
	SettleSplitParents(ctx context.Context) (int64, error)
}

// SplitOutcome is the status of a parent from its children's statuses (ok
// false while a child is still open or there is none).
func SplitOutcome(children []RunStatus) (RunStatus, bool) {
	if len(children) == 0 {
		return "", false
	}
	var completed, results, canceled int
	for _, st := range children {
		if !st.IsTerminal() {
			return "", false
		}
		switch st {
		case RunStatusCompleted:
			completed++
			results++
		case RunStatusPartial:
			results++
		case RunStatusCanceled:
			canceled++
		}
	}
	switch {
	case completed == len(children):
		return RunStatusCompleted, true
	case canceled == len(children):
		return RunStatusCanceled, true
	case results == 0:
		return RunStatusFailed, true
	}
	return RunStatusPartial, true
}
