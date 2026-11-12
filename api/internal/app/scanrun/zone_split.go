package scanrun

// Runs of a workflow scan split over several scan zones: each zone child
// settles its parent when it finishes, and a canceled parent cancels its
// children. Architecture: docs/architecture/scan-zones.md ("Workflow runs
// over several zones").

import (
	"context"

	"github.com/openctemio/openctem/api/pkg/domain/scanrun"
)

// settleSplitParent settles the parent of the zone child run once every
// child finished, and then records the parent's outcome on its scan and
// hands it to the run-settled callback, as finishRun does for an unsplit
// run. The parent is read in the child's tenant only.
func (s *Service) settleSplitParent(ctx context.Context, child *scanrun.Run) {
	store, ok := s.runRepo.(scanrun.ZoneSplitStore)
	if !ok || child.ParentRunID == nil {
		return
	}
	status, settled, err := store.SettleSplitParent(ctx, child.TenantID, *child.ParentRunID)
	if err != nil {
		s.logger.Error("failed to settle a split run from its zone runs", "run_id", child.ParentRunID.String(), "error", err)
	}
	if !settled {
		return
	}
	parent, err := s.runRepo.GetByTenantAndID(ctx, child.TenantID, *child.ParentRunID)
	if err != nil {
		s.logger.Warn("failed to read a settled split run", "run_id", child.ParentRunID.String(), "error", err)
		return
	}
	s.logger.Info("split run settled from its zone runs", "run_id", parent.ID.String(), "status", string(status))
	s.notifyRun(parent.TenantID, parent.ID)
	if s.runCompleted != nil {
		s.runCompleted(ctx, parent)
	}
}

// cancelZoneChildren cancels the open zone runs of a canceled split run.
func (s *Service) cancelZoneChildren(ctx context.Context, parent *scanrun.Run) {
	store, ok := s.runRepo.(scanrun.ZoneSplitStore)
	if !ok || parent.ParentRunID != nil {
		return
	}
	children, err := store.ListChildRuns(ctx, parent.TenantID, parent.ID)
	if err != nil {
		s.logger.Warn("failed to list the zone runs of a canceled run", "run_id", parent.ID.String(), "error", err)
		return
	}
	for _, c := range children {
		if c.IsComplete() {
			continue
		}
		if err := s.CancelRun(ctx, parent.TenantID.String(), c.ID.String()); err != nil {
			s.logger.Warn("failed to cancel a zone run of a canceled run", "run_id", c.ID.String(), "error", err)
		}
	}
}

// ZoneRuns returns the zone runs of a split run, read in the run's own
// tenant (none for an unsplit run or a repository without splits).
func (s *Service) ZoneRuns(ctx context.Context, parent *scanrun.Run) ([]*scanrun.Run, error) {
	store, ok := s.runRepo.(scanrun.ZoneSplitStore)
	if !ok || parent == nil || parent.ParentRunID != nil {
		return nil, nil
	}
	if _, split := parent.Context[scanrun.RunContextKeyZoneSplit]; !split {
		return nil, nil
	}
	return store.ListChildRuns(ctx, parent.TenantID, parent.ID)
}
