package scanrun

import (
	"context"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// RunNotifier hears that a run changed (a step started, finished or was
// queued, the run settled or was canceled), so the live run map refreshes
// at once instead of on its next poll. It carries only the run: listeners
// re-read the run through the gated endpoints, so a notification can never
// show more than the reader may see.
type RunNotifier interface {
	RunChanged(tenantID, runID shared.ID)
}

// SetRunNotifier wires the live run updates after the service is built
// (the websocket hub is created later).
func (s *Service) SetRunNotifier(n RunNotifier) { s.runNotifier = n }

// notifyRun tells the notifier the run changed (no-op without one).
func (s *Service) notifyRun(tenantID, runID shared.ID) {
	if s.runNotifier == nil || tenantID.IsZero() || runID.IsZero() {
		return
	}
	s.runNotifier.RunChanged(tenantID, runID)
}

// notifyRunByID resolves the run's tenant (callers that only hold the run
// id, such as a sensor starting a step) before notifying.
func (s *Service) notifyRunByID(ctx context.Context, runID shared.ID) {
	if s.runNotifier == nil {
		return
	}
	if run, err := s.runRepo.GetByID(ctx, runID); err == nil && run != nil {
		s.notifyRun(run.TenantID, run.ID)
	}
}
