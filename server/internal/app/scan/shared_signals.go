package scan

// Anomaly signals of shared sensor use (docs/rfcs/RFC-100-shared-sensors.md
// §9): the trigger reports the targets of every job it queues for shared
// sensors and every target the platform deny list refuses. The observer
// (*scanpolicy.Service) keeps aggregate daily counts per organization and
// alerts the administrators; it never refuses anything and never blocks.

import (
	"context"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// SharedUseObserver receives the signals (*scanpolicy.Service).
type SharedUseObserver interface {
	ObserveSharedTargets(ctx context.Context, tenantID shared.ID, targets []string)
	ObserveDenyListHits(ctx context.Context, tenantID shared.ID, n int)
}

// SetSharedUseObserver wires the observer; without it no signal is counted.
func (s *Service) SetSharedUseObserver(o SharedUseObserver) { s.sharedUse = o }

func (s *Service) observeSharedTargets(ctx context.Context, tenantID shared.ID, targets []string) {
	if s.sharedUse != nil {
		s.sharedUse.ObserveSharedTargets(ctx, tenantID, targets)
	}
}

// observeDenyListHit counts one target the platform deny list refused.
func (s *Service) observeDenyListHit(ctx context.Context, tenantID shared.ID) {
	if s.sharedUse != nil {
		s.sharedUse.ObserveDenyListHits(ctx, tenantID, 1)
	}
}
