package scan

// Scope snapshot per scan run (RFC-065 §9): when a run is created, the scope
// that authorized its targets is hashed and stored with it. The evidence is
// best effort: a failed snapshot is logged and noted on the run, it never
// stops the run (the dispatch gate decides what is scanned).

import (
	"context"

	"github.com/openctemio/openctem/api/pkg/domain/scanrun"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// ScopeSnapshotRecorder stores the scope snapshot of a run
// (*scope.SnapshotRecorder).
type ScopeSnapshotRecorder interface {
	RecordRunSnapshot(ctx context.Context, tenantID, runID shared.ID, targets []string) (string, error)
}

// WithScopeSnapshots records a scope snapshot for every scan run.
func WithScopeSnapshots(r ScopeSnapshotRecorder) ServiceOption {
	return func(s *Service) { s.scopeSnapshots = r }
}

// runContextScopeSnapshot names the run's snapshot hash in its context.
const runContextScopeSnapshot = "scope_snapshot_sha256"

// recordScopeSnapshot stores the snapshot of a new run and notes its hash
// on the run context (persisted with the run's next update).
func (s *Service) recordScopeSnapshot(ctx context.Context, run *scanrun.Run, targets []string) {
	if s.scopeSnapshots == nil || run == nil {
		return
	}
	sum, err := s.scopeSnapshots.RecordRunSnapshot(ctx, run.TenantID, run.ID, targets)
	if err != nil {
		s.logger.Warn("scope snapshot not recorded", "run_id", run.ID.String(), "error", err)
		if run.Context != nil {
			prev, _ := run.Context["dispatch_warnings"].([]string)
			run.Context["dispatch_warnings"] = append(prev, "the scope snapshot of this run could not be recorded")
		}
		return
	}
	if run.Context != nil {
		run.Context[runContextScopeSnapshot] = sum
	}
}
