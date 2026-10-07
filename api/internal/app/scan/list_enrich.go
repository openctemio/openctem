package scan

import (
	"context"

	"github.com/openctemio/openctem/api/pkg/domain/pipeline"
	"github.com/openctemio/openctem/api/pkg/domain/scan"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// The scan list shows each scan's real latest run (state, progress, refusal)
// and what the scan runs (its workflow's name). Both are read in batches for
// a page of scans, scoped to the caller's tenant.

// LastRun is a scan's latest run with its task counts (nil before any task
// was dispatched).
type LastRun struct {
	Run   *pipeline.Run
	Tasks *pipeline.TaskSummary
}

// Progress is how far a live run is, 0-100: finished tasks of all tasks, or
// finished steps of all steps before tasks exist.
func (l LastRun) Progress() int {
	if l.Tasks != nil && l.Tasks.Total > 0 {
		done := l.Tasks.Completed + l.Tasks.Failed + l.Tasks.Canceled
		return min(100, done*100/l.Tasks.Total)
	}
	if l.Run == nil {
		return 0
	}
	return min(100, l.Run.GetProgress())
}

// runBatchReader reads runs by id for one tenant
// (postgres.PipelineRunRepository).
type runBatchReader interface {
	ListByTenantAndIDs(ctx context.Context, tenantID shared.ID, ids []shared.ID) ([]*pipeline.Run, error)
}

// templateNamer names templates a tenant may use
// (postgres.PipelineTemplateRepository).
type templateNamer interface {
	TemplateNames(ctx context.Context, tenantID shared.ID, ids []shared.ID) (map[shared.ID]string, error)
}

// LastRuns returns the latest run of each scan that has one, keyed by scan
// id. Best-effort: a read failure is logged and the list shows no run state
// rather than failing.
func (s *Service) LastRuns(ctx context.Context, tenantID shared.ID, scans []*scan.Scan) map[shared.ID]LastRun {
	reader, ok := s.runRepo.(runBatchReader)
	if !ok {
		return nil
	}
	ids := make([]shared.ID, 0, len(scans))
	byRun := make(map[shared.ID]shared.ID, len(scans))
	for _, sc := range scans {
		if sc.LastRunID != nil && sc.TenantID == tenantID {
			ids = append(ids, *sc.LastRunID)
			byRun[*sc.LastRunID] = sc.ID
		}
	}
	if len(ids) == 0 {
		return nil
	}
	runs, err := reader.ListByTenantAndIDs(ctx, tenantID, ids)
	if err != nil {
		s.logger.Warn("failed to read the scans' last runs", "error", err)
		return nil
	}
	var tasks map[shared.ID]pipeline.TaskSummary
	if tr, ok := s.commandRepo.(pipeline.TaskReader); ok {
		if tasks, err = tr.TaskSummaries(ctx, tenantID, ids); err != nil {
			s.logger.Warn("failed to read the scans' last run tasks", "error", err)
		}
	}
	out := make(map[shared.ID]LastRun, len(runs))
	for _, r := range runs {
		scanID, ok := byRun[r.ID]
		if !ok {
			continue
		}
		lr := LastRun{Run: r}
		if t, ok := tasks[r.ID]; ok {
			lr.Tasks = &t
		}
		out[scanID] = lr
	}
	return out
}

// PipelineNames returns the name of each workflow scan's template, keyed by
// template id. Best-effort like LastRuns.
func (s *Service) PipelineNames(ctx context.Context, tenantID shared.ID, scans []*scan.Scan) map[shared.ID]string {
	namer, ok := s.templateRepo.(templateNamer)
	if !ok {
		return nil
	}
	seen := map[shared.ID]bool{}
	var ids []shared.ID
	for _, sc := range scans {
		if sc.PipelineID != nil && !seen[*sc.PipelineID] {
			seen[*sc.PipelineID] = true
			ids = append(ids, *sc.PipelineID)
		}
	}
	if len(ids) == 0 {
		return nil
	}
	names, err := namer.TemplateNames(ctx, tenantID, ids)
	if err != nil {
		s.logger.Warn("failed to name the scans' workflows", "error", err)
		return nil
	}
	return names
}
