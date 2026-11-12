package scanrun

import (
	"context"
	"testing"

	"github.com/openctemio/openctem/server/pkg/domain/scanrun"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/logger"
)

// splitRunRepo keeps runs in memory and answers the split store as the
// repository does: tenant-scoped reads, first terminal transition wins.
type splitRunRepo struct {
	scanrun.RunRepository
	runs map[shared.ID]*scanrun.Run
}

func (r *splitRunRepo) GetByTenantAndID(_ context.Context, tenant, id shared.ID) (*scanrun.Run, error) {
	run, ok := r.runs[id]
	if !ok || run.TenantID != tenant {
		return nil, shared.ErrNotFound
	}
	cp := *run
	return &cp, nil
}

func (r *splitRunRepo) UpdateStatus(_ context.Context, tenant, id shared.ID, status scanrun.RunStatus, _ string) error {
	run, ok := r.runs[id]
	if !ok || run.TenantID != tenant {
		return shared.ErrNotFound
	}
	if run.Status.IsTerminal() {
		return scanrun.ErrRunAlreadyFinished
	}
	run.Status = status
	return nil
}

func (r *splitRunRepo) ListChildRuns(_ context.Context, tenant, parent shared.ID) ([]*scanrun.Run, error) {
	var out []*scanrun.Run
	for _, run := range r.runs {
		if run.TenantID == tenant && run.ParentRunID != nil && *run.ParentRunID == parent {
			cp := *run
			out = append(out, &cp)
		}
	}
	return out, nil
}

func (r *splitRunRepo) SettleSplitParent(ctx context.Context, tenant, parent shared.ID) (scanrun.RunStatus, bool, error) {
	p, ok := r.runs[parent]
	if !ok || p.TenantID != tenant || p.Status.IsTerminal() {
		return "", false, nil
	}
	kids, _ := r.ListChildRuns(ctx, tenant, parent)
	var sts []scanrun.RunStatus
	for _, k := range kids {
		sts = append(sts, k.Status)
	}
	st, done := scanrun.SplitOutcome(sts)
	if !done {
		return "", false, nil
	}
	p.Status = st
	return st, true, nil
}

func (r *splitRunRepo) SettleSplitParents(context.Context) (int64, error) { return 0, nil }

func newSplitFixture(t *testing.T) (*Service, *splitRunRepo, *scanrun.Run, []*scanrun.Run, *[]shared.ID) {
	t.Helper()
	tenant := shared.NewID()
	repo := &splitRunRepo{runs: map[shared.ID]*scanrun.Run{}}
	parent := &scanrun.Run{ID: shared.NewID(), TenantID: tenant, Status: scanrun.RunStatusRunning,
		Context: map[string]any{scanrun.RunContextKeyZoneSplit: map[string]any{"groups": []any{}}}}
	repo.runs[parent.ID] = parent
	var kids []*scanrun.Run
	for range 2 {
		k := &scanrun.Run{ID: shared.NewID(), TenantID: tenant, Status: scanrun.RunStatusRunning, ParentRunID: &parent.ID}
		repo.runs[k.ID] = k
		kids = append(kids, k)
	}
	var completed []shared.ID
	s := &Service{runRepo: repo, logger: logger.NewNop()}
	s.runCompleted = func(_ context.Context, run *scanrun.Run) { completed = append(completed, run.ID) }
	return s, repo, parent, kids, &completed
}

// The parent settles when its last zone run finishes, and only the parent is
// handed to the run-settled callback (one scan_completed per scan run).
func TestZoneSplit_ParentSettlesWhenLastChildFinishes(t *testing.T) {
	s, repo, parent, kids, completed := newSplitFixture(t)
	ctx := context.Background()

	s.finishRun(ctx, kids[0], scanrun.RunStatusCompleted, "", 2)
	if repo.runs[parent.ID].Status != scanrun.RunStatusRunning {
		t.Fatal("parent settled while a zone run is still running")
	}
	s.finishRun(ctx, kids[1], scanrun.RunStatusFailed, "boom", 0)
	if got := repo.runs[parent.ID].Status; got != scanrun.RunStatusPartial {
		t.Fatalf("parent = %s, want partial", got)
	}
	if len(*completed) != 1 || (*completed)[0] != parent.ID {
		t.Errorf("run-settled callback got %v, want the parent only", *completed)
	}
}

// Canceling the parent cancels its open zone runs; the parent ends canceled.
func TestZoneSplit_CancelCascades(t *testing.T) {
	s, repo, parent, kids, _ := newSplitFixture(t)
	ctx := context.Background()
	repo.runs[kids[0].ID].Status = scanrun.RunStatusCompleted

	if err := s.CancelRun(ctx, parent.TenantID.String(), parent.ID.String()); err != nil {
		t.Fatal(err)
	}
	if got := repo.runs[parent.ID].Status; got != scanrun.RunStatusCanceled {
		t.Errorf("parent = %s, want canceled", got)
	}
	if got := repo.runs[kids[0].ID].Status; got != scanrun.RunStatusCompleted {
		t.Errorf("finished zone run changed to %s", got)
	}
	if got := repo.runs[kids[1].ID].Status; got != scanrun.RunStatusCanceled {
		t.Errorf("open zone run = %s, want canceled", got)
	}

	// Another tenant cannot cancel the parent, nor reach its zone runs.
	s2, repo2, parent2, kids2, _ := newSplitFixture(t)
	if err := s2.CancelRun(ctx, shared.NewID().String(), parent2.ID.String()); err == nil {
		t.Fatal("another tenant canceled a split run")
	}
	if repo2.runs[kids2[0].ID].Status != scanrun.RunStatusRunning {
		t.Error("another tenant's cancel reached a zone run")
	}
}
