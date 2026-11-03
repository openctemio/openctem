package remediation

import (
	"context"
	"errors"
	"testing"
	"time"

	moduledom "github.com/openctemio/openctem/api/pkg/domain/module"
	remediationdom "github.com/openctemio/openctem/api/pkg/domain/remediation"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

type remediationOff map[string]bool

func (o remediationOff) TenantDisabledModules(_ context.Context, tenantID string) map[string]bool {
	if o[tenantID] {
		return map[string]bool{moduledom.ModuleRemediation: true}
	}
	return nil
}

// staleRepo serves the stale tasks of two tenants. The off tenant's rows come
// first and fill the whole batch until the tenant is on the skip list (the
// oldest rows belong to the tenant that is off).
type staleRepo struct {
	remediationdom.TaskRepository
	off, on   shared.ID
	recompute []shared.ID
}

func (r *staleRepo) StaleTasksForPlatform(_ context.Context, limit int, skip []shared.ID) ([]remediationdom.StaleTaskRef, error) {
	if len(skip) == 0 {
		out := make([]remediationdom.StaleTaskRef, limit)
		for i := range out {
			out[i] = remediationdom.StaleTaskRef{TenantID: r.off, TaskID: shared.NewID()}
		}
		return out, nil
	}
	return []remediationdom.StaleTaskRef{{TenantID: r.on, TaskID: shared.NewID()}}, nil
}

func (r *staleRepo) ReconcileTasks(_ context.Context, tenantID shared.ID, _ []shared.ID) (*remediationdom.RecomputeReport, error) {
	r.recompute = append(r.recompute, tenantID)
	return nil, nil
}

func TestTaskReconcile_SkipsTenantWithRemediationOff_AndDoesNotStarveOthers(t *testing.T) {
	repo := &staleRepo{off: shared.NewID(), on: shared.NewID()}
	s := NewTaskService(repo, logger.NewNop())
	s.SetModuleGuard(remediationOff{repo.off.String(): true})
	if _, err := s.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(repo.recompute) != 1 || repo.recompute[0] != repo.on {
		t.Fatalf("expected only the tenant with remediation on to be recomputed, got %v", repo.recompute)
	}
}

type dueQueries struct {
	QueryTaskRepository
	off, on shared.ID
	ran     []shared.ID
}

func (q *dueQueries) DueAutoQueryTasksForPlatform(_ context.Context, _ time.Time, limit int, skip []shared.ID) ([]remediationdom.DueQueryTask, error) {
	if len(skip) == 0 {
		out := make([]remediationdom.DueQueryTask, limit)
		for i := range out {
			out[i] = remediationdom.DueQueryTask{TenantID: q.off, TaskID: shared.NewID()}
		}
		return out, nil
	}
	return []remediationdom.DueQueryTask{{TenantID: q.on, TaskID: shared.NewID()}}, nil
}

func (q *dueQueries) GetTaskQuery(_ context.Context, tenantID, _ shared.ID) (*remediationdom.TaskQuery, error) {
	q.ran = append(q.ran, tenantID)
	return nil, errors.New("stop here: the test only needs to know who was picked")
}

type nopMatcher struct{ QueryMatcher }

func TestTaskAutoInclude_SkipsTenantWithRemediationOff_AndDoesNotStarveOthers(t *testing.T) {
	q := &dueQueries{off: shared.NewID(), on: shared.NewID()}
	s := NewTaskService(nil, logger.NewNop())
	s.queries, s.matcher = q, nopMatcher{}
	s.SetModuleGuard(remediationOff{q.off.String(): true})
	if _, err := s.AutoInclude(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(q.ran) != 1 || q.ran[0] != q.on {
		t.Fatalf("expected only the tenant with remediation on to run its query task, got %v", q.ran)
	}
}

type keysOnlyRepo struct {
	remediationdom.SuggestionRepository
	tenants []shared.ID
	ran     []shared.ID
}

func (r *keysOnlyRepo) TenantsWithKeysForPlatform(context.Context) ([]shared.ID, error) {
	return r.tenants, nil
}

func (r *keysOnlyRepo) Candidates(_ context.Context, tenantID shared.ID) ([]remediationdom.Candidate, error) {
	r.ran = append(r.ran, tenantID)
	return nil, errors.New("stop here: the test only needs to know who was picked")
}

func TestSuggestionsRunAll_SkipsTenantWithRemediationOff(t *testing.T) {
	on, off := shared.NewID(), shared.NewID()
	repo := &keysOnlyRepo{tenants: []shared.ID{off, on}}
	s := NewSuggestionService(repo, logger.NewNop())
	s.SetModuleGuard(remediationOff{off.String(): true})
	if _, err := s.RunAll(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(repo.ran) != 1 || repo.ran[0] != on {
		t.Fatalf("expected suggestions only for the tenant with remediation on, got %v", repo.ran)
	}
}
