package automation

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	automationdom "github.com/openctemio/openctem/api/pkg/domain/automation"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// queueRunRepo records which runs the executor started (GetWithNodeRuns) or
// failed, and returns an error on start so nothing else runs.
type queueRunRepo struct {
	automationdom.RunRepository
	mu      sync.Mutex
	runs    map[shared.ID]*automationdom.Run
	started []shared.ID
}

func (r *queueRunRepo) GetByID(_ context.Context, id shared.ID) (*automationdom.Run, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if run, ok := r.runs[id]; ok {
		return run, nil
	}
	return nil, shared.ErrNotFound
}

func (r *queueRunRepo) Update(_ context.Context, run *automationdom.Run) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.runs[run.ID] = run
	return nil
}

func (r *queueRunRepo) GetWithNodeRuns(_ context.Context, id shared.ID) (*automationdom.Run, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.started = append(r.started, id)
	return nil, errors.New("stop here")
}

func (r *queueRunRepo) status(id shared.ID) (automationdom.RunStatus, string, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	run := r.runs[id]
	started := false
	for _, s := range r.started {
		if s == id {
			started = true
		}
	}
	return run.Status, run.ErrorMessage, started
}

func newQueueRun(t *testing.T, repo *queueRunRepo, tenant shared.ID) shared.ID {
	t.Helper()
	run, err := automationdom.NewRun(shared.NewID(), tenant, automationdom.TriggerTypeManual, nil)
	if err != nil {
		t.Fatal(err)
	}
	repo.mu.Lock()
	repo.runs[run.ID] = run
	repo.mu.Unlock()
	return run.ID
}

// With the tenant's slots taken, a run waits instead of failing, and starts
// as soon as a slot frees; one that waits too long fails with the reason.
func TestExecuteAsync_WaitsForATenantSlot(t *testing.T) {
	repo := &queueRunRepo{runs: map[shared.ID]*automationdom.Run{}}
	e := NewWorkflowExecutor(nil, repo, nil, logger.NewNop())
	e.maxConcurrentPerTenant = 1
	e.maxQueueWait = 2 * time.Second
	tenant := shared.NewID()

	slot := e.tenantSlot(tenant.String())
	slot <- struct{}{} // another run of the tenant holds the only slot

	waiting := newQueueRun(t, repo, tenant)
	e.ExecuteAsyncWithTenant(waiting, tenant)
	time.Sleep(100 * time.Millisecond)
	if st, msg, started := repo.status(waiting); started || st != automationdom.RunStatusPending {
		t.Fatalf("run with no free slot: status %s (%s), started %v; want it waiting", st, msg, started)
	}
	<-slot // the other run ends
	deadline := time.Now().Add(time.Second)
	for {
		if _, _, started := repo.status(waiting); started {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the waiting run did not start once the slot was free")
		}
		time.Sleep(10 * time.Millisecond)
	}

	// Taken again, and a short wait: the run fails, saying why.
	e.maxQueueWait = 50 * time.Millisecond
	for len(slot) > 0 { // let the started run release its slot
		time.Sleep(5 * time.Millisecond)
	}
	slot <- struct{}{}
	late := newQueueRun(t, repo, tenant)
	e.ExecuteAsyncWithTenant(late, tenant)
	deadline = time.Now().Add(time.Second)
	for {
		st, msg, started := repo.status(late)
		if st == automationdom.RunStatusFailed {
			if started || !strings.Contains(msg, "not started: waited") {
				t.Fatalf("timed-out run: started %v, message %q", started, msg)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed-out run status %s, want failed", st)
		}
		time.Sleep(10 * time.Millisecond)
	}
	<-slot
}
