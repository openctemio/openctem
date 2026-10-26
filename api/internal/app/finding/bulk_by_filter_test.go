package finding

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/operation"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/api/pkg/filterspec"
)

// memOperations is an in-memory operation.Store; finished is closed when an
// operation ends.
type memOperations struct {
	mu       sync.Mutex
	ops      map[shared.ID]*operation.Operation
	finished chan struct{}
}

func newMemOperations() *memOperations {
	return &memOperations{ops: map[shared.ID]*operation.Operation{}, finished: make(chan struct{})}
}

func (m *memOperations) Create(_ context.Context, op *operation.Operation, _ operation.Budget) (*operation.Operation, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := *op
	cp.ID, cp.Status = shared.NewID(), operation.StatusRunning
	m.ops[cp.ID] = &cp
	out := cp
	return &out, false, nil
}

func (m *memOperations) ByKey(context.Context, shared.ID, shared.ID, string) (*operation.Operation, error) {
	return nil, operation.ErrNotFound
}

func (m *memOperations) Get(_ context.Context, tenantID, createdBy, id shared.ID) (*operation.Operation, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	op, ok := m.ops[id]
	if !ok || op.TenantID != tenantID || op.CreatedBy != createdBy {
		return nil, operation.ErrNotFound
	}
	out := *op
	return &out, nil
}

func (m *memOperations) Advance(_ context.Context, _, id shared.ID, p operation.Progress) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	op := m.ops[id]
	op.Processed, op.Succeeded, op.Skipped, op.Failed = p.Processed, p.Succeeded, p.Skipped, p.Failed
	return nil
}

func (m *memOperations) Finish(_ context.Context, _, id shared.ID, status operation.Status, p operation.Progress, msg string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	op := m.ops[id]
	op.Status, op.Error = status, msg
	op.Processed, op.Succeeded, op.Skipped, op.Failed = p.Processed, p.Succeeded, p.Skipped, p.Failed
	close(m.finished)
	return nil
}

// selectingRepo answers the first id selection with all, and every later
// one (the per-chunk re-check) with recheck. panicOnRead makes the bulk
// service's read panic.
type selectingRepo struct {
	racingRepo
	all, recheck []shared.ID
	calls        int
	panicOnRead  bool
}

func (r *selectingRepo) IDsWhere(_ context.Context, _ *filterspec.Where, _ int) ([]shared.ID, error) {
	r.calls++
	if r.calls == 1 {
		return r.all, nil
	}
	return r.recheck, nil
}

func (r *selectingRepo) GetByIDs(ctx context.Context, tenantID shared.ID, ids []shared.ID) ([]*vulnerability.Finding, error) {
	if r.panicOnRead {
		panic("boom")
	}
	return r.racingRepo.GetByIDs(ctx, tenantID, ids)
}

func bulkByFilterInput(tenantID shared.ID, status, resolution string, expected int) BulkByFilterInput {
	user := shared.NewID().String()
	return BulkByFilterInput{
		Caller: FilterCaller{TenantID: tenantID.String(), UserID: user, IsAdmin: true, Has: func(string) bool { return true }},
		Verb:   BulkVerbStatus, Spec: &filterspec.Spec{}, ExpectedCount: expected,
		Status: BulkUpdateStatusInput{Status: status, Resolution: resolution, ActorID: user, HasStatusPermission: true},
	}
}

// False positive, acceptance and duplicate are refused however the status is
// spelled: the check parses the status like the bulk service and the step-up
// gate do (case and surrounding whitespace), never a raw string compare.
func TestBulkByFilter_DispositionsRefusedInEverySpelling(t *testing.T) {
	tenantID := shared.NewID()
	repo := &selectingRepo{}
	svc := newBulkTestService(repo)
	svc.SetOperationStore(newMemOperations())
	for _, st := range []string{"false_positive", " False_Positive ", "FALSE_POSITIVE", "accepted", "Accepted\t", "\nACCEPTED",
		"duplicate", " DUPLICATE", "Duplicate\n"} {
		_, err := svc.BulkByFilter(context.Background(), bulkByFilterInput(tenantID, st, "noise", 1))
		if !errors.Is(err, ErrBulkByFilterNotAllowed) {
			t.Errorf("status %q: err = %v, want ErrBulkByFilterNotAllowed", st, err)
		}
	}
	// A closing status in any spelling needs a note.
	for _, st := range []string{"resolved", " RESOLVED ", "Resolved\t"} {
		_, err := svc.BulkByFilter(context.Background(), bulkByFilterInput(tenantID, st, "  ", 1))
		if !errors.Is(err, ErrBulkByFilterNote) {
			t.Errorf("status %q without a note: err = %v, want ErrBulkByFilterNote", st, err)
		}
	}
	if repo.calls != 0 {
		t.Fatalf("a refused change read findings (%d selections)", repo.calls)
	}
}

// A finding that left the filter or the caller's scope after the count is
// skipped by the chunk's re-check and never written.
func TestBulkByFilter_ChunkRecheckSkipsFindingsThatLeft(t *testing.T) {
	tenantID := shared.NewID()
	stay := mkFinding(t, tenantID, vulnerability.FindingSourceDAST)
	left := mkFinding(t, tenantID, vulnerability.FindingSourceDAST)
	repo := &selectingRepo{
		racingRepo: racingRepo{
			bulkStubRepo: bulkStubRepo{byID: map[string]*vulnerability.Finding{stay.ID().String(): stay, left.ID().String(): left}},
			stored: map[shared.ID]vulnerability.FindingStatus{
				stay.ID(): vulnerability.FindingStatusNew, left.ID(): vulnerability.FindingStatusNew,
			},
		},
		all:     []shared.ID{stay.ID(), left.ID()},
		recheck: []shared.ID{stay.ID()},
	}
	svc := newBulkTestService(repo)
	svc.SetOperationStore(newMemOperations())
	res, err := svc.BulkByFilter(context.Background(), bulkByFilterInput(tenantID, "confirmed", "", 2))
	if err != nil {
		t.Fatal(err)
	}
	op := res.Operation
	if op.Status != operation.StatusSucceeded || op.Processed != 2 || op.Succeeded != 1 || op.Skipped != 1 {
		t.Fatalf("operation = %+v, want succeeded, processed 2, succeeded 1, skipped 1", op)
	}
	if repo.stored[left.ID()] != vulnerability.FindingStatusNew {
		t.Fatalf("the finding that left the filter was written: %s", repo.stored[left.ID()])
	}
	if repo.stored[stay.ID()] != vulnerability.FindingStatusConfirmed {
		t.Fatalf("the finding still selected was not written: %s", repo.stored[stay.ID()])
	}
}

// A panic while applying the change ends the operation as failed (no panic
// text in it) instead of stopping the process and leaving it running: in the
// request and in the background.
func TestBulkByFilter_PanicEndsOperationAsFailed(t *testing.T) {
	for _, n := range []int{1, BulkByFilterInlineMax + 1} {
		tenantID := shared.NewID()
		ids := make([]shared.ID, n)
		for i := range ids {
			ids[i] = shared.NewID()
		}
		repo := &selectingRepo{all: ids, recheck: ids, panicOnRead: true}
		store := newMemOperations()
		svc := newBulkTestService(repo)
		svc.SetOperationStore(store)
		in := bulkByFilterInput(tenantID, "confirmed", "", n)
		res, err := svc.BulkByFilter(context.Background(), in)
		if err != nil {
			t.Fatalf("n=%d: %v", n, err)
		}
		select {
		case <-store.finished:
		case <-time.After(30 * time.Second):
			t.Fatalf("n=%d: the operation never finished", n)
		}
		userID, _ := shared.IDFromString(in.Caller.UserID)
		op, err := store.Get(context.Background(), tenantID, userID, res.Operation.ID)
		if err != nil {
			t.Fatal(err)
		}
		if op.Status != operation.StatusFailed || op.Error != errBulkByFilterInternal.Error() {
			t.Fatalf("n=%d: operation = %s %q, want failed with the generic error", n, op.Status, op.Error)
		}
	}
}
