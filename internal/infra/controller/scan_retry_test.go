package controller

import (
	"context"
	"errors"
	"testing"

	"github.com/openctemio/api/pkg/domain/pipeline"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
)

// fakeRetryRepo implements retryRunRepository. It hands out one candidate the
// first time ListPendingRetries is called, then stops — modeling the real
// query, which only returns a run while retry_dispatched_at IS NULL. Calling
// ResetRetryClaim re-arms the candidate (clears the claim), which is exactly
// the behavior the fix depends on.
type fakeRetryRepo struct {
	cand      pipeline.RetryCandidate
	claimed   bool // true once listed and not yet reset (retry_dispatched_at set)
	resetCall int  // number of ResetRetryClaim calls
	resetID   shared.ID
}

func (r *fakeRetryRepo) ListPendingRetries(_ context.Context, _ int) ([]pipeline.RetryCandidate, error) {
	if r.claimed {
		// Already claimed and not reset: the SQL filter (retry_dispatched_at IS
		// NULL) excludes it, so nothing eligible.
		return nil, nil
	}
	r.claimed = true
	return []pipeline.RetryCandidate{r.cand}, nil
}

func (r *fakeRetryRepo) ResetRetryClaim(_ context.Context, runID shared.ID) error {
	r.resetCall++
	r.resetID = runID
	r.claimed = false // claim released → eligible again next tick
	return nil
}

// dispatcherFunc adapts a func to RetryDispatcher.
type dispatcherFunc func(ctx context.Context, tenantID, scanID shared.ID, retryAttempt int) error

func (f dispatcherFunc) RetryScanRun(ctx context.Context, tenantID, scanID shared.ID, retryAttempt int) error {
	return f(ctx, tenantID, scanID, retryAttempt)
}

func newCandidate(t *testing.T) pipeline.RetryCandidate {
	t.Helper()
	return pipeline.RetryCandidate{
		RunID:               shared.NewID(),
		ScanID:              shared.NewID(),
		TenantID:            shared.NewID(),
		RetryAttempt:        0,
		MaxRetries:          3,
		RetryBackoffSeconds: 60,
	}
}

// A transient dispatch failure must release the claim so the run is eligible
// again on the next reconcile tick. This is the regression guard for the
// permanent-stall bug: before the fix the claim stayed set forever and the scan
// never auto-retried.
func TestScanRetry_DispatchFailure_ResetsClaim(t *testing.T) {
	repo := &fakeRetryRepo{cand: newCandidate(t)}
	failing := dispatcherFunc(func(context.Context, shared.ID, shared.ID, int) error {
		return errors.New("transient: no agent available")
	})
	c := NewScanRetryController(repo, failing, &ScanRetryControllerConfig{Logger: logger.NewNop()})

	// Tick 1: candidate is claimed, dispatch fails, claim is reset.
	processed, err := c.Reconcile(context.Background())
	if err != nil {
		t.Fatalf("reconcile returned error: %v", err)
	}
	if processed != 0 {
		t.Fatalf("processed = %d, want 0 (dispatch failed)", processed)
	}
	if repo.resetCall != 1 {
		t.Fatalf("ResetRetryClaim calls = %d, want 1", repo.resetCall)
	}
	if repo.resetID != repo.cand.RunID {
		t.Fatalf("ResetRetryClaim runID = %s, want %s", repo.resetID, repo.cand.RunID)
	}

	// Tick 2: because the claim was reset, the run is eligible again — it must
	// re-appear as a candidate. Without the fix it would be gone forever.
	cands, err := repo.ListPendingRetries(context.Background(), 100)
	if err != nil {
		t.Fatalf("list after reset: %v", err)
	}
	if len(cands) != 1 {
		t.Fatalf("candidates after reset = %d, want 1 (run must be eligible again)", len(cands))
	}
}

// The happy path must NOT reset the claim: a successful dispatch creates a new
// run, so the old run's claim stays set (invariant preserved, no re-dispatch).
func TestScanRetry_DispatchSuccess_KeepsClaim(t *testing.T) {
	cand := newCandidate(t)
	repo := &fakeRetryRepo{cand: cand}
	var gotAttempt int
	ok := dispatcherFunc(func(_ context.Context, _, _ shared.ID, attempt int) error {
		gotAttempt = attempt
		return nil
	})
	c := NewScanRetryController(repo, ok, &ScanRetryControllerConfig{Logger: logger.NewNop()})

	processed, err := c.Reconcile(context.Background())
	if err != nil {
		t.Fatalf("reconcile returned error: %v", err)
	}
	if processed != 1 {
		t.Fatalf("processed = %d, want 1", processed)
	}
	if gotAttempt != cand.RetryAttempt+1 {
		t.Fatalf("dispatched attempt = %d, want %d", gotAttempt, cand.RetryAttempt+1)
	}
	if repo.resetCall != 0 {
		t.Fatalf("ResetRetryClaim calls = %d, want 0 on success", repo.resetCall)
	}
}
