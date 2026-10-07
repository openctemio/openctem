package controller

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/scanrun"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// fakeRetryRepo implements retryRunRepository. It hands out one candidate the
// first time ListPendingRetries is called, then stops — modeling the real
// query, which only returns a run while retry_dispatched_at IS NULL. Calling
// ReleaseFailedRetryDispatch re-arms the candidate (clears the claim) and
// spends the attempt.
type fakeRetryRepo struct {
	cand      scanrun.RetryCandidate
	claimed   bool // true once listed and not yet reset (retry_dispatched_at set)
	resetCall int  // number of ReleaseFailedRetryDispatch calls
	resetID   shared.ID
}

func (r *fakeRetryRepo) ListPendingRetries(_ context.Context, _ int) ([]scanrun.RetryCandidate, error) {
	if r.claimed {
		// Already claimed and not reset: the SQL filter (retry_dispatched_at IS
		// NULL) excludes it, so nothing eligible.
		return nil, nil
	}
	r.claimed = true
	return []scanrun.RetryCandidate{r.cand}, nil
}

func (r *fakeRetryRepo) ReleaseFailedRetryDispatch(_ context.Context, runID shared.ID) error {
	r.resetCall++
	r.resetID = runID
	r.claimed = false // claim released → eligible again next tick
	r.cand.RetryAttempt++
	return nil
}

// dispatcherFunc adapts a func to RetryDispatcher.
type dispatcherFunc func(ctx context.Context, tenantID, scanID shared.ID, retryAttempt int) error

func (f dispatcherFunc) RetryScanRun(ctx context.Context, tenantID, scanID shared.ID, retryAttempt int) error {
	return f(ctx, tenantID, scanID, retryAttempt)
}

func newCandidate(t *testing.T) scanrun.RetryCandidate {
	t.Helper()
	return scanrun.RetryCandidate{
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
		return errors.New("transient: no sensor available")
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
		t.Fatalf("ReleaseFailedRetryDispatch calls = %d, want 1", repo.resetCall)
	}
	if repo.resetID != repo.cand.RunID {
		t.Fatalf("ReleaseFailedRetryDispatch runID = %s, want %s", repo.resetID, repo.cand.RunID)
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
		t.Fatalf("ReleaseFailedRetryDispatch calls = %d, want 0 on success", repo.resetCall)
	}
}

// A dispatch that fails for a reason another attempt cannot fix (D7) is not
// released: the run is not retried again.
func TestScanRetry_PermanentDispatchFailure_GivesUp(t *testing.T) {
	repo := &fakeRetryRepo{cand: newCandidate(t)}
	refused := dispatcherFunc(func(context.Context, shared.ID, shared.ID, int) error {
		return fmt.Errorf("failed to trigger retry: %w",
			shared.NewDomainError("NO_TARGETS", "scan resolves to no targets", shared.ErrValidation))
	})
	c := NewScanRetryController(repo, refused, &ScanRetryControllerConfig{Logger: logger.NewNop()})
	if _, err := c.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if repo.resetCall != 0 {
		t.Fatalf("claim released %d time(s); a permanent refusal must not be retried", repo.resetCall)
	}
	if cands, _ := repo.ListPendingRetries(context.Background(), 100); len(cands) != 0 {
		t.Fatalf("run eligible again after a permanent refusal")
	}
}

// A transient dispatch failure spends the attempt: before, the claim was
// released with retry_attempt unchanged, so a dispatch that kept failing was
// retried every backoff interval forever.
func TestScanRetry_TransientDispatchFailure_SpendsTheAttempt(t *testing.T) {
	repo := &fakeRetryRepo{cand: newCandidate(t)}
	failing := dispatcherFunc(func(context.Context, shared.ID, shared.ID, int) error {
		return errors.New("database is restarting")
	})
	c := NewScanRetryController(repo, failing, &ScanRetryControllerConfig{Logger: logger.NewNop()})
	if _, err := c.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if repo.cand.RetryAttempt != 1 {
		t.Fatalf("retry_attempt = %d after a failed dispatch, want 1 (attempt spent)", repo.cand.RetryAttempt)
	}
}
