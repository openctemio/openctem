package controller

import (
	"context"
	"errors"
	"testing"
	"time"
)

// F-13: unit tests for the priority-audit retention controller.
//
// The controller MUST:
//   - Ask the repo how many rows are eligible first (CountOlderThan).
//   - Skip the delete if zero.
//   - Skip the delete if DryRun is set.
//   - Actually delete and return the count otherwise.
//   - Propagate the repo's error cleanly.

type fakeRetentionStore struct {
	countResult int64
	countErr    error
	deleteCalls int
	deleteErr   error
	lastCutoff  time.Time
}

func (f *fakeRetentionStore) CountOlderThan(_ context.Context, before time.Time) (int64, error) {
	f.lastCutoff = before
	return f.countResult, f.countErr
}

func (f *fakeRetentionStore) DeleteOlderThan(_ context.Context, _ time.Time) (int64, error) {
	f.deleteCalls++
	if f.deleteErr != nil {
		return 0, f.deleteErr
	}
	return f.countResult, nil
}

func TestPriorityAuditRetention_NothingToDo(t *testing.T) {
	store := &fakeRetentionStore{countResult: 0}
	c := NewPriorityAuditRetentionController(store, nil)
	n, err := c.Reconcile(context.Background())
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if n != 0 {
		t.Fatalf("n=%d, want 0", n)
	}
	if store.deleteCalls != 0 {
		t.Fatalf("delete must not be called when count is zero (got %d)", store.deleteCalls)
	}
}

func TestPriorityAuditRetention_DeletesWhenNonEmpty(t *testing.T) {
	store := &fakeRetentionStore{countResult: 42}
	c := NewPriorityAuditRetentionController(store, &PriorityAuditRetentionConfig{
		RetentionDays: 7,
	})
	n, err := c.Reconcile(context.Background())
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if n != 42 {
		t.Fatalf("n=%d, want 42", n)
	}
	if store.deleteCalls != 1 {
		t.Fatalf("delete calls = %d, want 1", store.deleteCalls)
	}
	// Cutoff should be ~7 days ago.
	if time.Since(store.lastCutoff) < 6*24*time.Hour {
		t.Fatalf("cutoff too recent: %v", store.lastCutoff)
	}
}

func TestPriorityAuditRetention_DryRun_SkipsDelete(t *testing.T) {
	store := &fakeRetentionStore{countResult: 99}
	c := NewPriorityAuditRetentionController(store, &PriorityAuditRetentionConfig{
		RetentionDays: 30,
		DryRun:        true,
	})
	n, err := c.Reconcile(context.Background())
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if n != 99 {
		t.Fatalf("n=%d (count reported) want 99", n)
	}
	if store.deleteCalls != 0 {
		t.Fatalf("dry-run must not call delete (got %d)", store.deleteCalls)
	}
}

func TestPriorityAuditRetention_CountError_Propagates(t *testing.T) {
	store := &fakeRetentionStore{countErr: errors.New("db down")}
	c := NewPriorityAuditRetentionController(store, nil)
	_, err := c.Reconcile(context.Background())
	if err == nil {
		t.Fatal("expected error from count failure")
	}
}

func TestPriorityAuditRetention_DeleteError_Propagates(t *testing.T) {
	store := &fakeRetentionStore{countResult: 5, deleteErr: errors.New("constraint")}
	c := NewPriorityAuditRetentionController(store, nil)
	_, err := c.Reconcile(context.Background())
	if err == nil {
		t.Fatal("expected error from delete failure")
	}
}

func TestPriorityAuditRetention_Defaults(t *testing.T) {
	c := NewPriorityAuditRetentionController(&fakeRetentionStore{}, nil)
	if c.Name() != "priority-audit-retention" {
		t.Fatalf("name = %q", c.Name())
	}
	if c.Interval() != 24*time.Hour {
		t.Fatalf("default interval = %v", c.Interval())
	}
	if c.config.RetentionDays != 180 {
		t.Fatalf("default retention = %d, want 180", c.config.RetentionDays)
	}
}
