package controller

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/openctemio/api/pkg/domain/shared"
)

type fakeControlStore struct {
	mu           sync.Mutex
	markCalls    int
	markResult   int64
	markErr      error
	expireCalls  int
	expireResult []ExpiredControl
	expireErr    error
	lastGrace    time.Duration
}

func (f *fakeControlStore) MarkOverdue(_ context.Context, _ time.Time) (int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.markCalls++
	return f.markResult, f.markErr
}

func (f *fakeControlStore) ExpireWithGrace(_ context.Context, _ time.Time, grace time.Duration) ([]ExpiredControl, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.expireCalls++
	f.lastGrace = grace
	return f.expireResult, f.expireErr
}

func TestCadence_Defaults(t *testing.T) {
	c := NewControlTestCadenceController(&fakeControlStore{}, nil)
	if c.Name() != "control-test-cadence" {
		t.Fatalf("name = %q", c.Name())
	}
	if c.Interval() != time.Hour {
		t.Fatalf("default interval = %v", c.Interval())
	}
	if c.cfg.Grace != 7*24*time.Hour {
		t.Fatalf("default grace = %v", c.cfg.Grace)
	}
}

func TestCadence_ReconcileNoWork(t *testing.T) {
	store := &fakeControlStore{markResult: 0, expireResult: nil}
	c := NewControlTestCadenceController(store, nil)
	n, err := c.Reconcile(context.Background())
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if n != 0 {
		t.Fatalf("n = %d", n)
	}
	if store.markCalls != 1 || store.expireCalls != 1 {
		t.Fatalf("store calls wrong: mark=%d expire=%d", store.markCalls, store.expireCalls)
	}
}

func TestCadence_MarksOverdue(t *testing.T) {
	store := &fakeControlStore{markResult: 5, expireResult: nil}
	c := NewControlTestCadenceController(store, nil)
	n, err := c.Reconcile(context.Background())
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if n != 5 {
		t.Fatalf("n = %d, want 5", n)
	}
}

func TestCadence_ExpireTriggersReclassify(t *testing.T) {
	tenant := shared.NewID()
	assets := []shared.ID{shared.NewID(), shared.NewID()}
	store := &fakeControlStore{
		markResult: 0,
		expireResult: []ExpiredControl{
			{TenantID: tenant, ControlID: shared.NewID(), AssetIDs: assets},
		},
	}
	capture := &captureQueue{}
	pub := NewControlChangePublisher(capture, nil)

	c := NewControlTestCadenceController(store, &ControlTestCadenceConfig{
		Publisher: pub,
	})

	_, err := c.Reconcile(context.Background())
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(capture.reqs) != 1 {
		t.Fatalf("expected 1 reclassify enqueue, got %d", len(capture.reqs))
	}
	req := capture.reqs[0]
	if req.TenantID != tenant || req.Reason != ReasonControlChange {
		t.Fatalf("wrong request: %+v", req)
	}
	if len(req.AssetIDs) != 2 {
		t.Fatalf("expected 2 asset ids, got %d", len(req.AssetIDs))
	}
}

func TestCadence_MarkOverdue_ErrorPropagates(t *testing.T) {
	boom := errors.New("db down")
	store := &fakeControlStore{markErr: boom}
	c := NewControlTestCadenceController(store, nil)
	_, err := c.Reconcile(context.Background())
	if !errors.Is(err, boom) {
		t.Fatalf("want boom, got %v", err)
	}
}

func TestCadence_ExpireError_DoesNotLoseMarkCount(t *testing.T) {
	boom := errors.New("expire failed")
	store := &fakeControlStore{markResult: 3, expireErr: boom}
	c := NewControlTestCadenceController(store, nil)
	n, err := c.Reconcile(context.Background())
	if !errors.Is(err, boom) {
		t.Fatalf("want boom, got %v", err)
	}
	if n != 3 {
		t.Fatalf("mark count should be preserved, got %d", n)
	}
}

func TestCadence_GracePassedToStore(t *testing.T) {
	store := &fakeControlStore{}
	c := NewControlTestCadenceController(store, &ControlTestCadenceConfig{
		Grace: 3 * 24 * time.Hour,
	})
	_, _ = c.Reconcile(context.Background())
	if store.lastGrace != 3*24*time.Hour {
		t.Fatalf("grace = %v, want 72h", store.lastGrace)
	}
}
