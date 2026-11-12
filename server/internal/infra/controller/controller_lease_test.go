package controller

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/controllerlease"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// fakeLeases grants a lease to the first holder only, until released.
type fakeLeases struct {
	mu       sync.Mutex
	holder   string
	epoch    int64
	renewOK  bool
	released int
}

func (f *fakeLeases) TryAcquire(_ context.Context, name, holder string, _ time.Duration) (controllerlease.Lease, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.holder != "" && f.holder != holder {
		return controllerlease.Lease{}, false, nil
	}
	f.holder = holder
	f.epoch++
	return controllerlease.Lease{Name: name, Holder: holder, Epoch: f.epoch}, true, nil
}

func (f *fakeLeases) Renew(context.Context, controllerlease.Lease, time.Duration) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.renewOK, nil
}

func (f *fakeLeases) Release(_ context.Context, l controllerlease.Lease) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.holder == l.Holder {
		f.holder = ""
	}
	f.released++
	return nil
}

type countingController struct {
	name      string
	exclusive bool
	mu        sync.Mutex
	runs      int
	block     time.Duration
	canceled  bool
}

func (c *countingController) Name() string            { return c.name }
func (c *countingController) Interval() time.Duration { return time.Hour }
func (c *countingController) Exclusive() bool         { return c.exclusive }
func (c *countingController) Reconcile(ctx context.Context) (int, error) {
	c.mu.Lock()
	c.runs++
	c.mu.Unlock()
	if c.block > 0 {
		select {
		case <-time.After(c.block):
		case <-ctx.Done():
			c.mu.Lock()
			c.canceled = true
			c.mu.Unlock()
		}
	}
	return 0, nil
}

func newLeaseManager(store controllerlease.Store, holder string) *Manager {
	return NewManager(&ManagerConfig{Logger: logger.NewNop(), Leases: store, LeaseHolder: holder})
}

func TestManager_ExclusiveControllerRunsOnOneReplica(t *testing.T) {
	store := &fakeLeases{renewOK: true}
	store.holder = "replica-b" // another replica holds it
	c := &countingController{name: "retention", exclusive: true}
	m := newLeaseManager(store, "replica-a")
	m.reconcileOnce(context.Background(), c)
	if c.runs != 0 {
		t.Fatalf("ran %d times while another replica holds the lease", c.runs)
	}

	store.holder = ""
	m.reconcileOnce(context.Background(), c)
	if c.runs != 1 || store.released != 1 || store.holder != "" {
		t.Fatalf("runs=%d released=%d holder=%q, want one run and the lease released", c.runs, store.released, store.holder)
	}
}

func TestManager_NonExclusiveAndNoStoreRunAsBefore(t *testing.T) {
	store := &fakeLeases{holder: "replica-b"}
	plain := &countingController{name: "health"}
	newLeaseManager(store, "replica-a").reconcileOnce(context.Background(), plain)
	ex := &countingController{name: "retention", exclusive: true}
	NewManager(&ManagerConfig{Logger: logger.NewNop()}).reconcileOnce(context.Background(), ex)
	if plain.runs != 1 || ex.runs != 1 {
		t.Fatalf("plain=%d exclusive-without-store=%d, want both to run", plain.runs, ex.runs)
	}
}

// Losing the lease mid-run (it expired and another replica took it) stops the
// reconcile instead of letting two replicas sweep at once.
func TestManager_LostLeaseCancelsTheReconcile(t *testing.T) {
	store := &fakeLeases{renewOK: false}
	c := &countingController{name: "retention", exclusive: true, block: 30 * time.Second}
	m := newLeaseManager(store, "replica-a")
	m.leaseRenew = 20 * time.Millisecond
	tc := &timeoutCountingController{countingController: c, timeout: time.Minute}
	start := time.Now()
	m.reconcileOnce(context.Background(), tc)
	if !c.canceled {
		t.Fatal("the reconcile was not canceled")
	}
	if time.Since(start) > 5*time.Second {
		t.Fatalf("reconcile ran %v after losing its lease", time.Since(start))
	}
}

type timeoutCountingController struct {
	*countingController
	timeout time.Duration
}

func (c *timeoutCountingController) ReconcileTimeout() time.Duration { return c.timeout }
