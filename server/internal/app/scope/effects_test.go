package scope

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

type fakeEffectsRepo struct {
	mu      sync.Mutex
	tenants []shared.ID
	closes  map[shared.ID]int
	reopens map[shared.ID]int
	failFor shared.ID
	block   chan struct{}
}

func (f *fakeEffectsRepo) TenantsWithScopeEffects(context.Context) ([]shared.ID, error) {
	return f.tenants, nil
}

func (f *fakeEffectsRepo) CloseOutOfScope(_ context.Context, tid shared.ID, limit int) ([]shared.ID, error) {
	if f.block != nil {
		<-f.block
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if limit != EffectsBatch {
		return nil, errors.New("unexpected batch size")
	}
	if tid == f.failFor {
		return nil, errors.New("boom")
	}
	f.closes[tid]++
	return []shared.ID{shared.NewID()}, nil
}

func (f *fakeEffectsRepo) ReopenBackInScope(_ context.Context, tid shared.ID, _ int) ([]shared.ID, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reopens[tid]++
	return nil, nil
}

func newFakeEffectsRepo(tenants ...shared.ID) *fakeEffectsRepo {
	return &fakeEffectsRepo{tenants: tenants, closes: map[shared.ID]int{}, reopens: map[shared.ID]int{}}
}

// One organization failing does not stop the pass over the others, and
// every organization gets a close then a reopen.
func TestEffectsReconcileAll(t *testing.T) {
	a, b, c := shared.NewID(), shared.NewID(), shared.NewID()
	repo := newFakeEffectsRepo(a, b, c)
	repo.failFor = b
	e := NewEffects(repo, nil, logger.NewNop())
	n, err := e.ReconcileAll(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Fatalf("moved %d, want 2 (a and c)", n)
	}
	if repo.closes[a] != 1 || repo.closes[c] != 1 || repo.reopens[a] != 1 || repo.reopens[c] != 1 {
		t.Fatalf("closes %v reopens %v", repo.closes, repo.reopens)
	}
	if repo.reopens[b] != 0 {
		t.Fatal("a failed close must not go on to reopen")
	}
}

func TestEffectsReconcileTenantRejectsZero(t *testing.T) {
	e := NewEffects(newFakeEffectsRepo(), nil, logger.NewNop())
	if _, err := e.ReconcileTenant(context.Background(), shared.ID{}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("err %v, want validation", err)
	}
}

// Kicks during a running pass fold into exactly one more pass; a nil
// reconciler ignores kicks.
func TestEffectsKickFolds(t *testing.T) {
	var nilEffects *Effects
	nilEffects.Kick(shared.NewID()) // must not panic

	tid := shared.NewID()
	repo := newFakeEffectsRepo()
	repo.block = make(chan struct{})
	e := NewEffects(repo, nil, logger.NewNop())
	e.Kick(tid)
	e.Kick(tid)
	e.Kick(tid)
	close(repo.block)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		e.mu.Lock()
		busy := e.inFlight[tid]
		e.mu.Unlock()
		if !busy {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	repo.mu.Lock()
	defer repo.mu.Unlock()
	if repo.closes[tid] != 2 {
		t.Fatalf("passes %d, want 2 (the first and one folded)", repo.closes[tid])
	}
}
