package easm

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/internal/app/scope"
	scopedom "github.com/openctemio/openctem/api/pkg/domain/scope"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

type countingJoin struct {
	mu      sync.Mutex
	runs    map[shared.ID]int
	active  atomic.Int32
	overlap atomic.Bool
	hold    chan struct{} // when set, a run waits on it
	fail    atomic.Bool
}

func (c *countingJoin) Run(_ context.Context, id shared.ID) ([]scope.JoinedAsset, error) {
	if c.active.Add(1) > 1 {
		c.overlap.Store(true)
	}
	defer c.active.Add(-1)
	if c.hold != nil {
		<-c.hold
	}
	c.mu.Lock()
	c.runs[id]++
	c.mu.Unlock()
	if c.fail.Load() {
		return nil, errors.New("db down")
	}
	return []scope.JoinedAsset{{AssetID: "a"}}, nil
}

func (c *countingJoin) Preview(context.Context, shared.ID, *scopedom.Target) ([]scope.JoinedAsset, error) {
	return nil, nil
}

func (c *countingJoin) count(id shared.ID) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.runs[id]
}

// A burst of changes is one run per tenant; tenants are independent.
func TestJoinScheduler_Debounces(t *testing.T) {
	j := &countingJoin{runs: map[shared.ID]int{}}
	s := newJoinScheduler(j, 20*time.Millisecond, nil)
	a, b := shared.NewID(), shared.NewID()
	for range 10 {
		s.Schedule(a)
	}
	s.Schedule(b)
	s.Wait()
	if j.count(a) != 1 || j.count(b) != 1 {
		t.Fatalf("runs a=%d b=%d, want 1 each", j.count(a), j.count(b))
	}
	s.Schedule(shared.ID{}) // a zero tenant is ignored
	s.Wait()
}

// A change during a run gets one more run after it, never two at once.
func TestJoinScheduler_RunsAgainAfterAChangeDuringARun(t *testing.T) {
	j := &countingJoin{runs: map[shared.ID]int{}, hold: make(chan struct{})}
	s := newJoinScheduler(j, 5*time.Millisecond, nil)
	a := shared.NewID()
	s.Schedule(a)
	for j.active.Load() == 0 {
		time.Sleep(time.Millisecond)
	}
	s.Schedule(a)
	s.Schedule(a)
	close(j.hold)
	s.Wait()
	if j.count(a) != 2 {
		t.Fatalf("runs = %d, want 2", j.count(a))
	}
	if j.overlap.Load() {
		t.Fatal("two runs of one tenant at once")
	}
}

// RunNow takes over a pending request and returns what it confirmed; a
// failed run is retried in the background.
func TestJoinScheduler_RunNow(t *testing.T) {
	j := &countingJoin{runs: map[shared.ID]int{}}
	s := newJoinScheduler(j, time.Hour, nil)
	a := shared.NewID()
	s.Schedule(a)
	done, err := s.RunNow(context.Background(), a)
	if err != nil || len(done) != 1 {
		t.Fatalf("RunNow = %v, %v", done, err)
	}
	s.Wait() // the pending hour-long timer was taken over, not left behind
	if j.count(a) != 1 {
		t.Fatalf("runs = %d, want 1", j.count(a))
	}

	j.fail.Store(true)
	s2 := newJoinScheduler(j, 5*time.Millisecond, nil)
	if _, err := s2.RunNow(context.Background(), a); err == nil {
		t.Fatal("a failed run reported success")
	}
	s2.Wait()
	if j.count(a) != 3 {
		t.Fatalf("runs = %d, want the failed run and its retry (3)", j.count(a))
	}
}
