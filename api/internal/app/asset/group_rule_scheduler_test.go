package asset

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func TestGroupRuleScheduler_DebouncesABurstIntoOneRun(t *testing.T) {
	var runs atomic.Int32
	s := newGroupRuleScheduler(func(context.Context, shared.ID) (int, error) { runs.Add(1); return 0, nil }, 20*time.Millisecond, nil)
	tenant := shared.NewID()
	for i := 0; i < 50; i++ {
		s.NotifyAssetsChanged(tenant)
	}
	s.Wait()
	if got := runs.Load(); got != 1 {
		t.Fatalf("a burst ran %d times, want 1", got)
	}
}

func TestGroupRuleScheduler_ChangeDuringARunRunsAgain(t *testing.T) {
	var runs atomic.Int32
	started, release := make(chan struct{}, 2), make(chan struct{})
	s := newGroupRuleScheduler(func(context.Context, shared.ID) (int, error) {
		runs.Add(1)
		started <- struct{}{}
		<-release
		return 0, nil
	}, 5*time.Millisecond, nil)
	tenant := shared.NewID()
	s.NotifyAssetsChanged(tenant)
	<-started
	s.NotifyAssetsChanged(tenant) // while the first run is in progress
	s.NotifyAssetsChanged(tenant)
	close(release)
	s.Wait()
	if got := runs.Load(); got != 2 {
		t.Fatalf("ran %d times, want 2 (one repeat for the change during the run)", got)
	}
}

func TestGroupRuleScheduler_TenantsAreIndependentAndRunsNeverOverlap(t *testing.T) {
	var mu sync.Mutex
	active := map[shared.ID]int{}
	seen := map[shared.ID]int{}
	overlap := false
	s := newGroupRuleScheduler(func(_ context.Context, id shared.ID) (int, error) {
		mu.Lock()
		active[id]++
		seen[id]++
		if active[id] > 1 {
			overlap = true
		}
		mu.Unlock()
		time.Sleep(15 * time.Millisecond)
		mu.Lock()
		active[id]--
		mu.Unlock()
		return 0, nil
	}, 2*time.Millisecond, nil)
	a, b := shared.NewID(), shared.NewID()
	for i := 0; i < 30; i++ {
		s.NotifyAssetsChanged(a)
		s.NotifyAssetsChanged(b)
		time.Sleep(time.Millisecond)
	}
	s.Wait()
	if overlap {
		t.Fatal("two runs of one tenant overlapped")
	}
	if seen[a] == 0 || seen[b] == 0 {
		t.Fatalf("a tenant was never evaluated: %v", seen)
	}
}

func TestGroupRuleScheduler_NilAndZeroTenantAreIgnored(t *testing.T) {
	var s *GroupRuleScheduler
	s.NotifyAssetsChanged(shared.NewID())
	var runs atomic.Int32
	real := newGroupRuleScheduler(func(context.Context, shared.ID) (int, error) { runs.Add(1); return 0, nil }, time.Millisecond, nil)
	real.NotifyAssetsChanged(shared.ID{})
	real.Wait()
	if runs.Load() != 0 {
		t.Fatal("a zero tenant was evaluated")
	}
}
