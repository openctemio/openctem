package controller

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/durablejob"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

type fakeDurableStore struct {
	due       []durablejob.Claimed
	kinds     []durablejob.Kind
	completed []shared.ID
	retried   map[shared.ID]time.Time
	buried    map[shared.ID]string
}

func (f *fakeDurableStore) Claim(_ context.Context, kinds []durablejob.Kind, _ int, _ time.Duration) ([]durablejob.Claimed, error) {
	f.kinds = kinds
	out := f.due
	f.due = nil
	return out, nil
}
func (f *fakeDurableStore) Complete(_ context.Context, j durablejob.Claimed) error {
	f.completed = append(f.completed, j.ID)
	return nil
}
func (f *fakeDurableStore) Retry(_ context.Context, j durablejob.Claimed, at time.Time, _ string) error {
	f.retried[j.ID] = at
	return nil
}
func (f *fakeDurableStore) Bury(_ context.Context, j durablejob.Claimed, reason string) error {
	f.buried[j.ID] = reason
	return nil
}

type permErr struct{}

func (permErr) Error() string   { return "not found at the provider" }
func (permErr) Permanent() bool { return true }

func claimed(kind durablejob.Kind, attempts int) durablejob.Claimed {
	return durablejob.Claimed{ID: shared.NewID(), Attempts: attempts,
		Job: durablejob.Job{Kind: kind, TenantID: shared.NewID(), SubjectID: shared.NewID()}}
}

func TestDurableJobsController_Outcomes(t *testing.T) {
	ok, transient, permanent, exhausted := claimed(durablejob.KindJiraStatusSync, 1), claimed(durablejob.KindJiraStatusSync, 2),
		claimed(durablejob.KindJiraStatusSync, 1), claimed(durablejob.KindJiraStatusSync, durableJobMaxAttempts)
	store := &fakeDurableStore{due: []durablejob.Claimed{ok, transient, permanent, exhausted},
		retried: map[shared.ID]time.Time{}, buried: map[shared.ID]string{}}
	var gotTenant shared.ID
	handler := func(_ context.Context, j durablejob.Claimed) error {
		switch j.ID {
		case ok.ID:
			gotTenant = j.TenantID
			return nil
		case permanent.ID:
			return permErr{}
		default:
			return errors.New("jira timeout")
		}
	}
	now := time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)
	c := NewDurableJobsController(store, map[durablejob.Kind]DurableJobHandler{durablejob.KindJiraStatusSync: handler}, 0, logger.NewNop())
	c.now = func() time.Time { return now }

	n, err := c.Reconcile(context.Background())
	if err != nil || n != 1 {
		t.Fatalf("Reconcile = %d, %v", n, err)
	}
	if len(store.kinds) != 1 || store.kinds[0] != durablejob.KindJiraStatusSync {
		t.Fatalf("claimed kinds %v: only kinds with a handler", store.kinds)
	}
	if len(store.completed) != 1 || store.completed[0] != ok.ID || gotTenant != ok.TenantID {
		t.Fatalf("completed %v (tenant %s)", store.completed, gotTenant)
	}
	if at, ok := store.retried[transient.ID]; !ok || !at.Equal(now.Add(time.Minute)) {
		t.Fatalf("transient failure retried at %v, want +1m (second attempt)", at)
	}
	if _, ok := store.buried[permanent.ID]; !ok {
		t.Fatal("permanent failure not buried")
	}
	if _, ok := store.buried[exhausted.ID]; !ok {
		t.Fatal("job at the attempt limit not buried")
	}
}

func TestDurableJobBackoff(t *testing.T) {
	for attempts, want := range map[int]time.Duration{1: 30 * time.Second, 2: time.Minute, 3: 2 * time.Minute, 20: time.Hour} {
		if got := durableJobBackoff(attempts); got != want {
			t.Errorf("backoff(%d) = %v, want %v", attempts, got, want)
		}
	}
}
