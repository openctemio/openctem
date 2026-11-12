package widgets

import (
	"context"
	"errors"
	"testing"
	"time"

	dashboardapp "github.com/openctemio/openctem/api/internal/app/dashboard"
	"github.com/openctemio/openctem/api/pkg/domain/dashboard"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// fakeSnapshots records the budget and lock calls of Refresh now.
type fakeSnapshots struct {
	dashboard.SnapshotStore
	lockFree         bool
	budgetOK         bool
	taken, refunded  int
	locked, released int
	fpErr            error
}

func (f *fakeSnapshots) TryRefreshLock(context.Context, shared.ID, shared.ID) (func(), bool, error) {
	if !f.lockFree {
		return nil, false, nil
	}
	f.locked++
	return func() { f.released++ }, true, nil
}

func (f *fakeSnapshots) TakeRefreshBudget(context.Context, shared.ID, shared.ID, shared.ID) (bool, time.Duration, error) {
	if !f.budgetOK {
		return false, time.Minute, nil
	}
	f.taken++
	return true, 0, nil
}

func (f *fakeSnapshots) RefundRefreshBudget(context.Context, shared.ID, shared.ID, shared.ID) error {
	f.refunded++
	return nil
}

func (f *fakeSnapshots) ScopeFingerprint(context.Context, shared.ID, shared.ID, *shared.DataScope, bool) (string, error) {
	if f.fpErr != nil {
		return "", f.fpErr
	}
	return "restricted:k", nil
}

func TestRefreshNow_LockBudgetAndRefund(t *testing.T) {
	tenant, user := shared.NewID(), shared.NewID()
	d, err := dashboard.NewDashboard(tenant, user, "d", "", 4, nil)
	if err != nil {
		t.Fatal(err)
	}
	c := dashboardapp.Caller{TenantID: tenant, UserID: user}
	scope := dashboard.ReadScope{TenantID: tenant}
	svc := func(f *fakeSnapshots, slots int) *Service {
		return &Service{snapshots: f, limiter: newLimiter(slots, slots, slots), logger: logger.NewNop(), now: time.Now}
	}

	// Another refresh of the dashboard runs: refused, budget untouched.
	f := &fakeSnapshots{budgetOK: true}
	if _, err := svc(f, 1).refreshNow(context.Background(), c, d, scope); !errors.Is(err, ErrRefreshRunning) {
		t.Fatalf("busy dashboard: err = %v, want ErrRefreshRunning", err)
	}
	if f.taken != 0 {
		t.Errorf("a refused refresh took the budget")
	}

	// Over the budget: 429 with the wait, lock released.
	f = &fakeSnapshots{lockFree: true}
	var budget *ErrRefreshBudget
	if _, err := svc(f, 1).refreshNow(context.Background(), c, d, scope); !errors.As(err, &budget) {
		t.Fatalf("over budget: err = %v", err)
	}
	if f.released != f.locked {
		t.Errorf("lock not released (%d taken, %d released)", f.locked, f.released)
	}

	// No read slot free: the computation cannot run, the budget is given back.
	f = &fakeSnapshots{lockFree: true, budgetOK: true}
	if _, err := svc(f, 0).refreshNow(context.Background(), c, d, scope); !errors.Is(err, ErrBusy) {
		t.Fatalf("no read slot: err = %v, want ErrBusy", err)
	}
	if f.taken != 1 || f.refunded != 1 || f.released != 1 {
		t.Errorf("taken %d refunded %d released %d, want 1 1 1", f.taken, f.refunded, f.released)
	}

	// A computation that started and failed keeps the budget: a dashboard
	// that keeps failing is not recomputed faster than the budget allows.
	boom := errors.New("boom")
	f = &fakeSnapshots{lockFree: true, budgetOK: true, fpErr: boom}
	if _, err := svc(f, 1).refreshNow(context.Background(), c, d, scope); !errors.Is(err, boom) {
		t.Fatalf("failed computation: err = %v, want boom", err)
	}
	if f.taken != 1 || f.refunded != 0 || f.released != 1 {
		t.Errorf("taken %d refunded %d released %d, want 1 0 1", f.taken, f.refunded, f.released)
	}
}
