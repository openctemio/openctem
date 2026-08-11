package controller

import (
	"context"
	"testing"

	moduledom "github.com/openctemio/api/pkg/domain/module"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/simulation"
	"github.com/openctemio/api/pkg/logger"
)

// fakeModuleGuard is a per-tenant disabled-module oracle for the compute-guard
// tests. A tenant absent from disabledByTenant has no modules disabled (the
// backward-compatible "no subscription" case).
type fakeModuleGuard struct {
	disabledByTenant map[string]map[string]bool
	calls            int
}

func (f *fakeModuleGuard) TenantDisabledModules(_ context.Context, tenantID string) map[string]bool {
	f.calls++
	return f.disabledByTenant[tenantID]
}

// fakeControlTestRepo embeds the domain interface so only the two methods the
// controller uses need real implementations; any other call panics (unused).
type fakeControlTestRepo struct {
	simulation.ControlTestRepository
	overdue []*simulation.OverdueControlTest
	marked  []shared.ID
}

func (f *fakeControlTestRepo) ListOverdue(_ context.Context, _ int, _ int) ([]*simulation.OverdueControlTest, error) {
	return f.overdue, nil
}

func (f *fakeControlTestRepo) MarkOverdue(_ context.Context, _ shared.ID, id shared.ID) error {
	f.marked = append(f.marked, id)
	return nil
}

func newOverdue(tenant, id shared.ID) *simulation.OverdueControlTest {
	return &simulation.OverdueControlTest{
		TenantID:      tenant,
		ControlTestID: id,
		Name:          "detection",
		Framework:     "mitre",
	}
}

// TestControlTestScheduler_SkipsUnsubscribedTenant proves the compute guard: a
// tenant that has NOT subscribed to the control-testing module has its overdue
// control tests skipped, while an all-on tenant in the same batch is processed.
func TestControlTestScheduler_SkipsUnsubscribedTenant(t *testing.T) {
	tenantOff, offCT := shared.NewID(), shared.NewID()
	tenantOn, onCT := shared.NewID(), shared.NewID()

	repo := &fakeControlTestRepo{overdue: []*simulation.OverdueControlTest{
		newOverdue(tenantOff, offCT),
		newOverdue(tenantOn, onCT),
	}}
	guard := &fakeModuleGuard{disabledByTenant: map[string]map[string]bool{
		tenantOff.String(): {moduledom.ModuleControlTesting: true},
	}}

	c := NewControlTestSchedulerController(repo, &ControlTestSchedulerConfig{
		Logger:      logger.NewNop(),
		ModuleGuard: guard,
	})

	n, err := c.Reconcile(context.Background())
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if n != 1 {
		t.Fatalf("marked = %d, want 1 (only the subscribed tenant)", n)
	}
	if len(repo.marked) != 1 || repo.marked[0] != onCT {
		t.Fatalf("expected only the subscribed tenant's control test marked, got %v", repo.marked)
	}
}

// TestControlTestScheduler_RunsForAllOnTenant proves the guard is a strict
// no-op: with no ModuleGuard wired (the default), every overdue test is marked.
func TestControlTestScheduler_RunsForAllOnTenant(t *testing.T) {
	tenant, ct := shared.NewID(), shared.NewID()
	repo := &fakeControlTestRepo{overdue: []*simulation.OverdueControlTest{newOverdue(tenant, ct)}}

	c := NewControlTestSchedulerController(repo, &ControlTestSchedulerConfig{
		Logger: logger.NewNop(),
		// ModuleGuard intentionally nil — backward-compatible "always run".
	})

	n, err := c.Reconcile(context.Background())
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if n != 1 || len(repo.marked) != 1 || repo.marked[0] != ct {
		t.Fatalf("nil guard must run for all tenants: n=%d marked=%v", n, repo.marked)
	}
}

// TestControlTestScheduler_EmptySubscriptionRunsAll proves that a guard which
// returns an empty disabled set (tenant present, nothing disabled — the "all
// modules on" subscription) still runs the sweep for that tenant.
func TestControlTestScheduler_EmptySubscriptionRunsAll(t *testing.T) {
	tenant, ct := shared.NewID(), shared.NewID()
	repo := &fakeControlTestRepo{overdue: []*simulation.OverdueControlTest{newOverdue(tenant, ct)}}
	guard := &fakeModuleGuard{disabledByTenant: map[string]map[string]bool{
		tenant.String(): {}, // subscribed, nothing disabled
	}}

	c := NewControlTestSchedulerController(repo, &ControlTestSchedulerConfig{
		Logger:      logger.NewNop(),
		ModuleGuard: guard,
	})

	n, err := c.Reconcile(context.Background())
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if n != 1 {
		t.Fatalf("empty disabled set must not skip: n=%d", n)
	}
}
