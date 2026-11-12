package controller

import (
	"context"
	"testing"
	"time"

	certmonitorapp "github.com/openctemio/openctem/api/internal/app/certmonitor"
	assetdom "github.com/openctemio/openctem/api/pkg/domain/asset"
	exposuredom "github.com/openctemio/openctem/api/pkg/domain/exposure"
	moduledom "github.com/openctemio/openctem/api/pkg/domain/module"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/ticketlink"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/pagination"
)

// Each test below proves that one background job leaves a tenant with its
// module off alone and still serves a tenant with the module on (the registry
// test tests/unit/module_job_guard_test.go names these tests).

// skipRunner records which tenants a callback-style runner would have worked
// on: the controller hands the runner a skip func, the runner calls it per
// tenant.
type skipRunner struct{ worked []shared.ID }

func (r *skipRunner) work(a, b shared.ID, skip func(shared.ID) bool) int {
	for _, id := range []shared.ID{a, b} {
		if !skip(id) {
			r.worked = append(r.worked, id)
		}
	}
	return len(r.worked)
}

type lookalikeStub struct {
	*skipRunner
	a, b shared.ID
}

func (l lookalikeStub) Run(_ context.Context, skip func(shared.ID) bool) (int, error) {
	return l.work(l.a, l.b, skip), nil
}

type pageMonStub struct {
	*skipRunner
	a, b shared.ID
}

func (p pageMonStub) Run(_ context.Context, skip func(shared.ID) bool) (int, error) {
	return p.work(p.a, p.b, skip), nil
}
func (p pageMonStub) Sweep(context.Context) (int64, error) { return 0, nil }

type seedStub struct {
	*skipRunner
	a, b shared.ID
}

func (s seedStub) RefreshDue(_ context.Context, skip func(shared.ID) bool) (int, error) {
	return s.work(s.a, s.b, skip), nil
}

func offFor(module string, off shared.ID) *fakeModuleGuard {
	return &fakeModuleGuard{disabledByTenant: map[string]map[string]bool{off.String(): {module: true}}}
}

func onlyOn(t *testing.T, worked []shared.ID, on shared.ID) {
	t.Helper()
	if len(worked) != 1 || worked[0] != on {
		t.Fatalf("expected work only for the tenant with the module on, got %v", worked)
	}
}

func TestEASMLookalike_SkipsTenantWithAttackSurfaceOff(t *testing.T) {
	on, off := shared.NewID(), shared.NewID()
	r := &skipRunner{}
	c := NewEASMLookalikeController(lookalikeStub{r, on, off}, offFor(moduledom.ModuleAttackSurface, off), 0)
	if _, err := c.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	onlyOn(t, r.worked, on)
}

func TestPageMonitor_SkipsTenantWithAttackSurfaceOff(t *testing.T) {
	on, off := shared.NewID(), shared.NewID()
	r := &skipRunner{}
	c := NewPageMonitorController(pageMonStub{r, on, off}, offFor(moduledom.ModuleAttackSurface, off), 0)
	if _, err := c.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	onlyOn(t, r.worked, on)
}

func TestEASMNetworkSeed_SkipsTenantWithAttackSurfaceOff(t *testing.T) {
	on, off := shared.NewID(), shared.NewID()
	r := &skipRunner{}
	c := NewEASMNetworkSeedController(seedStub{r, on, off}, offFor(moduledom.ModuleAttackSurface, off), 0)
	if _, err := c.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	onlyOn(t, r.worked, on)
}

type autoAddStub struct {
	*skipRunner
	a, b shared.ID
}

func (s autoAddStub) Run(_ context.Context, skip func(shared.ID) bool) (int, error) {
	return s.work(s.a, s.b, skip), nil
}

func TestEASMAddressAutoAdd_SkipsTenantWithAttackSurfaceOff(t *testing.T) {
	on, off := shared.NewID(), shared.NewID()
	r := &skipRunner{}
	c := NewEASMAddressAutoAddController(autoAddStub{r, on, off}, offFor(moduledom.ModuleAttackSurface, off), 0)
	if _, err := c.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	onlyOn(t, r.worked, on)
}

type digestStub struct{ sent []shared.ID }

func (d *digestStub) RunTenant(_ context.Context, id shared.ID) (bool, error) {
	d.sent = append(d.sent, id)
	return true, nil
}

func TestEASMWeeklyDigest_SkipsTenantWithAttackSurfaceOff(t *testing.T) {
	on, off := shared.NewID(), shared.NewID()
	d := &digestStub{}
	c := NewEASMWeeklyDigestController(d, &fakeTenantLister{ids: []shared.ID{on, off}},
		offFor(moduledom.ModuleAttackSurface, off), 0, logger.NewNop())
	if _, err := c.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	onlyOn(t, d.sent, on)
}

// ctAssets records the tenants the CT sweep looked assets up for.
type ctAssets struct{ tenants []string }

func (a *ctAssets) List(_ context.Context, f assetdom.Filter, _ assetdom.ListOptions, _ pagination.Pagination) (pagination.Result[*assetdom.Asset], error) {
	if f.TenantID != nil {
		a.tenants = append(a.tenants, *f.TenantID)
	}
	return pagination.Result[*assetdom.Asset]{}, nil
}

type ctExposures struct{}

func (ctExposures) BulkUpsert(context.Context, []*exposuredom.ExposureEvent) error { return nil }

func TestCertMonitor_SkipsTenantWithAttackSurfaceOff(t *testing.T) {
	on, off := shared.NewID(), shared.NewID()
	assets := &ctAssets{}
	svc := certmonitorapp.NewService(assets, ctExposures{}, "", logger.NewNop())
	c := NewCertMonitorController(svc, &fakeTenantLister{ids: []shared.ID{on, off}},
		&CertMonitorControllerConfig{ModuleGuard: offFor(moduledom.ModuleAttackSurface, off)})
	if _, err := c.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, id := range assets.tenants {
		if id == off.String() {
			t.Fatalf("the CT sweep looked up assets of the tenant with the module off")
		}
	}
	if len(assets.tenants) == 0 {
		t.Fatalf("the CT sweep never ran for the tenant with the module on")
	}
}

func TestTaskTicket_SkipsTenantWithRemediationOff(t *testing.T) {
	onRef := ticketlink.TaskLinkRef{TenantID: shared.NewID(), TaskID: shared.NewID()}
	offRef := ticketlink.TaskLinkRef{TenantID: shared.NewID(), TaskID: shared.NewID()}
	s := &syncStub{}
	ctl := NewTaskTicketController(behindStub{refs: []ticketlink.TaskLinkRef{offRef, onRef}}, s, 0, logger.NewNop())
	ctl.SetModuleGuard(offFor(moduledom.ModuleRemediation, offRef.TenantID))
	if _, err := ctl.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(s.pushed) != 1 || s.pushed[0] != onRef {
		t.Fatalf("expected a push only for the tenant with remediation on, got %v", s.pushed)
	}
}

// starvingLinks returns only the off tenant's links until that tenant is on
// the skip list: the oldest rows belong to the tenant that is off.
type starvingLinks struct {
	off, on ticketlink.TaskLinkRef
	skips   int
}

func (s *starvingLinks) TaskLinksBehindForPlatform(_ context.Context, limit int, skip []shared.ID) ([]ticketlink.TaskLinkRef, error) {
	s.skips = len(skip)
	if len(skip) == 0 {
		out := make([]ticketlink.TaskLinkRef, limit)
		for i := range out {
			out[i] = s.off
		}
		return out, nil
	}
	return []ticketlink.TaskLinkRef{s.on}, nil
}

func TestTaskTicket_DisabledTenantRowsDoNotStarveOthers(t *testing.T) {
	st := &starvingLinks{
		off: ticketlink.TaskLinkRef{TenantID: shared.NewID(), TaskID: shared.NewID()},
		on:  ticketlink.TaskLinkRef{TenantID: shared.NewID(), TaskID: shared.NewID()},
	}
	s := &syncStub{}
	ctl := NewTaskTicketController(st, s, 0, logger.NewNop())
	ctl.SetModuleGuard(offFor(moduledom.ModuleRemediation, st.off.TenantID))
	if _, err := ctl.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(s.pushed) != 1 || s.pushed[0] != st.on {
		t.Fatalf("a full batch of the disabled tenant's links starved the enabled tenant: %v", s.pushed)
	}
}

type assignProbe struct {
	a, b shared.ID
	done []shared.ID
}

func (p *assignProbe) AssignAllPrograms(ctx context.Context, off func(context.Context, shared.ID) bool) (int64, error) {
	for _, id := range []shared.ID{p.a, p.b} {
		if off == nil || !off(ctx, id) {
			p.done = append(p.done, id)
		}
	}
	return int64(len(p.done)), nil
}

func TestProgramAssignment_SkipsTenantWithScopeOff(t *testing.T) {
	on, off := shared.NewID(), shared.NewID()
	p := &assignProbe{a: on, b: off}
	c := NewProgramAssignmentController(p, time.Minute)
	c.SetModuleGuard(offFor(moduledom.ModuleScopeConfig, off))
	if _, err := c.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	onlyOn(t, p.done, on)
}
