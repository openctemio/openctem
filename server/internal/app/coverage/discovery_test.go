package coverage

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	covdom "github.com/openctemio/openctem/api/pkg/domain/coverage"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/stage"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// Every capability the coverage loop plans belongs to exactly one discovery stages
// stage, and each mapping entry is a stage catalog capability whose catalog
// phase fits its discovery stage: a new coverage rule fails here until it is
// placed in a stage.
func TestDiscoveryStageMapping_CoversThePlannedCapabilities(t *testing.T) {
	planned := plannedCapabilities(covdom.Rules())
	if len(planned) == 0 {
		t.Fatal("no planned capability")
	}
	for _, c := range planned {
		if _, ok := covdom.DiscoveryStageOf(c); !ok {
			t.Errorf("planned capability %s has no discovery stages stage (pkg/domain/coverage/discovery stages.go)", c)
		}
	}
	allowed := map[covdom.DiscoveryStage][]string{
		covdom.StageAssetDiscovery: {"discover.passive", "discover.active"},
		covdom.StageExposureScan:   {"discover.active", "assess", "validate"},
		covdom.StageValidation:     {"discover.passive"},
		covdom.StageTechnology:     {"discover.active"},
	}
	for _, st := range stage.All() {
		p, ok := covdom.DiscoveryStageOf(string(st.Key))
		if !ok {
			continue
		}
		if !slices.Contains(allowed[p], st.Phase) {
			t.Errorf("%s (phase %s) does not fit discovery stage %s", st.Key, st.Phase, p)
		}
	}
	for _, c := range []string{"discover.subdomains", "enumerate.subdomains", "resolve.dns", "lookup.rdap", "lookup.asn",
		"scan.ports", "vuln.templates", "probe.http"} {
		if _, ok := stage.Lookup(stage.Key(c)); !ok {
			t.Errorf("%s is not in the stage catalog", c)
		}
	}
	// Each stage of the default policy has at least one planned capability.
	for _, p := range covdom.DiscoveryStages() {
		if len(covdom.DiscoveryCapabilities(planned, p)) == 0 {
			t.Errorf("discovery stage %s has no planned capability", p)
		}
	}
	// Platform checks run on the sweep's schedule, not in the discovery stages.
	for _, c := range []string{covdom.CapabilityDNSEmail, covdom.CapabilityDNSDangling} {
		if _, ok := covdom.DiscoveryStageOf(c); ok {
			t.Errorf("%s must not be a discovery stages capability", c)
		}
	}
	if covdom.DiscoveryStage("bogus").Valid() {
		t.Error("unknown stage is valid")
	}
}

type fakeDiscoveryStore struct {
	stats    []covdom.CapabilityDiscovery
	waits    map[string]time.Duration
	madeDue  int
	active   []shared.ID
	auto     covdom.AutoValidation
	tenantOf map[string]shared.ID // last tenant per call
}

func (f *fakeDiscoveryStore) seen(call string, t shared.ID) {
	if f.tenantOf == nil {
		f.tenantOf = map[string]shared.ID{}
	}
	f.tenantOf[call] = t
}

func (f *fakeDiscoveryStore) DiscoveryStats(_ context.Context, t shared.ID, _ []string) ([]covdom.CapabilityDiscovery, error) {
	f.seen("stats", t)
	return f.stats, nil
}

func (f *fakeDiscoveryStore) MakeDueNow(_ context.Context, t shared.ID, waits map[string]time.Duration) (int, error) {
	f.seen("due", t)
	f.waits = waits
	return f.madeDue, nil
}

func (f *fakeDiscoveryStore) ActiveCoverageRuns(_ context.Context, t shared.ID) ([]shared.ID, error) {
	f.seen("active", t)
	return f.active, nil
}

func (f *fakeDiscoveryStore) LastAutoValidation(_ context.Context, t shared.ID, _ []string) (covdom.AutoValidation, error) {
	f.seen("auto", t)
	return f.auto, nil
}

type fakeBudget struct{ used int }

func (f fakeBudget) AttemptsSince(context.Context, shared.ID, time.Time) (int, error) {
	return f.used, nil
}

type fakeSwitch struct {
	on  bool
	err error
}

func (f fakeSwitch) CoverageEnabled(context.Context, shared.ID) (bool, error) { return f.on, f.err }

type fakeLimiter struct{ held map[string]time.Time }

func (f *fakeLimiter) Acquire(_ context.Context, key string, window time.Duration) (bool, time.Time, error) {
	if f.held == nil {
		f.held = map[string]time.Time{}
	}
	if until, ok := f.held[key]; ok && until.After(time.Now()) {
		return false, until, nil
	}
	f.held[key] = time.Now().Add(window)
	return true, time.Time{}, nil
}

func (f *fakeLimiter) AvailableAt(_ context.Context, keys []string) (map[string]time.Time, error) {
	out := map[string]time.Time{}
	for _, k := range keys {
		if t, ok := f.held[k]; ok {
			out[k] = t
		}
	}
	return out, nil
}

type fakeCanceller struct {
	canceled []string
	fail     map[string]bool
}

func (f *fakeCanceller) CancelRun(_ context.Context, tenantID, runID string) error {
	if f.fail[runID] {
		return errors.New("already complete")
	}
	f.canceled = append(f.canceled, tenantID+"/"+runID)
	return nil
}

func newTestDiscovery(store *fakeDiscoveryStore, used int, sw TenantSwitch, lim RunLimiter, c RunCanceller, loop bool) *Discovery {
	return NewDiscovery(store, fakeBudget{used: used}, sw, c, lim,
		DiscoveryConfig{LoopEnabled: loop, Interval: time.Minute, DailyBudget: 100}, logger.NewNop())
}

func TestDiscoveryRun_MakesOnlyTheStageDue(t *testing.T) {
	store := &fakeDiscoveryStore{madeDue: 7}
	tenant := shared.NewID()
	d := newTestDiscovery(store, 0, fakeSwitch{on: true}, &fakeLimiter{}, nil, true)
	res, err := d.Run(context.Background(), tenant, []covdom.DiscoveryStage{covdom.StageValidation})
	if err != nil {
		t.Fatal(err)
	}
	if res.PairsMadeDue != 7 || len(res.Started) != 1 || res.NextPassWithin != time.Minute {
		t.Fatalf("result = %+v", res)
	}
	if store.tenantOf["due"] != tenant {
		t.Fatal("made due for another tenant")
	}
	for c, w := range store.waits {
		if p, _ := covdom.DiscoveryStageOf(c); p != covdom.StageValidation {
			t.Errorf("%s is not a validation capability", c)
		}
		if w != covdom.BatchWait(d.ruleOf(c).Every) || w <= 0 {
			t.Errorf("%s wait = %s", c, w)
		}
	}
	if _, ok := store.waits["resolve.dns"]; !ok {
		t.Errorf("resolve.dns not made due: %v", store.waits)
	}
}

func TestDiscoveryRun_Refusals(t *testing.T) {
	ctx, tenant := context.Background(), shared.NewID()
	all := covdom.DiscoveryStages()
	cases := []struct {
		name string
		d    *Discovery
		want error
	}{
		{"loop off", newTestDiscovery(&fakeDiscoveryStore{}, 0, fakeSwitch{on: true}, &fakeLimiter{}, nil, false), ErrLoopOff},
		{"coverage off", newTestDiscovery(&fakeDiscoveryStore{}, 0, fakeSwitch{on: false}, &fakeLimiter{}, nil, true), ErrCoverageOff},
		{"no switch is off", newTestDiscovery(&fakeDiscoveryStore{}, 0, nil, &fakeLimiter{}, nil, true), ErrCoverageOff},
		{"budget spent", newTestDiscovery(&fakeDiscoveryStore{}, 100, fakeSwitch{on: true}, &fakeLimiter{}, nil, true), ErrBudgetSpent},
	}
	for _, c := range cases {
		store := c.d.store.(*fakeDiscoveryStore)
		if _, err := c.d.Run(ctx, tenant, all); !errors.Is(err, c.want) {
			t.Errorf("%s: err = %v, want %v", c.name, err, c.want)
		}
		if store.waits != nil {
			t.Errorf("%s: pairs were made due", c.name)
		}
	}
	// A switch that cannot be read refuses (fail closed).
	d := newTestDiscovery(&fakeDiscoveryStore{}, 0, fakeSwitch{err: errors.New("db")}, &fakeLimiter{}, nil, true)
	if _, err := d.Run(ctx, tenant, all); err == nil {
		t.Error("unreadable switch ran")
	}
	if _, err := d.Run(ctx, tenant, []covdom.DiscoveryStage{"bogus"}); !errors.Is(err, shared.ErrValidation) {
		t.Errorf("unknown stage err = %v", err)
	}
}

func TestDiscoveryRun_OncePerMinutePerStageAndTenant(t *testing.T) {
	ctx := context.Background()
	lim := &fakeLimiter{}
	d := newTestDiscovery(&fakeDiscoveryStore{}, 0, fakeSwitch{on: true}, lim, nil, true)
	a, b := shared.NewID(), shared.NewID()
	if _, err := d.Run(ctx, a, []covdom.DiscoveryStage{covdom.StageAssetDiscovery}); err != nil {
		t.Fatal(err)
	}
	var soon *TooSoonError
	if _, err := d.Run(ctx, a, []covdom.DiscoveryStage{covdom.StageAssetDiscovery}); !errors.As(err, &soon) || soon.Until.IsZero() {
		t.Fatalf("second run err = %v", err)
	}
	// Another tenant's stage and another stage are not limited.
	if _, err := d.Run(ctx, b, []covdom.DiscoveryStage{covdom.StageAssetDiscovery}); err != nil {
		t.Fatalf("other tenant: %v", err)
	}
	// Run all skips the stage run a moment ago and starts the others.
	res, err := d.Run(ctx, a, covdom.DiscoveryStages())
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Started) != 3 || len(res.Skipped) != 1 || res.Skipped[0] != covdom.StageAssetDiscovery {
		t.Fatalf("run all = %+v", res)
	}
	if _, err := d.Run(ctx, a, covdom.DiscoveryStages()); !errors.As(err, &soon) {
		t.Fatalf("run all again err = %v", err)
	}
	for k := range lim.held {
		if !strings.Contains(k, a.String()) && !strings.Contains(k, b.String()) {
			t.Errorf("limiter key %q names no tenant", k)
		}
	}
}

func TestDiscoveryAbortAll_CancelsOnlyTheTenantsCoverageRuns(t *testing.T) {
	r1, r2 := shared.NewID(), shared.NewID()
	tenant := shared.NewID()
	store := &fakeDiscoveryStore{active: []shared.ID{r1, r2}}
	c := &fakeCanceller{fail: map[string]bool{r2.String(): true}}
	d := newTestDiscovery(store, 0, fakeSwitch{on: true}, &fakeLimiter{}, c, true)
	res, err := d.AbortAll(context.Background(), tenant)
	if err != nil {
		t.Fatal(err)
	}
	if res.Canceled != 1 || res.Failed != 1 || len(c.canceled) != 1 || c.canceled[0] != tenant.String()+"/"+r1.String() {
		t.Fatalf("abort = %+v %v", res, c.canceled)
	}
	if store.tenantOf["active"] != tenant {
		t.Fatal("listed another tenant's runs")
	}
}

func TestDiscoveryOverview_StatusesAndAvailability(t *testing.T) {
	now := time.Now()
	store := &fakeDiscoveryStore{
		stats: []covdom.CapabilityDiscovery{
			{Capability: "probe.http", Stage: covdom.StageTechnology, Pairs: 4, Covered: 1,
				LastRun: &covdom.CapabilityRun{Status: "running", CreatedAt: now, TasksTotal: 3, TasksDone: 1}},
			{Capability: "resolve.dns", Stage: covdom.StageValidation, Pairs: 2, Paused: 2, PausedReason: covdom.ReadyToolMissing},
		},
		auto: covdom.AutoValidation{Assets: 5},
	}
	lim := &fakeLimiter{}
	tenant := shared.NewID()
	d := newTestDiscovery(store, 3, fakeSwitch{on: true}, lim, nil, true)
	if _, err := d.Run(context.Background(), tenant, []covdom.DiscoveryStage{covdom.StageExposureScan}); err != nil {
		t.Fatal(err)
	}
	o, err := d.Overview(context.Background(), tenant)
	if err != nil {
		t.Fatal(err)
	}
	if !o.CoverageEnabled || o.BudgetUsed != 3 || o.AutoValidation.Assets != 5 || len(o.Stages) != 4 {
		t.Fatalf("overview = %+v", o)
	}
	byStage := map[covdom.DiscoveryStage]covdom.StageSummary{}
	for _, s := range o.Stages {
		byStage[s.Stage] = s
	}
	if s := byStage[covdom.StageTechnology]; s.Status != covdom.DiscoveryRunning || s.ProgressDone != 1 || s.ProgressTotal != 3 || s.ProgressUnit != covdom.ProgressTasks {
		t.Errorf("technology = %+v", s)
	}
	if s := byStage[covdom.StageValidation]; s.Status != covdom.DiscoveryPaused || s.Reason != covdom.ReadyToolMissing {
		t.Errorf("validation = %+v", s)
	}
	if s := byStage[covdom.StageAssetDiscovery]; s.Status != covdom.DiscoveryIdle || len(s.Capabilities) == 0 {
		t.Errorf("asset discovery = %+v", s)
	}
	if _, ok := o.RunAvailableAt[covdom.StageExposureScan]; !ok {
		t.Error("exposure scan run availability not reported")
	}
	if _, ok := o.RunAvailableAt[covdom.StageAssetDiscovery]; ok {
		t.Error("asset discovery reported as limited")
	}
	// Coverage off pauses every idle stage with coverage_off.
	d = newTestDiscovery(&fakeDiscoveryStore{}, 0, fakeSwitch{on: false}, lim, nil, true)
	o, err = d.Overview(context.Background(), tenant)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range o.Stages {
		if s.Status != covdom.DiscoveryPaused || s.Reason != covdom.ReasonCoverageOff {
			t.Errorf("coverage off %s = %+v", s.Stage, s)
		}
	}
}

func TestSummarizeStage(t *testing.T) {
	now := time.Now()
	earlier := now.Add(-time.Hour)
	failed := []covdom.CapabilityDiscovery{
		{Capability: "scan.ports", Pairs: 10, Covered: 4, LastRun: &covdom.CapabilityRun{Status: "failed", CreatedAt: earlier}},
		{Capability: "vuln.templates", Pairs: 5, Covered: 5, LastRun: &covdom.CapabilityRun{Status: "completed", CreatedAt: now, StartedAt: &now}},
	}
	s := covdom.SummarizeStage(covdom.StageExposureScan, failed, false)
	if s.Status != covdom.DiscoveryFailed || s.ProgressDone != 9 || s.ProgressTotal != 15 || s.ProgressUnit != covdom.ProgressPairs ||
		s.LastRunAt == nil || !s.LastRunAt.Equal(now) {
		t.Errorf("failed stage = %+v", s)
	}
	// Running wins over coverage off.
	running := []covdom.CapabilityDiscovery{{Capability: "scan.ports", LastRun: &covdom.CapabilityRun{Status: "pending", CreatedAt: now, TasksTotal: 2}}}
	if s := covdom.SummarizeStage(covdom.StageExposureScan, running, true); s.Status != covdom.DiscoveryRunning || s.ProgressTotal != 2 {
		t.Errorf("running stage = %+v", s)
	}
	if s := covdom.SummarizeStage(covdom.StageExposureScan, nil, false); s.Status != covdom.DiscoveryIdle || s.LastRunAt != nil {
		t.Errorf("empty stage = %+v", s)
	}
}
