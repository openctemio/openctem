package integration

// Readiness before coverage runs (RFC-093) on a migrated database: a
// capability that cannot run for the tenant gets no run (nothing reaches the
// run starter, so no run, command or blocked run exists), its pairs whose
// time has come are paused with one readiness reason, the reason follows the
// condition, and the pairs resume by themselves on the first pass where the
// capability is ready. One tenant's readiness never pauses or resumes
// another tenant's pairs.

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	covdom "github.com/openctemio/openctem/api/pkg/domain/coverage"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// fakeReadiness answers a reason per tenant and capability ("*" = every
// capability).
type fakeReadiness struct {
	mu      sync.Mutex
	reasons map[shared.ID]map[string]string
	calls   int
}

func (f *fakeReadiness) set(tenant shared.ID, capability, reason string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.reasons[tenant] == nil {
		f.reasons[tenant] = map[string]string{}
	}
	f.reasons[tenant][capability] = reason
}

func (f *fakeReadiness) CoverageReadiness(_ context.Context, tenantID shared.ID, capabilities []string) map[string]string {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	out := map[string]string{}
	for _, c := range capabilities {
		if r, ok := f.reasons[tenantID][c]; ok {
			out[c] = r
		} else if r, ok := f.reasons[tenantID]["*"]; ok {
			out[c] = r
		}
	}
	return out
}

func (g *cycleRig) runCount(tn v2Tenant) int {
	g.t.Helper()
	var n int
	if err := g.r.db.QueryRow(`SELECT count(*) FROM scan_runs WHERE tenant_id = $1`, tn.tenant.String()).Scan(&n); err != nil {
		g.t.Fatal(err)
	}
	return n
}

func TestAssetCoverageReadiness_NoRunWhenNotReady_ResumesWhenReady(t *testing.T) {
	g := newCycleRig(t)
	rd := &fakeReadiness{reasons: map[shared.ID]map[string]string{}}
	g.svc.EnableReadiness(rd)
	a := g.r.newTenant()
	g.scope(a)
	name := g.asset(a, "www.ready.test", "subdomain", "", "")
	rd.set(a.tenant, "*", covdom.ReadyNoEligibleSensor)

	// Not ready: no run started, no run row, pairs paused with the reason.
	for i := 0; i < 3; i++ {
		if got := g.pass(a); len(got) != 0 {
			t.Fatalf("pass %d started %v while not ready", i, got)
		}
	}
	if n := g.runCount(a); n != 0 {
		t.Fatalf("%d runs exist for a capability that cannot run", n)
	}
	r := g.row(a, name, "resolve.dns")
	if r.State != covdom.StatePaused || r.Reason != covdom.ReadyNoEligibleSensor {
		t.Fatalf("not-ready pair = %s:%s", r.State, r.Reason)
	}
	pausedAt := r.UpdatedAt

	// Same condition on later passes: the row is not written again.
	g.pass(a)
	if r := g.row(a, name, "resolve.dns"); !r.UpdatedAt.Equal(pausedAt) {
		t.Fatal("a paused pair was rewritten while its reason did not change")
	}

	// The condition changes (a sensor enrolled but is offline): the reason
	// follows.
	rd.set(a.tenant, "*", covdom.ReadySensorOffline)
	g.pass(a)
	if r := g.row(a, name, "resolve.dns"); r.State != covdom.StatePaused || r.Reason != covdom.ReadySensorOffline {
		t.Fatalf("pair after the condition changed = %s:%s", r.State, r.Reason)
	}

	// Ready: the pairs resume and run in the same pass.
	rd.set(a.tenant, "*", "")
	if got := g.pass(a)["resolve.dns"]; strings.Join(got, ",") != "www.ready.test" {
		t.Fatalf("resumed batch = %v", got)
	}
	if r := g.row(a, name, "resolve.dns"); r.State != covdom.StateQueued || r.Reason != "" {
		t.Fatalf("resumed pair = %s:%s", r.State, r.Reason)
	}
}

// A covered pair within its cadence is not paused (it is covered); one past
// its cadence is.
func TestAssetCoverageReadiness_PausesOnlyPairsWhoseTimeHasCome(t *testing.T) {
	g := newCycleRig(t)
	rd := &fakeReadiness{reasons: map[shared.ID]map[string]string{}}
	g.svc.EnableReadiness(rd)
	a := g.r.newTenant()
	g.scope(a)
	fresh := g.asset(a, "fresh.ready.test", "subdomain", "", "")
	stale := g.asset(a, "stale.ready.test", "subdomain", "", "")
	g.pass(a)
	g.complete("resolve.dns")
	g.pass(a)
	g.dueIn(a, stale, "resolve.dns", -time.Minute)

	rd.set(a.tenant, "resolve.dns", covdom.ReadyToolMissing)
	if got := g.pass(a)["resolve.dns"]; len(got) != 0 {
		t.Fatalf("started %v while not ready", got)
	}
	if r := g.row(a, fresh, "resolve.dns"); r.State != covdom.StateCovered {
		t.Fatalf("covered pair within its cadence = %s:%s, want covered", r.State, r.Reason)
	}
	if r := g.row(a, stale, "resolve.dns"); r.State != covdom.StatePaused || r.Reason != covdom.ReadyToolMissing {
		t.Fatalf("covered pair past its cadence = %s:%s, want paused tool_missing", r.State, r.Reason)
	}
}

// No scope entry at all: every capability pauses as no_scope (the gate
// would refuse every target); adding one resumes them.
func TestAssetCoverageReadiness_NoScope(t *testing.T) {
	g := newCycleRig(t)
	a := g.r.newTenant()
	name := g.asset(a, "noscope.ready.test", "subdomain", "", "")
	if got := g.pass(a); len(got) != 0 {
		t.Fatalf("started %v without any scope entry", got)
	}
	if r := g.row(a, name, "resolve.dns"); r.State != covdom.StatePaused || r.Reason != covdom.ReadyNoScope {
		t.Fatalf("pair without scope = %s:%s", r.State, r.Reason)
	}
	g.scope(a)
	if got := g.pass(a)["resolve.dns"]; strings.Join(got, ",") != "noscope.ready.test" {
		t.Fatalf("after adding scope = %v", got)
	}
}

// An expired scope entry is no scope.
func TestAssetCoverageReadiness_ExpiredScopeIsNoScope(t *testing.T) {
	g := newCycleRig(t)
	a := g.r.newTenant()
	g.exec(`INSERT INTO scope_targets (tenant_id, target_type, pattern, expires_at) VALUES ($1, 'domain', '*.test', now() - interval '1 day')`, a.tenant)
	name := g.asset(a, "expired.ready.test", "subdomain", "", "")
	g.pass(a)
	if r := g.row(a, name, "resolve.dns"); r.State != covdom.StatePaused || r.Reason != covdom.ReadyNoScope {
		t.Fatalf("pair with only an expired entry = %s:%s", r.State, r.Reason)
	}
}

// Tenant isolation: tenant b not ready leaves tenant a running; tenant a's
// scope entry does not make tenant b ready.
func TestAssetCoverageReadiness_TenantIsolation(t *testing.T) {
	g := newCycleRig(t)
	rd := &fakeReadiness{reasons: map[shared.ID]map[string]string{}}
	g.svc.EnableReadiness(rd)
	a := g.r.newTenant()
	b := g.r.newTenant()
	g.scope(a)
	aName := g.asset(a, "a.ready.test", "subdomain", "", "")
	bName := g.asset(b, "b.ready.test", "subdomain", "", "")
	rd.set(b.tenant, "*", covdom.ReadyNoEligibleSensor)

	if got := g.pass(b); len(got) != 0 {
		t.Fatalf("tenant b started %v", got)
	}
	if r := g.row(b, bName, "resolve.dns"); r.State != covdom.StatePaused || r.Reason != covdom.ReadyNoScope {
		// b has no scope entry of its own: a's entry must not count.
		t.Fatalf("tenant b pair = %s:%s, want paused no_scope", r.State, r.Reason)
	}
	if got := g.pass(a)["resolve.dns"]; strings.Join(got, ",") != "a.ready.test" {
		t.Fatalf("tenant a batch = %v", got)
	}
	if r := g.row(a, aName, "resolve.dns"); r.State != covdom.StateQueued {
		t.Fatalf("tenant a pair = %s", r.State)
	}
	if r := g.row(b, bName, "resolve.dns"); r.State != covdom.StatePaused {
		t.Fatalf("tenant a's pass resumed tenant b: %s", r.State)
	}
}
