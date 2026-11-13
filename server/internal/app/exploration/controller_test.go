package exploration

import (
	"context"
	"testing"
	"time"

	scanapp "github.com/openctemio/openctem/server/internal/app/scan"
	"github.com/openctemio/openctem/server/pkg/domain/asset"
	"github.com/openctemio/openctem/server/pkg/domain/exploration"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/logger"
)

type ctlStore struct {
	subjects   map[shared.ID]exploration.LeadSubject // by asset id (tenant checked via tenantOf)
	tenantOf   map[shared.ID]shared.ID
	runs       map[shared.ID]exploration.RunFacts
	findings   map[shared.ID][]exploration.FindingYield // by run
	liveness   map[shared.ID]string
	checkedAt  *time.Time
	dispatches int
}

func (s *ctlStore) Tenants(context.Context) ([]shared.ID, error) { return nil, nil }
func (s *ctlStore) Subjects(_ context.Context, t shared.ID, ids []shared.ID) (map[shared.ID]exploration.LeadSubject, error) {
	out := map[shared.ID]exploration.LeadSubject{}
	for _, id := range ids {
		if subj, ok := s.subjects[id]; ok && s.tenantOf[id] == t {
			out[id] = subj
		}
	}
	return out, nil
}
func (s *ctlStore) Cells(context.Context, shared.ID) (map[string]exploration.CellStats, error) {
	return map[string]exploration.CellStats{}, nil
}
func (s *ctlStore) ToolMeanMs(context.Context, shared.ID, []string) (map[string]float64, error) {
	return map[string]float64{}, nil
}
func (s *ctlStore) DispatchesSince(context.Context, shared.ID, time.Time) (int, error) {
	return s.dispatches, nil
}
func (s *ctlStore) Runs(_ context.Context, _ shared.ID, ids []shared.ID) (map[shared.ID]exploration.RunFacts, error) {
	out := map[shared.ID]exploration.RunFacts{}
	for _, id := range ids {
		if r, ok := s.runs[id]; ok {
			out[id] = r
		}
	}
	return out, nil
}
func (s *ctlStore) RunFindings(_ context.Context, _, run, _ shared.ID) ([]exploration.FindingYield, error) {
	return s.findings[run], nil
}
func (s *ctlStore) Liveness(_ context.Context, _, a shared.ID) (string, *time.Time, error) {
	return s.liveness[a], s.checkedAt, nil
}
func (s *ctlStore) MatchState(context.Context, shared.ID, []shared.ID) (exploration.MatchState, error) {
	return exploration.MatchState{}, nil
}

type fakeStarter struct {
	calls   []scanapp.CoverageInput
	refuse  string
	err     error
	nextRun shared.ID
}

func (f *fakeStarter) StartCoverage(_ context.Context, in scanapp.CoverageInput) (*scanapp.CoverageResult, error) {
	f.calls = append(f.calls, in)
	if f.err != nil {
		return nil, f.err
	}
	if f.refuse != "" {
		return &scanapp.CoverageResult{Refused: []scanapp.RefusedTarget{{Target: in.Targets[0], Code: f.refuse}}}, nil
	}
	f.nextRun = shared.NewID()
	id := f.nextRun
	return &scanapp.CoverageResult{RunID: &id, Tool: "nuclei", Kept: in.Targets}, nil
}

type fakeLedger struct {
	attempts int
	queued   []shared.ID
}

func (l *fakeLedger) AttemptsSince(context.Context, shared.ID, time.Time) (int, error) {
	return l.attempts, nil
}
func (l *fakeLedger) MarkQueued(_ context.Context, _ shared.ID, _ string, ids []shared.ID, _ shared.ID, _ string) error {
	l.queued = append(l.queued, ids...)
	return nil
}

type harness struct {
	tenant  shared.ID
	repo    *memRepo
	store   *ctlStore
	starter *fakeStarter
	ledger  *fakeLedger
	audit   *memAudit
	c       *Controller
	now     time.Time
}

func newHarness(t *testing.T, auto bool) *harness {
	t.Helper()
	h := &harness{tenant: shared.NewID(), repo: newMemRepo(), starter: &fakeStarter{}, ledger: &fakeLedger{}, audit: &memAudit{},
		store: &ctlStore{subjects: map[shared.ID]exploration.LeadSubject{}, tenantOf: map[shared.ID]shared.ID{},
			runs: map[shared.ID]exploration.RunFacts{}, findings: map[shared.ID][]exploration.FindingYield{}, liveness: map[shared.ID]string{}},
		now: time.Date(2026, 11, 8, 12, 0, 0, 0, time.UTC)}
	h.c = NewController(h.repo, h.store, nil, h.starter, h.ledger, fixedSwitch{on: auto}, h.audit, logger.NewNop(),
		ControllerConfig{DailyBudget: 100})
	h.c.now = func() time.Time { return h.now }
	return h
}

// subject registers an asset of the tenant and opens a lead on it.
func (h *harness) lead(t *testing.T, typ, capability string, at asset.AssetType, auto bool) (*exploration.Lead, exploration.LeadSubject) {
	t.Helper()
	id := shared.NewID()
	s := exploration.LeadSubject{ID: id, Name: "app-" + id.String()[:8] + ".example.com", Type: at}
	h.store.subjects[id], h.store.tenantOf[id] = s, h.tenant
	ex, _ := h.repo.EnsureContinuous(context.Background(), h.tenant)
	lt, _ := exploration.LookupLeadType(typ)
	l, err := exploration.NewLead(exploration.NewLeadInput{TenantID: h.tenant, ExplorationID: ex, Type: typ,
		Action: exploration.Action{Capability: capability}, SubjectAssetID: &id, ReasonCode: lt.Reasons[0],
		Origin: exploration.OriginRule, OriginRef: lt.RuleRef(), AutoActive: auto})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.repo.OpenLead(context.Background(), l, nil); err != nil {
		t.Fatal(err)
	}
	return l, s
}

func (h *harness) state(t *testing.T, id shared.ID) *exploration.Lead {
	t.Helper()
	l, err := h.repo.GetLead(context.Background(), h.tenant, id, nil)
	if err != nil {
		t.Fatal(err)
	}
	return l
}

func TestController_DispatchesTheSubjectOnlyThroughTheCoveragePath(t *testing.T) {
	h := newHarness(t, true)
	l, s := h.lead(t, "dns.takeover_check", "check.takeover", asset.AssetTypeSubdomain, true)
	if _, err := h.c.RunTenant(context.Background(), h.tenant); err != nil {
		t.Fatal(err)
	}
	if len(h.starter.calls) != 1 {
		t.Fatalf("starts = %d", len(h.starter.calls))
	}
	in := h.starter.calls[0]
	if in.TenantID != h.tenant || in.Capability != "check.takeover" || len(in.Targets) != 1 || in.Targets[0] != s.Name {
		t.Fatalf("started %+v, want the subject's own name in the lead's tenant", in)
	}
	got := h.state(t, l.ID)
	if got.State != exploration.StateRunning || got.Attempts != 1 {
		t.Fatalf("state %s attempts %d", got.State, got.Attempts)
	}
	links, _ := h.repo.Links(context.Background(), h.tenant, l.ID)
	if len(links) != 1 || links[0].Rel != exploration.RelDispatchedAs || *links[0].EndID != h.starter.nextRun {
		t.Fatalf("links %+v", links)
	}
	if len(h.ledger.queued) != 1 || h.ledger.queued[0] != s.ID {
		t.Fatal("the ledger pair was not marked on the run")
	}
	// A running lead is never dispatched again.
	if _, err := h.c.RunTenant(context.Background(), h.tenant); err != nil {
		t.Fatal(err)
	}
	if len(h.starter.calls) != 1 {
		t.Fatalf("a running lead was dispatched again (%d starts)", len(h.starter.calls))
	}
}

// A target the dispatch gate refuses (out of scope) never runs: the lead is
// blocked with the gate's code and rechecked later.
func TestController_OutOfScopeRefusedAtDispatch(t *testing.T) {
	h := newHarness(t, true)
	h.starter.refuse = "out_of_scope"
	l, _ := h.lead(t, "dns.takeover_check", "check.takeover", asset.AssetTypeSubdomain, true)
	if _, err := h.c.RunTenant(context.Background(), h.tenant); err != nil {
		t.Fatal(err)
	}
	got := h.state(t, l.ID)
	if got.State != exploration.StateBlocked || got.BlockedReason != "out_of_scope" || got.Attempts != 0 {
		t.Fatalf("state %s reason %q attempts %d", got.State, got.BlockedReason, got.Attempts)
	}
	if links, _ := h.repo.Links(context.Background(), h.tenant, l.ID); len(links) != 0 {
		t.Fatal("a refused lead recorded a dispatch")
	}
	// Before the recheck time nothing happens; after it the lead reopens and
	// the gate decides again.
	h.c.RunTenant(context.Background(), h.tenant) //nolint:errcheck // state is checked below
	if len(h.starter.calls) != 1 {
		t.Fatalf("rechecked too early: %d starts", len(h.starter.calls))
	}
	h.now = h.now.Add(DefaultBlockedRecheck + time.Minute)
	h.c.RunTenant(context.Background(), h.tenant) //nolint:errcheck // state is checked below
	if len(h.starter.calls) != 2 || h.state(t, l.ID).State != exploration.StateBlocked {
		t.Fatalf("recheck: %d starts, state %s", len(h.starter.calls), h.state(t, l.ID).State)
	}
}

func TestController_GateErrorBlocks(t *testing.T) {
	h := newHarness(t, true)
	h.starter.err = shared.NewDomainError("SCOPE_NO_ENTRY", "no scope entry", shared.ErrValidation)
	l, _ := h.lead(t, "asset.gone_with_findings", "resolve.dns", asset.AssetTypeSubdomain, true)
	h.c.RunTenant(context.Background(), h.tenant) //nolint:errcheck // state is checked below
	if got := h.state(t, l.ID); got.State != exploration.StateBlocked || got.BlockedReason != "SCOPE_NO_ENTRY" {
		t.Fatalf("state %s reason %q", got.State, got.BlockedReason)
	}
}

// An active step waits for a person while automatic coverage is off; an
// intrusive one never runs as the system.
func TestController_ApprovalTiersAtDispatch(t *testing.T) {
	h := newHarness(t, false)
	active, _ := h.lead(t, "version.confirm", "probe.http", asset.AssetTypeHost, true) // opened while auto was on
	passive, _ := h.lead(t, "asset.gone_with_findings", "resolve.dns", asset.AssetTypeSubdomain, false)
	h.c.RunTenant(context.Background(), h.tenant) //nolint:errcheck // state is checked below
	if got := h.state(t, active.ID); got.State != exploration.StateAwaitingApproval {
		t.Fatalf("active lead with auto coverage off: %s", got.State)
	}
	if got := h.state(t, passive.ID); got.State != exploration.StateRunning {
		t.Fatalf("passive lead: %s", got.State)
	}
	for _, in := range h.starter.calls {
		if in.Capability == "probe.http" {
			t.Fatal("an active step ran without approval")
		}
	}

	// Intrusive: forced onto the frontier, it is still never started.
	h2 := newHarness(t, true)
	l, _ := h2.lead(t, "version.confirm", "probe.http", asset.AssetTypeHost, true)
	stored := h2.repo.leads[l.ID]
	stored.Tier = 2
	h2.c.RunTenant(context.Background(), h2.tenant) //nolint:errcheck // state is checked below
	if len(h2.starter.calls) != 0 || h2.state(t, l.ID).BlockedReason != BlockedIntrusive {
		t.Fatalf("intrusive lead: %d starts, state %s", len(h2.starter.calls), h2.state(t, l.ID).State)
	}
}

func TestController_BudgetAndRunningCaps(t *testing.T) {
	h := newHarness(t, true)
	h.ledger.attempts = 99 // the coverage ledger used almost all of the day's budget
	h.store.dispatches = 1
	h.lead(t, "dns.takeover_check", "check.takeover", asset.AssetTypeSubdomain, true)
	h.c.RunTenant(context.Background(), h.tenant) //nolint:errcheck // starts are checked below
	if len(h.starter.calls) != 0 {
		t.Fatal("dispatched past the coverage daily budget")
	}
	h2 := newHarness(t, true)
	for i := 0; i < DefaultMaxRunning+3; i++ {
		h2.lead(t, "dns.takeover_check", "check.takeover", asset.AssetTypeSubdomain, true)
	}
	h2.c.RunTenant(context.Background(), h2.tenant) //nolint:errcheck // starts are checked below
	if len(h2.starter.calls) != DefaultMaxRunning {
		t.Fatalf("started %d, want the running cap %d", len(h2.starter.calls), DefaultMaxRunning)
	}
}

func TestController_BusyCapabilityKeepsLeadOpen(t *testing.T) {
	h := newHarness(t, true)
	h.starter.err = scanapp.ErrCoverageBusy
	l, _ := h.lead(t, "dns.takeover_check", "check.takeover", asset.AssetTypeSubdomain, true)
	h.c.RunTenant(context.Background(), h.tenant) //nolint:errcheck // state is checked below
	if got := h.state(t, l.ID); got.State != exploration.StateOpen || got.Attempts != 0 {
		t.Fatalf("busy: %s attempts %d", got.State, got.Attempts)
	}
}

func TestController_SettleByFinding(t *testing.T) {
	h := newHarness(t, true)
	found, _ := h.lead(t, "dns.takeover_check", "check.takeover", asset.AssetTypeSubdomain, true)
	h.c.RunTenant(context.Background(), h.tenant) //nolint:errcheck // states are checked below
	run1 := h.starter.nextRun
	h.store.runs[run1] = exploration.RunFacts{Status: "running", CreatedAt: h.now}
	nothing, _ := h.lead(t, "dns.takeover_check", "check.takeover", asset.AssetTypeSubdomain, true)
	h.c.RunTenant(context.Background(), h.tenant) //nolint:errcheck // states are checked below
	run2 := h.starter.nextRun
	fid := shared.NewID()
	h.store.findings[run1] = []exploration.FindingYield{{ID: fid, Created: true}}
	h.store.runs[run1] = exploration.RunFacts{Status: "completed", CreatedAt: h.now}
	h.store.runs[run2] = exploration.RunFacts{Status: "completed", CreatedAt: h.now}
	h.c.RunTenant(context.Background(), h.tenant) //nolint:errcheck // states are checked below

	if got := h.state(t, found.ID); got.State != exploration.StateDone {
		t.Fatalf("finding reported: %s", got.State)
	}
	if got := h.state(t, nothing.ID); got.State != exploration.StateRefuted {
		t.Fatalf("nothing found: %s", got.State)
	}
	vs, _ := h.repo.Verdicts(context.Background(), h.tenant, found.ID)
	if len(vs) != 1 || vs[0].Verdict != exploration.VerdictProven || vs[0].Tier != exploration.TierDeterministic {
		t.Fatalf("verdicts %+v", vs)
	}
	links, _ := h.repo.Links(context.Background(), h.tenant, found.ID)
	var yielded bool
	for _, k := range links {
		yielded = yielded || (k.Rel == exploration.RelYields && k.EndKind == exploration.EndFinding && *k.EndID == fid && k.Effect == exploration.EffectCreated)
	}
	if !yielded {
		t.Fatalf("no yields link to the finding: %+v", links)
	}
	nl, _ := h.repo.Links(context.Background(), h.tenant, nothing.ID)
	var notFound bool
	for _, k := range nl {
		notFound = notFound || (k.Rel == exploration.RelYields && k.Effect == exploration.EffectNotFound)
	}
	if !notFound {
		t.Fatal("\"nothing found\" was not recorded as a result")
	}
}

// A failed run is inconclusive: the lead waits and is retried until its
// attempts run out, then it is exhausted.
func TestController_FailedRunsExhaust(t *testing.T) {
	h := newHarness(t, true)
	l, _ := h.lead(t, "dns.takeover_check", "check.takeover", asset.AssetTypeSubdomain, true)
	lt, _ := exploration.LookupLeadType("dns.takeover_check")
	for i := 0; i < lt.MaxAttempts; i++ {
		h.c.RunTenant(context.Background(), h.tenant) //nolint:errcheck // states are checked below
		h.store.runs[h.starter.nextRun] = exploration.RunFacts{Status: "failed", CreatedAt: h.now}
		h.c.RunTenant(context.Background(), h.tenant) //nolint:errcheck // states are checked below
		h.now = h.now.Add(DefaultRefusalRetry + time.Minute)
	}
	if got := h.state(t, l.ID); got.State != exploration.StateExhausted || got.Attempts != lt.MaxAttempts {
		t.Fatalf("state %s attempts %d", got.State, got.Attempts)
	}
	if len(h.starter.calls) != lt.MaxAttempts {
		t.Fatalf("starts %d", len(h.starter.calls))
	}
}

func TestController_SettleByLiveness(t *testing.T) {
	h := newHarness(t, true)
	l, s := h.lead(t, "asset.gone_with_findings", "resolve.dns", asset.AssetTypeSubdomain, true)
	h.c.RunTenant(context.Background(), h.tenant) //nolint:errcheck // states are checked below
	h.store.runs[h.starter.nextRun] = exploration.RunFacts{Status: "completed", CreatedAt: h.now}
	checked := h.now.Add(time.Minute)
	h.store.checkedAt, h.store.liveness[s.ID] = &checked, "alive"
	h.c.RunTenant(context.Background(), h.tenant) //nolint:errcheck // states are checked below
	if got := h.state(t, l.ID); got.State != exploration.StateRefuted {
		t.Fatalf("an asset that answers is not gone: %s", got.State)
	}
}

// A lead whose subject was removed or archived is superseded, never run; a
// pass for one tenant never touches another tenant's leads.
func TestController_SupersedeAndTenantBound(t *testing.T) {
	h := newHarness(t, true)
	l, s := h.lead(t, "dns.takeover_check", "check.takeover", asset.AssetTypeSubdomain, true)
	s.Archived = true
	h.store.subjects[s.ID] = s
	other := shared.NewID()
	h.c.RunTenant(context.Background(), other) //nolint:errcheck // states are checked below
	if h.state(t, l.ID).State != exploration.StateOpen || len(h.starter.calls) != 0 {
		t.Fatal("another tenant's pass touched this tenant's lead")
	}
	h.c.RunTenant(context.Background(), h.tenant) //nolint:errcheck // states are checked below
	if got := h.state(t, l.ID); got.State != exploration.StateSuperseded || len(h.starter.calls) != 0 {
		t.Fatalf("archived subject: %s, %d starts", got.State, len(h.starter.calls))
	}
}
