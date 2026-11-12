package coverage

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	bp "github.com/openctemio/openctem/server/pkg/domain/bountyprogram"
	covdom "github.com/openctemio/openctem/server/pkg/domain/coverage"
	"github.com/openctemio/openctem/server/pkg/domain/edgeaddr"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/domain/tenant"
	"github.com/openctemio/openctem/server/pkg/logger"
)

// pathPlanner records the ledger writes path discovery makes; every other
// method of the planner is left unimplemented (the embedded nil interface).
type pathPlanner struct {
	covdom.Planner
	paused  map[string]string // capability -> reason
	blocked map[shared.ID]string
}

func (p *pathPlanner) PauseForReadiness(_ context.Context, _ shared.ID, capability, reason string, _ time.Duration) (int, error) {
	if p.paused == nil {
		p.paused = map[string]string{}
	}
	p.paused[capability] = reason
	return 1, nil
}

func (p *pathPlanner) MarkBlocked(_ context.Context, _ shared.ID, _ string, reasons map[shared.ID]string, _ time.Duration) error {
	if p.blocked == nil {
		p.blocked = map[shared.ID]string{}
	}
	for id, r := range reasons {
		p.blocked[id] = r
	}
	return nil
}

type fakePathGate struct {
	on      bool
	budget  PathBudget
	fit     int
	refused map[string]string
}

func (g fakePathGate) PathDiscoveryFit(context.Context, shared.ID) (int, error) { return g.fit, nil }

func (g fakePathGate) PathDiscoveryEnabled(context.Context, shared.ID) (bool, error) {
	return g.on, nil
}
func (g fakePathGate) PathDiscoveryBudget(context.Context, shared.ID) (PathBudget, error) {
	return g.budget, nil
}

func (g fakePathGate) PathDiscoveryRefusals(context.Context, shared.ID, []string) (map[string]string, error) {
	return g.refused, nil
}

func pathService(p *pathPlanner) *Service {
	return &Service{planner: p, now: time.Now, logger: logger.NewNop()}
}

// Unwired, path discovery is never planned (fail closed).
func TestPathDiscoveryLimit_UnwiredNeverPlans(t *testing.T) {
	s := pathService(&pathPlanner{})
	if _, stop, err := s.pathDiscoveryLimit(context.Background(), shared.NewID(), 100); err != nil || !stop {
		t.Fatalf("stop %v err %v", stop, err)
	}
}

// The organization's switch off pauses the pairs: never covered.
func TestPathDiscoveryLimit_SwitchOffPauses(t *testing.T) {
	p := &pathPlanner{}
	s := pathService(p)
	s.SetPathDiscovery(fakePathGate{on: false, budget: PathBudget{PerOrigin: 300, Daily: 50000}})
	if _, stop, err := s.pathDiscoveryLimit(context.Background(), shared.NewID(), 100); err != nil || !stop {
		t.Fatalf("stop %v err %v", stop, err)
	}
	if p.paused[covdom.CapabilityEnumerateWebPaths] != covdom.ReadySwitchedOff {
		t.Fatalf("paused %v", p.paused)
	}
}

// The daily request budget bounds the batch; once spent the pairs are
// deferred (paused with budget), never covered.
func TestPathDiscoveryLimit_BudgetDefersNotCovers(t *testing.T) {
	p := &pathPlanner{}
	s := pathService(p)
	s.SetPathDiscovery(fakePathGate{on: true, budget: PathBudget{PerOrigin: 300, Daily: 1000}, fit: 1})
	n, stop, err := s.pathDiscoveryLimit(context.Background(), shared.NewID(), 100)
	if err != nil || stop || n != 1 {
		t.Fatalf("limit %d stop %v err %v, want 1 origin left in the budget", n, stop, err)
	}
	s.SetPathDiscovery(fakePathGate{on: true, budget: PathBudget{PerOrigin: 300, Daily: 1000}, fit: 0})
	if _, stop, err := s.pathDiscoveryLimit(context.Background(), shared.NewID(), 100); err != nil || !stop {
		t.Fatalf("spent budget: stop %v err %v", stop, err)
	}
	if p.paused[covdom.CapabilityEnumerateWebPaths] != covdom.ReadyBudgetSpent {
		t.Fatalf("paused %v, want deferred with budget", p.paused)
	}
}

// Refused targets are blocked with the reason and left out of the batch.
func TestPathDiscoveryRefuse_BlocksWithReason(t *testing.T) {
	p := &pathPlanner{}
	s := pathService(p)
	bounty, edge, ok := shared.NewID(), shared.NewID(), shared.NewID()
	due := []covdom.DueTarget{
		{AssetID: bounty, Name: "https://bounty.example.com", Type: "service", SubType: "http"},
		{AssetID: edge, Name: "https://192.0.2.10", Type: "service", SubType: "http"},
		{AssetID: ok, Name: "https://app.example.com", Type: "service", SubType: "http"},
	}
	s.SetPathDiscovery(fakePathGate{on: true, refused: map[string]string{
		"https://bounty.example.com": ReasonProgramForbidsEnumeration, "https://192.0.2.10": ReasonSharedEdgeAddress}})
	kept, err := s.pathDiscoveryRefuse(context.Background(), shared.NewID(), due)
	if err != nil || len(kept) != 1 || kept[0].AssetID != ok {
		t.Fatalf("kept %+v err %v", kept, err)
	}
	if p.blocked[bounty] != ReasonProgramForbidsEnumeration || p.blocked[edge] != ReasonSharedEdgeAddress {
		t.Fatalf("blocked %v", p.blocked)
	}
}

type fakePrograms struct{ forbid map[string][]string }

func (f fakePrograms) JobRules(_ context.Context, _ shared.ID, targets []string, _ time.Time) (*bp.JobRules, error) {
	if fb, ok := f.forbid[targets[0]]; ok {
		return &bp.JobRules{Programs: []string{"Example program"}, Forbidden: fb}, nil
	}
	return nil, nil
}

type fakeScopeSettings struct{ ss *tenant.ScopeSettings }

func (f fakeScopeSettings) GetScopeSettings(context.Context, string) (*tenant.ScopeSettings, error) {
	return f.ss, nil
}

// SECURITY: a program forbidding brute force or automated scanning refuses
// path discovery on its targets with the reason; another forbidden
// technique does not; an address origin on a shared edge network is
// labeled, a host name behind the same edge is not.
func TestPathDiscoveryPolicy_Refusals(t *testing.T) {
	edge, err := edgeaddr.New(edgeaddr.Dataset{Version: "t", Ranges: []edgeaddr.RangeEntry{
		{Provider: "edge-test", Class: edgeaddr.Edge, Prefixes: []string{"192.0.2.0/24"}}}})
	if err != nil {
		t.Fatal(err)
	}
	pol := PathDiscoveryPolicy{Edge: edge, Programs: fakePrograms{forbid: map[string][]string{
		"https://brute.example.com": {bp.ForbidBruteforce},
		"https://auto.example.com":  {bp.ForbidAutomatedScanning},
		"https://dos.example.com":   {bp.ForbidDoS},
	}}}
	got, err := pol.targetRefusals(context.Background(), shared.NewID(), []string{
		"https://brute.example.com", "https://auto.example.com", "https://dos.example.com",
		"https://192.0.2.10", "https://cdn-fronted.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"https://brute.example.com": ReasonProgramForbidsEnumeration,
		"https://auto.example.com":  ReasonProgramForbidsEnumeration,
		"https://192.0.2.10":        ReasonSharedEdgeAddress,
	}
	if len(got) != len(want) {
		t.Fatalf("refusals %v, want %v", got, want)
	}
	for k, v := range want {
		if got[k] != v {
			t.Fatalf("%s: %q, want %q", k, got[k], v)
		}
	}
}

// The switch defaults to on; an explicit false turns it off; unwired is off.
func TestPathDiscoveryPolicy_Switch(t *testing.T) {
	off := false
	for name, c := range map[string]struct {
		pol  PathDiscoveryPolicy
		want bool
	}{
		"default": {PathDiscoveryPolicy{Settings: fakeScopeSettings{ss: &tenant.ScopeSettings{}}}, true},
		"no row":  {PathDiscoveryPolicy{Settings: fakeScopeSettings{}}, true},
		"off":     {PathDiscoveryPolicy{Settings: fakeScopeSettings{ss: &tenant.ScopeSettings{PathDiscovery: &off}}}, false},
		"unwired": {PathDiscoveryPolicy{}, false},
	} {
		got, err := c.pol.PathDiscoveryEnabled(context.Background(), shared.NewID())
		if err != nil || got != c.want {
			t.Errorf("%s: %v %v, want %v", name, got, err, c.want)
		}
	}
}

// fakeLedger is the path discovery ledger in memory: the facts of origins and
// the claims, with the ledger's own rules (30 day floor per origin, daily
// budget, per-host budget of one run).
type fakeLedger struct {
	facts   map[string]covdom.PathOriginFacts
	claimed map[string]time.Time
	granted map[string]int
	hosts   map[string]string
	runs    map[string]shared.ID
	claims  int
	// undo is what ReleasePathClaim restores, per origin: the row the claim
	// replaced (ok false: none) and the command that claimed.
	undo map[string]fakeUndo
}

type fakeUndo struct {
	command shared.ID
	had     bool
	at      time.Time
	granted int
	host    string
}

func (l *fakeLedger) PathOriginFacts(_ context.Context, _ shared.ID, origins []string) (map[string]covdom.PathOriginFacts, error) {
	out := map[string]covdom.PathOriginFacts{}
	for _, o := range origins {
		if f, ok := l.facts[o]; ok {
			if t, ok := l.claimed[o]; ok {
				f.LastDispatch = t
			}
			out[o] = f
		}
	}
	return out, nil
}

func (l *fakeLedger) PathRequestsGrantedSince(_ context.Context, _ shared.ID, _ time.Time) (int, error) {
	n := 0
	for _, g := range l.granted {
		n += g
	}
	return n, nil
}

func (l *fakeLedger) ClaimPathOrigin(_ context.Context, c covdom.PathClaim) (int, string, error) {
	l.claims++
	origin, host, ok := covdom.PathOrigin(c.Origin)
	if !ok {
		return 0, covdom.ReasonNotAnOrigin, nil
	}
	if t, ok := l.claimed[origin]; ok && time.Since(t) < covdom.PathEvery {
		return 0, covdom.ReasonPathRanRecently, nil
	}
	granted := c.Requested
	spent := 0
	for o, g := range l.granted {
		if o != origin {
			spent += g
		}
	}
	granted = min(granted, c.Daily-spent)
	if granted < covdom.MinPathGrant {
		return 0, covdom.ReasonDailyBudgetSpent, nil
	}
	if c.RunID != nil {
		hostSpent := 0
		for o, g := range l.granted {
			if o != origin && l.hosts[o] == host && l.runs[o] == *c.RunID {
				hostSpent += g
			}
		}
		granted = min(granted, c.PerHost-hostSpent)
		if granted < covdom.MinPathGrant {
			return 0, covdom.ReasonHostBudgetSpent, nil
		}
		l.runs[origin] = *c.RunID
	}
	u := fakeUndo{command: c.CommandID}
	u.at, u.had = l.claimed[origin]
	u.granted, u.host = l.granted[origin], l.hosts[origin]
	if l.undo == nil {
		l.undo = map[string]fakeUndo{}
	}
	l.undo[origin] = u
	l.claimed[origin], l.granted[origin], l.hosts[origin] = time.Now(), granted, host
	return granted, "", nil
}

func (l *fakeLedger) ReleasePathClaim(_ context.Context, _, commandID shared.ID, origins []string) error {
	for o, u := range l.undo {
		if u.command != commandID || (origins != nil && !slices.Contains(origins, o)) {
			continue
		}
		if u.had {
			l.claimed[o], l.granted[o], l.hosts[o] = u.at, u.granted, u.host
		} else {
			delete(l.claimed, o)
			delete(l.granted, o)
			delete(l.hosts, o)
		}
		delete(l.undo, o)
	}
	return nil
}

func (l *fakeLedger) ReleaseEmptyPathClaim(ctx context.Context, tenantID, commandID shared.ID, origins []string) error {
	return l.ReleasePathClaim(ctx, tenantID, commandID, origins)
}

// admit is the guard's two calls in its order: the checks, then the claim.
func admit(p PathDiscoveryPolicy, ctx context.Context, tenantID shared.ID, run *shared.ID, targets []string, requested int) (int, error) {
	if err := p.CheckPathDispatch(ctx, tenantID, targets); err != nil {
		return 0, err
	}
	return p.ClaimPathDispatch(ctx, tenantID, shared.NewID(), run, targets, requested)
}

func newFakeLedger(origins ...string) *fakeLedger {
	l := &fakeLedger{facts: map[string]covdom.PathOriginFacts{}, claimed: map[string]time.Time{},
		granted: map[string]int{}, hosts: map[string]string{}, runs: map[string]shared.ID{}}
	for _, o := range origins {
		_, host, _ := covdom.PathOrigin(o)
		l.facts[o] = covdom.PathOriginFacts{AssetID: shared.NewID(), Host: host, ScopeEntry: true, InventoryChanged: true, EdgeClear: true}
	}
	return l
}

func policyWith(l covdom.PathLedger) PathDiscoveryPolicy {
	return PathDiscoveryPolicy{Settings: fakeScopeSettings{}, Ledger: l, Budget: PathBudget{PerOrigin: 300, Daily: 1000}}
}

// SECURITY: every caller reads the same gate. An origin with no active scope
// entry naming its host, behind an edge that challenged the last probe, with
// nothing new in the inventory, run within 30 days, or no web service of the
// organization at all is refused with the reason; the others pass.
func TestPathDiscoveryRefusals_OriginFacts(t *testing.T) {
	l := newFakeLedger("https://ok.example.com", "https://noscope.example.com", "https://edge.example.com",
		"https://same.example.com", "https://recent.example.com")
	set := func(o string, f func(*covdom.PathOriginFacts)) { v := l.facts[o]; f(&v); l.facts[o] = v }
	set("https://noscope.example.com", func(f *covdom.PathOriginFacts) { f.ScopeEntry = false })
	set("https://edge.example.com", func(f *covdom.PathOriginFacts) { f.EdgeClear = false })
	set("https://same.example.com", func(f *covdom.PathOriginFacts) { f.InventoryChanged = false })
	l.claimed["https://recent.example.com"] = time.Now().Add(-48 * time.Hour)
	got, err := policyWith(l).PathDiscoveryRefusals(context.Background(), shared.NewID(), []string{
		"https://ok.example.com", "https://noscope.example.com", "https://edge.example.com",
		"https://same.example.com", "https://recent.example.com", "https://other-tenant.example.com", "not a url"})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"https://noscope.example.com":      covdom.ReasonNoOriginScopeEntry,
		"https://edge.example.com":         covdom.ReasonEdgeChallenged,
		"https://same.example.com":         covdom.ReasonInventoryUnchanged,
		"https://recent.example.com":       covdom.ReasonPathRanRecently,
		"https://other-tenant.example.com": covdom.ReasonNotAnOrigin,
		"not a url":                        covdom.ReasonNotAnOrigin,
	}
	if len(got) != len(want) {
		t.Fatalf("refusals %v, want %v", got, want)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s: %q, want %q", k, got[k], v)
		}
	}
	// Without a ledger every origin is refused: an error, never a pass.
	if _, err := (PathDiscoveryPolicy{}).PathDiscoveryRefusals(context.Background(), shared.NewID(), []string{"https://ok.example.com"}); err == nil {
		t.Fatal("a policy without a ledger let an origin through")
	}
}

// SECURITY: the dispatch gate. The 300 requests per origin per 30 days hold
// across callers: a second dispatch of the same origin, from the planner or a
// workflow step or a scan, is refused; the switch and the budgets bind too;
// the cap is the platform's, whatever the job asks for.
func TestAdmitPathDispatch(t *testing.T) {
	ctx := context.Background()
	tenantID := shared.NewID()
	l := newFakeLedger("https://a.example.com", "https://b.example.com")
	pol := policyWith(l)

	got, err := admit(pol, ctx, tenantID, nil, []string{"https://a.example.com"}, 99999)
	if err != nil || got != 300 {
		t.Fatalf("granted %d err %v, want the per-origin budget of 300 whatever the job asked for", got, err)
	}
	// The same origin again (another caller, a retry): refused, nothing more spent.
	if _, err := admit(pol, ctx, tenantID, nil, []string{"https://a.example.com"}, 100); err == nil {
		t.Fatal("a second dispatch within 30 days was admitted")
	}
	if l.granted["https://a.example.com"] != 300 {
		t.Fatalf("ledger granted %v", l.granted)
	}
	// A smaller request is honored.
	got, err = admit(pol, ctx, tenantID, nil, []string{"https://b.example.com"}, 120)
	if err != nil || got != 120 {
		t.Fatalf("granted %d err %v, want 120", got, err)
	}

	// The switch off refuses before anything is claimed.
	off := false
	offPol := policyWith(newFakeLedger("https://c.example.com"))
	offPol.Settings = fakeScopeSettings{ss: &tenant.ScopeSettings{PathDiscovery: &off}}
	_, err = admit(offPol, ctx, tenantID, nil, []string{"https://c.example.com"}, 0)
	var de *shared.DomainError
	if !errors.As(err, &de) || de.Code != CodePathDiscoveryOff {
		t.Fatalf("switch off: %v", err)
	}
	if offPol.Ledger.(*fakeLedger).claims != 0 {
		t.Fatal("a refused job was recorded in the ledger")
	}

	// A refused origin (no scope entry) is never claimed.
	l2 := newFakeLedger("https://d.example.com")
	f := l2.facts["https://d.example.com"]
	f.ScopeEntry = false
	l2.facts["https://d.example.com"] = f
	if _, err := admit(policyWith(l2), ctx, tenantID, nil, []string{"https://d.example.com"}, 0); err == nil || l2.claims != 0 {
		t.Fatalf("an origin without a scope entry was admitted (claims %d, err %v)", l2.claims, err)
	}
}

// The organization's daily budget caps the sum of the caps granted, and the
// per-host budget of a run is shared by the run's origins on one host.
func TestAdmitPathDispatch_Budgets(t *testing.T) {
	ctx := context.Background()
	tenantID := shared.NewID()
	l := newFakeLedger("https://a.example.com", "https://a.example.com:8443", "https://b.example.com", "https://c.example.com")
	pol := policyWith(l)
	pol.Budget = PathBudget{PerOrigin: 300, Daily: 700}
	run := shared.NewID()

	if got, err := admit(pol, ctx, tenantID, &run, []string{"https://a.example.com"}, 0); err != nil || got != 300 {
		t.Fatalf("first origin: %d %v", got, err)
	}
	// Another port of the same host in the same run: the host's budget of
	// 300 is spent by the first task.
	_, err := admit(pol, ctx, tenantID, &run, []string{"https://a.example.com:8443"}, 0)
	if err == nil {
		t.Fatal("the host's per-run budget was spent twice")
	}
	if got, err := admit(pol, ctx, tenantID, &run, []string{"https://b.example.com"}, 0); err != nil || got != 300 {
		t.Fatalf("other host: %d %v", got, err)
	}
	// 600 of 700 spent: the next origin gets what is left (100), and the one
	// after that nothing.
	if got, err := admit(pol, ctx, tenantID, &run, []string{"https://c.example.com"}, 0); err != nil || got != 100 {
		t.Fatalf("daily budget left: %d %v, want 100", got, err)
	}
	l.facts["https://d.example.com"] = covdom.PathOriginFacts{AssetID: shared.NewID(), Host: "d.example.com", ScopeEntry: true, InventoryChanged: true, EdgeClear: true}
	if _, err := admit(pol, ctx, tenantID, &run, []string{"https://d.example.com"}, 0); err == nil {
		t.Fatal("the daily budget was exceeded")
	}
}

// The fit is what the daily budget holds at the per-origin cap, counting
// every caller's grants.
func TestPathDiscoveryFit(t *testing.T) {
	l := newFakeLedger()
	l.granted["x"] = 300
	pol := policyWith(l)
	if got, err := pol.PathDiscoveryFit(context.Background(), shared.NewID()); err != nil || got != 2 {
		t.Fatalf("fit %d err %v, want 2", got, err)
	}
}

// SECURITY: a job with several origins claims all of them or none. When a
// later origin is refused, the origins already claimed for the command are
// given back, so no origin is held for 30 days by a job that never ran.
func TestClaimPathDispatch_AllOrNothing(t *testing.T) {
	ctx := context.Background()
	tenantID := shared.NewID()
	l := newFakeLedger("https://a.example.com", "https://b.example.com")
	l.claimed["https://b.example.com"] = time.Now().Add(-time.Hour) // b ran recently
	l.granted["https://b.example.com"] = 50
	pol := policyWith(l)
	cmd := shared.NewID()
	_, err := pol.ClaimPathDispatch(ctx, tenantID, cmd, nil, []string{"https://a.example.com", "https://b.example.com"}, 0)
	var de *shared.DomainError
	if !errors.As(err, &de) || de.Code != CodePathDiscoveryRefused {
		t.Fatalf("a job with a refused origin: %v", err)
	}
	if _, held := l.claimed["https://a.example.com"]; held || l.granted["https://a.example.com"] != 0 {
		t.Fatalf("the origin claimed before the refusal is still held: %v %v", l.claimed, l.granted)
	}
	// b keeps its own earlier row.
	if l.granted["https://b.example.com"] != 50 {
		t.Fatalf("the refused origin's row changed: %v", l.granted)
	}
}

// A release restores the row the claim replaced (or removes it), and touches
// only the command's own claims.
func TestReleasePathDispatch(t *testing.T) {
	ctx := context.Background()
	tenantID := shared.NewID()
	l := newFakeLedger("https://a.example.com", "https://b.example.com")
	old := time.Now().Add(-40 * 24 * time.Hour)
	l.claimed["https://a.example.com"], l.granted["https://a.example.com"], l.hosts["https://a.example.com"] = old, 120, "a.example.com"
	pol := policyWith(l)
	cmd, other := shared.NewID(), shared.NewID()
	if _, err := pol.ClaimPathDispatch(ctx, tenantID, cmd, nil, []string{"https://a.example.com"}, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := pol.ClaimPathDispatch(ctx, tenantID, other, nil, []string{"https://b.example.com"}, 0); err != nil {
		t.Fatal(err)
	}
	if err := pol.ReleasePathDispatch(ctx, tenantID, cmd, nil); err != nil {
		t.Fatal(err)
	}
	if !l.claimed["https://a.example.com"].Equal(old) || l.granted["https://a.example.com"] != 120 {
		t.Fatalf("the previous row was not restored: %v %v", l.claimed, l.granted)
	}
	if _, held := l.claimed["https://b.example.com"]; !held {
		t.Fatal("another command's claim was released")
	}
	if err := pol.ReleasePathDispatch(ctx, tenantID, other, []string{"https://b.example.com"}); err != nil {
		t.Fatal(err)
	}
	if _, held := l.claimed["https://b.example.com"]; held {
		t.Fatal("a claim on an origin without a previous row was not removed")
	}
}
