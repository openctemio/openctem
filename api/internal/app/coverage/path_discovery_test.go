package coverage

import (
	"context"
	"testing"
	"time"

	bp "github.com/openctemio/openctem/api/pkg/domain/bountyprogram"
	covdom "github.com/openctemio/openctem/api/pkg/domain/coverage"
	"github.com/openctemio/openctem/api/pkg/domain/edgeaddr"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/tenant"
	"github.com/openctemio/openctem/api/pkg/logger"
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
	refused map[string]string
}

func (g fakePathGate) PathDiscoveryEnabled(context.Context, shared.ID) (bool, error) {
	return g.on, nil
}
func (g fakePathGate) PathDiscoveryBudget(context.Context, shared.ID) (PathBudget, error) {
	return g.budget, nil
}

func (g fakePathGate) PathDiscoveryRefusals(context.Context, shared.ID, []string) (map[string]string, error) {
	return g.refused, nil
}

type fakeAttempts struct{ n int }

func (f fakeAttempts) CapabilityAttemptsSince(context.Context, shared.ID, string, time.Time) (int, error) {
	return f.n, nil
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
	s.SetPathDiscovery(fakePathGate{on: false, budget: PathBudget{PerOrigin: 300, Daily: 50000}}, fakeAttempts{})
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
	s.SetPathDiscovery(fakePathGate{on: true, budget: PathBudget{PerOrigin: 300, Daily: 1000}}, fakeAttempts{n: 2})
	n, stop, err := s.pathDiscoveryLimit(context.Background(), shared.NewID(), 100)
	if err != nil || stop || n != 1 {
		t.Fatalf("limit %d stop %v err %v, want 1 origin left in the budget", n, stop, err)
	}
	s.SetPathDiscovery(fakePathGate{on: true, budget: PathBudget{PerOrigin: 300, Daily: 1000}}, fakeAttempts{n: 4})
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
		"https://bounty.example.com": ReasonProgramForbidsEnumeration, "https://192.0.2.10": ReasonSharedEdgeAddress}}, fakeAttempts{})
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
	got, err := pol.PathDiscoveryRefusals(context.Background(), shared.NewID(), []string{
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
