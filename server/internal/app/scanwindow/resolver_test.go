package scanwindow

import (
	"context"
	"errors"
	"testing"
	"time"

	bp "github.com/openctemio/openctem/api/pkg/domain/bountyprogram"
	swdom "github.com/openctemio/openctem/api/pkg/domain/scanwindow"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

var mon10 = time.Date(2026, 10, 5, 10, 0, 0, 0, time.UTC) // Monday

type policyList struct {
	ps  []*swdom.Policy
	err error
}

func (l policyList) List(_ context.Context, _ shared.ID, _ swdom.Filter) ([]*swdom.Policy, error) {
	return l.ps, l.err
}

type assetMap map[string][]swdom.TargetAsset

func (m assetMap) MatchTargetAssets(_ context.Context, _ shared.ID, targets []string) (map[string][]swdom.TargetAsset, error) {
	out := map[string][]swdom.TargetAsset{}
	for _, t := range targets {
		out[t] = m[t]
	}
	return out, nil
}

func policy(t *testing.T, tenant shared.ID, name string, kind swdom.Kind, sel swdom.Selector) *swdom.Policy {
	t.Helper()
	p, err := swdom.NewPolicy(tenant, swdom.Spec{Name: name, Kind: kind, MinTier: 1, Timezone: "UTC", Enabled: true,
		Selector: sel, Slots: []swdom.Slot{{Days: []int{6}, Start: "09:00", End: "17:00"}}}, nil, mon10)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// Every asset dimension, AND across dimensions, any-of within, tags
// case-insensitive; a target that is no asset matches no asset dimension.
func TestSnapshot_AssetSelectors(t *testing.T) {
	tenant := shared.NewID()
	g, bu := shared.NewID().String(), shared.NewID().String()
	prod := policy(t, tenant, "prod critical", swdom.KindAllow, swdom.Selector{Tags: []string{"PROD"}, Criticalities: []string{"critical"}})
	group := policy(t, tenant, "group", swdom.KindAllow, swdom.Selector{AssetGroupIDs: []string{g}, AssetTypes: []string{"domain", "host"}})
	unit := policy(t, tenant, "unit", swdom.KindAllow, swdom.Selector{BusinessUnitIDs: []string{bu}})
	everything := policy(t, tenant, "everything", swdom.KindBlackout, swdom.Selector{})
	assets := assetMap{
		"api.example.com": {{Name: "api.example.com", Type: "domain", Criticality: "critical", Tags: []string{"prod"}, GroupIDs: []string{g}}},
		"10.0.0.0/30":     {{Name: "10.0.0.1", Type: "ip_address", Criticality: "low"}, {Name: "10.0.0.2", Type: "ip_address", Criticality: "critical", Tags: []string{"prod"}, BusinessUnitIDs: []string{bu}}},
		"dev.example.com": {{Name: "dev.example.com", Type: "domain", Criticality: "critical", Tags: []string{"dev"}}},
	}
	r := NewResolver(policyList{ps: []*swdom.Policy{prod, group, unit, everything}}, nil)
	r.SetAssets(assets)
	snap, err := r.Load(context.Background(), tenant, []string{"api.example.com", "10.0.0.0/30", "dev.example.com", "unknown.example.com"}, mon10)
	if err != nil {
		t.Fatal(err)
	}
	names := func(target string) map[string]bool {
		out := map[string]bool{}
		for _, s := range snap.SourcesFor(target, nil) {
			out[s.Name] = true
		}
		return out
	}
	if n := names("api.example.com"); !n["prod critical"] || !n["group"] || n["unit"] || !n["everything"] {
		t.Errorf("api.example.com governed by %v", n)
	}
	// A CIDR carries the restrictions of every asset in it.
	if n := names("10.0.0.0/30"); !n["prod critical"] || !n["unit"] || n["group"] {
		t.Errorf("10.0.0.0/30 governed by %v", n)
	}
	if n := names("dev.example.com"); n["prod critical"] || !n["everything"] {
		t.Errorf("dev.example.com governed by %v", n)
	}
	if n := names("unknown.example.com"); len(n) != 1 || !n["everything"] {
		t.Errorf("an unknown target is governed only by selector-less policies, got %v", n)
	}
}

// The resolver never applies another tenant's policy, even if a store
// returned one; a policy selecting assets without a matcher fails closed.
func TestResolver_TenantIsolationAndFailClosed(t *testing.T) {
	tenant := shared.NewID()
	foreign := policy(t, shared.NewID(), "foreign", swdom.KindBlackout, swdom.Selector{})
	snap, err := NewResolver(policyList{ps: []*swdom.Policy{foreign}}, nil).Load(context.Background(), tenant, []string{"a.example"}, mon10)
	if err != nil || !snap.Empty() {
		t.Fatalf("foreign policy applied: empty=%v err=%v", snap.Empty(), err)
	}
	tagged := policy(t, tenant, "tagged", swdom.KindAllow, swdom.Selector{Tags: []string{"x"}})
	if _, err := NewResolver(policyList{ps: []*swdom.Policy{tagged}}, nil).Load(context.Background(), tenant, []string{"a.example"}, mon10); err == nil {
		t.Fatal("an asset selector without a matcher must fail closed")
	}
	if _, err := NewResolver(policyList{err: errors.New("db down")}, nil).Load(context.Background(), tenant, []string{"a.example"}, mon10); err == nil {
		t.Fatal("a store error must be returned")
	}
}

// Zone, scope entry and program dimensions; program testing windows are a
// source no override suspends.
func TestSnapshot_ScopeZoneAndPrograms(t *testing.T) {
	tenant := shared.NewID()
	zone, entry, prog := shared.NewID(), shared.NewID().String(), shared.NewID()
	zonePol := policy(t, tenant, "zone", swdom.KindBlackout, swdom.Selector{ScanZoneIDs: []string{zone.String()}})
	entryPol := policy(t, tenant, "entry", swdom.KindBlackout, swdom.Selector{ScopeTargetIDs: []string{entry}})
	progPol := policy(t, tenant, "program blackout", swdom.KindBlackout, swdom.Selector{ProgramIDs: []string{prog.String()}})
	program := &bp.Program{ID: prog, TenantID: tenant, Name: "Acme VDP", Rules: bp.Rules{RateLimitRPS: 3,
		TestingWindows: []bp.TestingWindow{{Days: []string{"sat"}, Start: "09:00", End: "17:00", Timezone: "Asia/Ho_Chi_Minh"}}}}
	snap := &Snapshot{
		now:      mon10,
		policies: []*swdom.Policy{zonePol, entryPol, progPol},
		sources: map[shared.ID]swdom.Source{
			zonePol.ID: swdom.PolicySource(zonePol), entryPol.ID: swdom.PolicySource(entryPol), progPol.ID: swdom.PolicySource(progPol),
		},
		entries:  map[string][]string{"in.example": {entry}},
		programs: map[string][]string{"bounty.example": {prog.String()}},
		progSrc:  map[string]swdom.Source{prog.String(): ProgramSource(program)},
	}
	has := func(srcs []swdom.Source, name string) bool {
		for _, s := range srcs {
			if s.Name == name {
				return true
			}
		}
		return false
	}
	if s := snap.SourcesFor("x.example", &zone); !has(s, "zone") || has(s, "entry") {
		t.Errorf("zone selector: %v", s)
	}
	if s := snap.SourcesFor("x.example", nil); has(s, "zone") {
		t.Error("a zone policy applied to unzoned work")
	}
	if s := snap.SourcesFor("in.example", nil); !has(s, "entry") {
		t.Error("scope entry selector did not match")
	}
	s := snap.SourcesFor("bounty.example", nil)
	if !has(s, "program blackout") || !has(s, "Acme VDP") {
		t.Fatalf("program target sources: %v", s)
	}
	// Overrides suspend the organization's policies, never the program.
	o, _ := swdom.NewOverride(tenant, nil, "incident 4711 needs a rescan", time.Hour, nil, mon10.Add(-time.Minute))
	snap.overrides = []*swdom.Override{o}
	s = snap.SourcesFor("bounty.example", nil)
	if has(s, "program blackout") || !has(s, "Acme VDP") {
		t.Fatalf("override result: %v", s)
	}
	d := snap.Decide([]string{"bounty.example"}, nil, 0)
	if d.Open || d.Blocking[0].Origin != swdom.OriginProgram {
		t.Fatalf("program window must still hold passive work outside its window: %+v", d)
	}
}

// Program testing windows evaluate as RFC-065 §12 enforced them: days and
// HH:MM in the window's zone, end exclusive; an unknown zone never opens.
func TestProgramSource(t *testing.T) {
	p := &bp.Program{ID: shared.NewID(), Name: "Acme", Rules: bp.Rules{TestingWindows: []bp.TestingWindow{
		{Days: []string{"mon"}, Start: "09:00", End: "17:00", Timezone: "Asia/Ho_Chi_Minh"}, // UTC+7
	}}}
	src := ProgramSource(p)
	if src.Overridable || src.Origin != swdom.OriginProgram || src.MinTier != swdom.TierAll || src.GraceMinutes != 0 {
		t.Fatalf("program source = %+v", src)
	}
	cases := []struct {
		at   string
		open bool
	}{
		{"2026-10-05T02:00:00Z", true},  // Mon 09:00 local
		{"2026-10-05T01:59:00Z", false}, // Mon 08:59 local
		{"2026-10-05T09:59:00Z", true},  // Mon 16:59 local
		{"2026-10-05T10:00:00Z", false}, // Mon 17:00 local: end is exclusive
		{"2026-10-06T03:00:00Z", false}, // Tue local
		{"2026-10-04T23:00:00Z", false}, // Mon 06:00 local
	}
	for _, c := range cases {
		at, _ := time.Parse(time.RFC3339, c.at)
		if got := swdom.Decide([]swdom.Source{src}, 0, at).Open; got != c.open {
			t.Errorf("%s: open = %v, want %v", c.at, got, c.open)
		}
	}
	bad := ProgramSource(&bp.Program{ID: shared.NewID(), Rules: bp.Rules{TestingWindows: []bp.TestingWindow{
		{Days: []string{"mon"}, Start: "00:00", End: "23:59", Timezone: "bogus"}}}})
	if !bad.Broken || swdom.Decide([]swdom.Source{bad}, 0, mon10).Open {
		t.Fatal("a window with an unknown zone must never be open")
	}
}
