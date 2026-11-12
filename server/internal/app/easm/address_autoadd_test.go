package easm

import (
	"context"
	"testing"
	"time"

	"github.com/openctemio/openctem/server/internal/app/scope"
	"github.com/openctemio/openctem/server/pkg/domain/addrowner"
	"github.com/openctemio/openctem/server/pkg/domain/easmseed"
	"github.com/openctemio/openctem/server/pkg/domain/scangov"
	scopedom "github.com/openctemio/openctem/server/pkg/domain/scope"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/domain/tenant"
)

type fakeAutoTargets struct {
	mode  scangov.Mode
	calls []scope.BulkTargetsInput
}

func (f *fakeAutoTargets) CreateTargets(_ context.Context, in scope.BulkTargetsInput) ([]scope.BulkTargetOutcome, error) {
	f.calls = append(f.calls, in)
	tid, _ := shared.IDFromString(in.TenantID)
	out := make([]scope.BulkTargetOutcome, 0, len(in.Items))
	for _, it := range in.Items {
		typ, _ := scopedom.ParseTargetType(it.TargetType)
		t, err := scopedom.NewEntry(tid, typ, it.Pattern, "", "", scopedom.EntryOptions{Now: time.Now()})
		out = append(out, scope.BulkTargetOutcome{Item: it, Target: t, Err: err})
	}
	return out, nil
}

func (f *fakeAutoTargets) ApprovalPolicy(context.Context, string) (scangov.Mode, string) {
	return f.mode, ""
}

type fakeAutoSettings struct{ s tenant.ScopeSettings }

func (f fakeAutoSettings) GetScopeSettings(context.Context, string) (*tenant.ScopeSettings, error) {
	s := f.s
	return &s, nil
}

type fakeAutoLog map[string]bool

func (f fakeAutoLog) Seen(_ context.Context, _ shared.ID, ps []string) (map[string]bool, error) {
	out := map[string]bool{}
	for _, p := range ps {
		if f[p] {
			out[p] = true
		}
	}
	return out, nil
}

func (f fakeAutoLog) Record(_ context.Context, _ shared.ID, ps []string) error {
	for _, p := range ps {
		f[p] = true
	}
	return nil
}

type fakeSeededTenants []shared.ID

func (f fakeSeededTenants) TenantsWithASNSeeds(context.Context, int) ([]shared.ID, error) {
	return f, nil
}

// autoAddFixture: a tenant that declared AS64500 (announcing 203.0.113.0/24)
// and whose names resolve to addresses with every kind of evidence.
func autoAddFixture(now time.Time) *SuggestionService {
	old := now.Add(-30 * 24 * time.Hour)
	at := func(ip string, props map[string]any, first time.Time, names ...string) AddressBehindNames {
		r := addr(ip, props, names...)
		r.FirstSeen = first
		return r
	}
	own := map[string]any{"asn": "AS64500"}
	store := &fakeSuggestionStore{addrs: []AddressBehindNames{
		at("203.0.113.10", nil, old, "a.acme.example"),                                        // own prefix + stable: strong
		at("203.0.113.11", nil, old, "b.acme.example"),                                        // own prefix + stable: strong (same prefix)
		at("198.51.100.20", own, old, "c.acme.example"),                                       // own AS + stable: strong, own address entry
		at("198.51.100.21", own, now.Add(-time.Hour), "d.acme.example"),                       // own AS but brand new: held back
		at("192.0.2.5", nil, old, "e.acme.example"),                                           // nothing known: a person decides
		at("104.16.9.9", own, old, "f.acme.example"),                                          // CDN edge, even with own AS data: never
		at("198.51.100.22", own, old, "g.acme.example", "x.other.example", "y.third.example"), // shared hosting: never
	}}
	cover := coverSet{}
	for _, n := range []string{"a", "b", "c", "d", "e", "f", "g"} {
		cover[n+".acme.example"] = true
	}
	seeds := func(context.Context, shared.ID) (easmseed.Networks, error) {
		return easmseed.Networks{ASNs: map[string]bool{"AS64500": true}, Prefixes: []string{"203.0.113.0/24"}}, nil
	}
	svc := NewSuggestionService(store, cover, nil, nil, seeds)
	svc.SetGuardrails(scopedom.DefaultGuardrails())
	svc.now = func() time.Time { return now }
	return svc
}

func TestAddressAutoAdd_AddsOnlyStrongAddressesThroughTheScopeService(t *testing.T) {
	now := time.Now()
	targets := &fakeAutoTargets{}
	tenantID := shared.NewID()
	a := NewAddressAutoAdd(autoAddFixture(now), targets, fakeAutoSettings{}, fakeSeededTenants{tenantID}, fakeAutoLog{}, nil, nil, nil)
	n, err := a.Run(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 || len(targets.calls) != 1 {
		t.Fatalf("added %d in %d calls, want 2 entries in 1 call", n, len(targets.calls))
	}
	in := targets.calls[0]
	if in.TenantID != tenantID.String() || in.Origin != scopedom.OriginAutoAddress || !in.Actor.Automatic || in.Actor.UserID != "" {
		t.Fatalf("input %+v: must be the tenant's own, origin auto_address, the automatic actor", in)
	}
	got := map[string]string{}
	for _, it := range in.Items {
		got[it.Pattern] = it.TargetType
	}
	want := map[string]string{"203.0.113.0/24": "cidr", "198.51.100.20": "ip_address"}
	if len(got) != len(want) {
		t.Fatalf("items %v, want %v", got, want)
	}
	for p, typ := range want {
		if got[p] != typ {
			t.Fatalf("items %v, want %v", got, want)
		}
	}
}

func TestAddressAutoAdd_FollowsTheSetting(t *testing.T) {
	now := time.Now()
	tenantID := shared.NewID()
	for _, tc := range []struct {
		name string
		mode string
		gov  scangov.Mode
	}{
		{"ask", tenant.AddressAsk, ""},
		{"never", tenant.AddressNever, ""},
		{"strict scan approval stops automatic adds", "", scangov.ModeStrict},
	} {
		targets := &fakeAutoTargets{mode: tc.gov}
		a := NewAddressAutoAdd(autoAddFixture(now), targets, fakeAutoSettings{tenant.ScopeSettings{AddressAutoAdd: tc.mode}},
			fakeSeededTenants{tenantID}, fakeAutoLog{}, nil, nil, nil)
		if n, err := a.Run(context.Background(), nil); err != nil || n != 0 || len(targets.calls) != 0 {
			t.Fatalf("%s: added %d (%d calls) err %v, want nothing", tc.name, n, len(targets.calls), err)
		}
	}
	// A tenant the module guard leaves out is not read.
	targets := &fakeAutoTargets{}
	a := NewAddressAutoAdd(autoAddFixture(now), targets, fakeAutoSettings{}, fakeSeededTenants{tenantID}, fakeAutoLog{}, nil, nil, nil)
	if n, _ := a.Run(context.Background(), func(shared.ID) bool { return true }); n != 0 || len(targets.calls) != 0 {
		t.Fatal("a skipped tenant was read")
	}
}

// One strong address alone in a prefix is its exact entry: a prefix is
// added only when two or more strong addresses fall in it.
func TestPlanAutoAdd_SingleAddressStaysExact(t *testing.T) {
	strong := func(ip, prefix string) SuggestionAddress {
		return SuggestionAddress{Address: ip, Prefix: prefix, Ownership: &addrownerHigh}
	}
	plan := PlanAutoAdd(&SuggestionCard{Addresses: []SuggestionAddress{strong("203.0.113.10", "203.0.113.0/24")}})
	if len(plan) != 1 || plan[0].Item.TargetType != "ip_address" || plan[0].Item.Pattern != "203.0.113.10" {
		t.Fatalf("plan %+v", plan)
	}
	if PlanAutoAdd(nil) != nil {
		t.Fatal("nil card")
	}
}

var addrownerHigh = addrowner.Assessment{Band: addrowner.High}

// A pattern is written once: after a person removes the entry, the next run
// does not add it again, and the addresses of a removed prefix are not added
// one by one instead.
func TestAddressAutoAdd_RemovalSticks(t *testing.T) {
	now := time.Now()
	tenantID := shared.NewID()
	log := fakeAutoLog{}
	targets := &fakeAutoTargets{}
	a := NewAddressAutoAdd(autoAddFixture(now), targets, fakeAutoSettings{}, fakeSeededTenants{tenantID}, log, nil, nil, nil)
	if n, err := a.Run(context.Background(), nil); err != nil || n != 2 {
		t.Fatalf("first run: %d %v", n, err)
	}
	if !log["203.0.113.0/24"] || !log["198.51.100.20"] {
		t.Fatalf("written patterns not remembered: %v", log)
	}
	// The entries are gone (a person removed them): the card offers the
	// same addresses again, the log keeps them out.
	if n, err := a.Run(context.Background(), nil); err != nil || n != 0 || len(targets.calls) != 1 {
		t.Fatalf("second run added %d (%d calls) err %v, want nothing", n, len(targets.calls), err)
	}
}
