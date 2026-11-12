package easm

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/attribution"
	"github.com/openctemio/openctem/api/pkg/domain/easmseed"
	scopedom "github.com/openctemio/openctem/api/pkg/domain/scope"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// tenantStore answers only its own tenant (another tenant has no rows).
type tenantStore struct {
	tenant shared.ID
	fakeSuggestionStore
}

func (s *tenantStore) AddressesBehindNames(ctx context.Context, t shared.ID, v *shared.DataScope, n int) ([]AddressBehindNames, error) {
	if !t.Equals(s.tenant) {
		return nil, nil
	}
	return s.fakeSuggestionStore.AddressesBehindNames(ctx, t, v, n)
}

type fakeDecisionReview struct {
	calls [][]string
	state attribution.State
}

func (f *fakeDecisionReview) DecideAs(_ context.Context, _ shared.ID, ids []string, st attribution.State, _ ScopeActor) (*DecisionResult, error) {
	f.calls = append(f.calls, ids)
	f.state = st
	out := &DecisionResult{}
	for _, id := range ids {
		out.Decided = append(out.Decided, Decision{AssetID: id, To: string(st)})
	}
	return out, nil
}

type fakeDecisionSeeds struct{ created []string }

func (f *fakeDecisionSeeds) Create(_ context.Context, _ shared.ID, _ *shared.ID, kind easmseed.Kind, value, _ string) (*SeedView, error) {
	f.created = append(f.created, string(kind)+":"+value)
	return &SeedView{Seed: easmseed.Seed{ID: "seed-1", Kind: kind, Value: value}}, nil
}

type fakeDeclined struct {
	rows       []easmseed.Declined
	undeclined []string
}

func (f *fakeDeclined) ListDeclined(context.Context, shared.ID) ([]easmseed.Declined, error) {
	return f.rows, nil
}

func (f *fakeDeclined) Decline(_ context.Context, _ shared.ID, kind easmseed.Kind, value, label string, _ *shared.ID) (*easmseed.Declined, error) {
	d := easmseed.Declined{ID: fmt.Sprintf("dec-%d", len(f.rows)+1), Kind: kind, Value: value, Label: label}
	f.rows = append(f.rows, d)
	return &d, nil
}

func (f *fakeDeclined) Undecline(_ context.Context, _ shared.ID, id string) (*easmseed.Declined, error) {
	for i, d := range f.rows {
		if d.ID == id {
			f.rows = append(f.rows[:i], f.rows[i+1:]...)
			return &d, nil
		}
	}
	return nil, shared.ErrNotFound
}

func (f *fakeDeclined) UndeclineValue(_ context.Context, _ shared.ID, kind easmseed.Kind, value string) error {
	f.undeclined = append(f.undeclined, string(kind)+":"+value)
	return nil
}

type decisionFixture struct {
	tenant   shared.ID
	cards    *SuggestionService
	targets  *fakeConfirmTargets
	review   *fakeDecisionReview
	seeds    *fakeDecisionSeeds
	declined *fakeDeclined
	d        *AddressDecisions
}

// newDecisionFixture: two addresses in the organization's own prefix, one
// with no network data, one in another organization's network and one CDN
// edge address, all behind in-scope names of one tenant.
func newDecisionFixture(t *testing.T) *decisionFixture {
	t.Helper()
	f := &decisionFixture{tenant: shared.NewID(), targets: &fakeConfirmTargets{}, review: &fakeDecisionReview{},
		seeds: &fakeDecisionSeeds{}, declined: &fakeDeclined{}}
	own := map[string]any{"asn": "AS38731", "asn_org": "Acme Bank"}
	store := &tenantStore{tenant: f.tenant, fakeSuggestionStore: fakeSuggestionStore{addrs: []AddressBehindNames{
		addr("198.51.100.20", own, "www.acme.example"),
		addr("198.51.100.21", own, "api.acme.example"),
		addr("203.0.113.7", nil, "vpn.acme.example"),
		addr("192.0.2.9", map[string]any{"asn": "AS7552", "asn_org": "Other Telecom"}, "mail.acme.example"),
		addr("104.16.2.2", nil, "cdn.acme.example"),
	}}}
	cover := coverSet{"www.acme.example": true, "api.acme.example": true, "vpn.acme.example": true,
		"mail.acme.example": true, "cdn.acme.example": true}
	org := func(context.Context, shared.ID) (string, error) { return "Acme Bank", nil }
	seeds := func(context.Context, shared.ID) (easmseed.Networks, error) {
		return easmseed.Networks{ASNs: map[string]bool{"AS38731": true}, Prefixes: []string{"198.51.100.0/24"}}, nil
	}
	f.cards = NewSuggestionService(store, cover, nil, org, seeds)
	f.cards.SetGuardrails(scopedom.DefaultGuardrails())
	f.cards.SetDeclined(f.declined)
	f.d = NewAddressDecisions(f.cards, f.targets, f.review, f.seeds, f.declined, nil)
	return f
}

func (f *decisionFixture) card(t *testing.T) *SuggestionCard {
	t.Helper()
	out, err := f.cards.Cards(context.Background(), f.tenant, true)
	if err != nil {
		t.Fatal(err)
	}
	for i := range out.Cards {
		if out.Cards[i].Kind == CardAddressesBehindNames {
			return &out.Cards[i]
		}
	}
	t.Fatal("no addresses card")
	return nil
}

func groupByKind(c *SuggestionCard, kind string) *SuggestionGroup {
	for i := range c.Groups {
		if c.Groups[i].Kind == kind {
			return &c.Groups[i]
		}
	}
	return nil
}

var person = ScopeActor{CanWriteScope: true}

func TestAddressGroups_KindsCountsAndTotal(t *testing.T) {
	f := newDecisionFixture(t)
	c := f.card(t)
	own := groupByKind(c, GroupOwnPrefix)
	if own == nil || own.Range != "198.51.100.0/24" || own.Waiting != 2 || len(own.Addresses) != 2 {
		t.Fatalf("own prefix group %+v", own)
	}
	block := groupByKind(c, GroupBlock)
	if block == nil || block.Prefix != "203.0.113.0/24" || block.Range != "" || block.AskNetwork {
		t.Fatalf("block group (never offered as a range) %+v", block)
	}
	other := groupByKind(c, GroupOtherNetwork)
	if other == nil || !other.AskNetwork || !other.Shared || other.ASN != "AS7552" || other.Waiting != 0 {
		t.Fatalf("other network group %+v", other)
	}
	prov := groupByKind(c, GroupProvider)
	if prov == nil || !prov.Shared || prov.AskNetwork {
		t.Fatalf("provider group %+v", prov)
	}
	if c.Groups[0].Kind != GroupOwnPrefix {
		t.Fatalf("own prefix first: %v", c.Groups[0].Kind)
	}
	out := &SuggestionCards{Cards: []SuggestionCard{*c}}
	out.Finish(0)
	if out.Total != 2 { // own prefix + block wait; shared groups never count
		t.Fatalf("total %d", out.Total)
	}
}

func TestAddressDecisions_AddRangeAndAddress(t *testing.T) {
	f := newDecisionFixture(t)
	res, err := f.d.Add(context.Background(), f.tenant, person, AddressAddInput{
		AddressSelection: AddressSelection{Addresses: []string{"203.0.113.7", "198.51.100.20"}}, Ranges: []string{"198.51.100.0/24"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(f.targets.calls) != 1 {
		t.Fatalf("calls %d", len(f.targets.calls))
	}
	in := f.targets.calls[0]
	if in.Origin != scopedom.OriginConfirmed || in.TenantID != f.tenant.String() {
		t.Fatalf("origin %s tenant %s", in.Origin, in.TenantID)
	}
	// The address inside the range is covered by it: two entries.
	if len(in.Items) != 2 || in.Items[0].Pattern != "198.51.100.0/24" || in.Items[1].Pattern != "203.0.113.7" {
		t.Fatalf("items %+v", in.Items)
	}
	if res.Created != 2 || len(res.Names) != 3 {
		t.Fatalf("result %+v", res)
	}
}

// SECURITY: nothing outside the caller's own pending set is ever written.
func TestAddressDecisions_AddRefusesWhatIsNotPending(t *testing.T) {
	cases := []struct {
		name string
		in   AddressAddInput
		want error
	}{
		{"unknown address", AddressAddInput{AddressSelection: AddressSelection{Addresses: []string{"203.0.113.99"}}}, ErrDecisionNotPending},
		{"one bad among good", AddressAddInput{AddressSelection: AddressSelection{Addresses: []string{"203.0.113.7", "203.0.113.99"}}}, ErrDecisionNotPending},
		{"not an address", AddressAddInput{AddressSelection: AddressSelection{Addresses: []string{"203.0.113.7", "evil.example"}}}, ErrDecisionNotPending},
		{"computed block range", AddressAddInput{Ranges: []string{"203.0.113.0/24"}}, ErrDecisionNotPending},
		{"supernet of own prefix", AddressAddInput{Ranges: []string{"198.51.0.0/16"}}, ErrDecisionNotPending},
		{"guardrail breach", AddressAddInput{Ranges: []string{"0.0.0.0/0"}}, ErrDecisionNotPending},
		{"CDN address in a bulk", AddressAddInput{AddressSelection: AddressSelection{Addresses: []string{"203.0.113.7", "104.16.2.2"}}}, ErrDecisionShared},
		{"unknown group", AddressAddInput{AddressSelection: AddressSelection{Groups: []string{"block:192.0.2.0/24"}}}, ErrDecisionNotPending},
		{"shared group without include_shared", AddressAddInput{AddressSelection: AddressSelection{Groups: []string{"provider:cloudflare|edge"}}}, ErrDecisionShared},
		{"CDN address without include_shared", AddressAddInput{AddressSelection: AddressSelection{Addresses: []string{"104.16.2.2"}}}, ErrDecisionShared},
		{"empty", AddressAddInput{}, ErrDecisionEmpty},
	}
	for _, tc := range cases {
		f := newDecisionFixture(t)
		_, err := f.d.Add(context.Background(), f.tenant, person, tc.in)
		if !errors.Is(err, tc.want) {
			t.Errorf("%s: err %v, want %v", tc.name, err, tc.want)
		}
		if len(f.targets.calls) != 0 {
			t.Errorf("%s: wrote %+v", tc.name, f.targets.calls)
		}
	}
}

func TestAddressDecisions_AddTooMany(t *testing.T) {
	f := newDecisionFixture(t)
	many := make([]string, maxSuggestionScan+1)
	for i := range many {
		many[i] = fmt.Sprintf("10.%d.%d.1", i/250, i%250)
	}
	if _, err := f.d.Add(context.Background(), f.tenant, person, AddressAddInput{AddressSelection: AddressSelection{Addresses: many}}); !errors.Is(err, ErrDecisionTooMany) {
		t.Fatalf("err %v", err)
	}
}

// A shared address may be added on its own, explicitly.
func TestAddressDecisions_AddSharedAloneAnyway(t *testing.T) {
	f := newDecisionFixture(t)
	if _, err := f.d.Add(context.Background(), f.tenant, person, AddressAddInput{AddressSelection: AddressSelection{Addresses: []string{"104.16.2.2"}}, IncludeShared: true}); err != nil {
		t.Fatal(err)
	}
	if len(f.targets.calls) != 1 || len(f.targets.calls[0].Items) != 1 {
		t.Fatalf("calls %+v", f.targets.calls)
	}
}

// SECURITY: another tenant's addresses are never pending for the caller.
func TestAddressDecisions_CrossTenant(t *testing.T) {
	f := newDecisionFixture(t)
	other := shared.NewID()
	if _, err := f.d.Add(context.Background(), other, person, AddressAddInput{AddressSelection: AddressSelection{Addresses: []string{"203.0.113.7"}}}); !errors.Is(err, ErrDecisionNotPending) {
		t.Fatalf("add: %v", err)
	}
	if _, err := f.d.Reject(context.Background(), other, person, AddressSelection{Addresses: []string{"203.0.113.7"}}); !errors.Is(err, ErrDecisionNotPending) {
		t.Fatalf("reject: %v", err)
	}
	if _, err := f.d.NetworkNotOurs(context.Background(), other, person, "other_network:AS7552"); !errors.Is(err, ErrNetworkNotAsked) {
		t.Fatalf("network: %v", err)
	}
	if len(f.targets.calls)+len(f.review.calls)+len(f.declined.rows)+len(f.seeds.created) != 0 {
		t.Fatal("something was written for another tenant")
	}
}

func TestAddressDecisions_Reject(t *testing.T) {
	f := newDecisionFixture(t)
	res, err := f.d.Reject(context.Background(), f.tenant, person, AddressSelection{Addresses: []string{"203.0.113.7", "104.16.2.2"}})
	if err != nil {
		t.Fatal(err)
	}
	if f.review.state != attribution.StateRejected || len(f.review.calls) != 1 || len(res.AssetIDs) != 2 {
		t.Fatalf("review %+v res %+v", f.review, res)
	}
	if _, err := f.d.Reject(context.Background(), f.tenant, person, AddressSelection{Addresses: []string{"203.0.113.99"}}); !errors.Is(err, ErrDecisionNotPending) {
		t.Fatalf("out of set: %v", err)
	}
}

func TestAddressDecisions_NetworkAnswers(t *testing.T) {
	f := newDecisionFixture(t)
	for _, key := range []string{"block:203.0.113.0/24", "own_prefix:198.51.100.0/24", "provider:x", "nope"} {
		if _, err := f.d.NetworkIsOurs(context.Background(), f.tenant, person, key); !errors.Is(err, ErrNetworkNotAsked) {
			t.Errorf("%s: %v", key, err)
		}
	}
	res, err := f.d.NetworkIsOurs(context.Background(), f.tenant, person, "other_network:AS7552")
	if err != nil {
		t.Fatal(err)
	}
	if res.SeedID != "seed-1" || len(f.seeds.created) != 1 || f.seeds.created[0] != "asn:AS7552" || len(f.declined.undeclined) != 1 {
		t.Fatalf("yes: %+v seeds %v", res, f.seeds.created)
	}

	g := newDecisionFixture(t)
	no, err := g.d.NetworkNotOurs(context.Background(), g.tenant, person, "other_network:AS7552")
	if err != nil {
		t.Fatal(err)
	}
	if no.DeclinedID == "" || no.Rejected == nil || len(no.Rejected.AssetIDs) != 1 {
		t.Fatalf("no: %+v", no)
	}
	// Not asked again: the network is now a declined group.
	c := g.card(t)
	if groupByKind(c, GroupOtherNetwork) != nil {
		t.Fatalf("still asked: %+v", c.Groups)
	}
	if dg := groupByKind(c, GroupDeclined); dg == nil || dg.DeclinedID != no.DeclinedID || dg.AskNetwork {
		t.Fatalf("declined group %+v", dg)
	}
	if _, err := g.d.NetworkNotOurs(context.Background(), g.tenant, person, "other_network:AS7552"); !errors.Is(err, ErrNetworkNotAsked) {
		t.Fatalf("asked twice: %v", err)
	}
}
