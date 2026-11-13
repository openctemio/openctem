package easm

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"net/netip"
	"sort"
	"testing"
	"time"

	"github.com/openctemio/openctem/server/internal/app/scope"
	"github.com/openctemio/openctem/server/pkg/domain/easmseed"
	scopedom "github.com/openctemio/openctem/server/pkg/domain/scope"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
)

func prefixStrings(ps []netip.Prefix) []string {
	out := make([]string, 0, len(ps))
	for _, p := range ps {
		out = append(out, p.String())
	}
	return out
}

func TestExactCover(t *testing.T) {
	cases := []struct {
		in   []string
		want []string
	}{
		{[]string{"203.0.113.4", "203.0.113.5", "203.0.113.6", "203.0.113.7"}, []string{"203.0.113.4/30"}},
		{[]string{"203.0.113.4", "203.0.113.5", "203.0.113.7"}, []string{"203.0.113.4/31", "203.0.113.7/32"}},
		{[]string{"203.0.113.5", "203.0.113.6"}, []string{"203.0.113.5/32", "203.0.113.6/32"}},
		{[]string{"203.0.113.9", "203.0.113.9", "::ffff:203.0.113.9"}, []string{"203.0.113.9/32"}},
		{[]string{"2001:db8::", "2001:db8::1", "198.51.100.1"}, []string{"198.51.100.1/32", "2001:db8::/127"}},
	}
	for _, tc := range cases {
		var in []netip.Addr
		for _, s := range tc.in {
			in = append(in, netip.MustParseAddr(s))
		}
		got := prefixStrings(ExactCover(in))
		if fmt.Sprint(got) != fmt.Sprint(tc.want) {
			t.Errorf("%v: got %v want %v", tc.in, got, tc.want)
		}
	}
}

// SECURITY: a range made from chosen addresses holds exactly the chosen
// addresses, never one more (random sets inside one /24).
func TestExactCover_NeverWiderThanTheChoice(t *testing.T) {
	rng := rand.New(rand.NewSource(7))
	for round := 0; round < 300; round++ {
		chosen := map[netip.Addr]bool{}
		var in []netip.Addr
		for i := 0; i < rng.Intn(80)+1; i++ {
			a := netip.AddrFrom4([4]byte{203, 0, 113, byte(rng.Intn(256))})
			chosen[a] = true
			in = append(in, a)
		}
		got := map[netip.Addr]bool{}
		for _, p := range ExactCover(in) {
			for a := p.Addr(); p.Contains(a); a = a.Next() {
				if !chosen[a] {
					t.Fatalf("round %d: %s covers %s, not chosen", round, p, a)
				}
				got[a] = true
			}
		}
		if len(got) != len(chosen) {
			t.Fatalf("round %d: covered %d of %d", round, len(got), len(chosen))
		}
	}
}

// selectionFixture: addresses with no network data behind one tenant's
// in-scope names, plus a CDN edge address and a Microsoft 365 mail address.
func selectionFixture(t *testing.T, ips ...string) *decisionFixture {
	t.Helper()
	f := &decisionFixture{tenant: shared.NewID(), targets: &fakeConfirmTargets{}, review: &fakeDecisionReview{},
		seeds: &fakeDecisionSeeds{}, declined: &fakeDeclined{}}
	rows := []AddressBehindNames{
		addr("104.16.2.2", nil, "cdn.acme.example"),
		addr("40.107.5.5", map[string]any{"asn": "AS8075", "asn_org": "Acme Bank"}, "mail.acme.example"),
	}
	cover := coverSet{"cdn.acme.example": true, "mail.acme.example": true}
	for i, ip := range ips {
		n := fmt.Sprintf("h%d.acme.example", i)
		rows = append(rows, addr(ip, nil, n))
		cover[n] = true
	}
	store := &tenantStore{tenant: f.tenant, fakeSuggestionStore: fakeSuggestionStore{addrs: rows}}
	org := func(context.Context, shared.ID) (string, error) { return "Acme Bank", nil }
	f.cards = NewSuggestionService(store, cover, nil, org, nil)
	f.cards.SetGuardrails(scopedom.DefaultGuardrails())
	f.d = NewAddressDecisions(f.cards, f.targets, f.review, f.seeds, f.declined, nil)
	return f
}

func patterns(calls []scope.BulkTargetsInput) []string {
	var out []string
	for _, c := range calls {
		for _, it := range c.Items {
			out = append(out, it.TargetType+":"+it.Pattern)
		}
	}
	sort.Strings(out)
	return out
}

// SECURITY: a bulk add creates ranges only from the selected addresses.
func TestAddressDecisions_AddSelectedAsRanges(t *testing.T) {
	f := selectionFixture(t, "203.0.113.4", "203.0.113.5", "203.0.113.6", "203.0.113.7", "203.0.113.8", "203.0.113.9")
	// .8 is on the card but not chosen: no range may reach it.
	_, err := f.d.Add(context.Background(), f.tenant, person, AddressAddInput{AddressSelection: AddressSelection{
		Addresses: []string{"203.0.113.4", "203.0.113.5", "203.0.113.6", "203.0.113.7", "203.0.113.9"}}})
	if err != nil {
		t.Fatal(err)
	}
	got := patterns(f.targets.calls)
	want := []string{"cidr:203.0.113.4/30", "ip_address:203.0.113.9"}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("items %v, want %v", got, want)
	}
	if f.targets.calls[0].Origin != scopedom.OriginConfirmed || f.targets.calls[0].TenantID != f.tenant.String() {
		t.Fatalf("input %+v", f.targets.calls[0])
	}
}

// The shared addresses in a selection are refused unless the person opts in;
// opted in, each is an exact entry of its own, never merged into a range.
func TestAddressDecisions_SharedInSelectionNeedsOptIn(t *testing.T) {
	f := selectionFixture(t, "104.16.2.3")
	sel := AddressSelection{Addresses: []string{"104.16.2.2", "104.16.2.3", "40.107.5.5"}}
	if _, err := f.d.Add(context.Background(), f.tenant, person, AddressAddInput{AddressSelection: sel}); !errors.Is(err, ErrDecisionShared) {
		t.Fatalf("without opt-in: %v", err)
	}
	if len(f.targets.calls) != 0 {
		t.Fatal("wrote without opt-in")
	}
	// 104.16.2.3 is a Cloudflare edge too: shared, so nothing is merged.
	if _, err := f.d.Add(context.Background(), f.tenant, person, AddressAddInput{AddressSelection: sel, IncludeShared: true}); err != nil {
		t.Fatal(err)
	}
	got := patterns(f.targets.calls)
	want := []string{"ip_address:104.16.2.2", "ip_address:104.16.2.3", "ip_address:40.107.5.5"}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("items %v, want %v", got, want)
	}
}

// "Select all N": every waiting address, also past the card's list, in
// chunks the scope service accepts.
func TestAddressDecisions_AllWaitingPastTheCard(t *testing.T) {
	var ips []string
	for i := 0; i < MaxSuggestionItems+50; i++ {
		// Every other address: no two adjacent, so no range forms.
		ips = append(ips, netip.AddrFrom4([4]byte{198, 51, byte(i / 100), byte((i % 100) * 2)}).String())
	}
	f := selectionFixture(t, ips...)
	c := f.card(t)
	if !c.Truncated || len(c.Addresses) != MaxSuggestionItems || c.Summary == nil || c.Summary.NeedYou != len(ips) {
		t.Fatalf("card truncated=%v listed=%d summary=%+v", c.Truncated, len(c.Addresses), c.Summary)
	}
	res, err := f.d.Add(context.Background(), f.tenant, person, AddressAddInput{AddressSelection: AddressSelection{AllWaiting: true}})
	if err != nil {
		t.Fatal(err)
	}
	if res.Created != len(ips) || len(f.targets.calls) != 2 || len(f.targets.calls[0].Items) != scope.MaxBulkTargets {
		t.Fatalf("created %d in %d calls", res.Created, len(f.targets.calls))
	}
	for _, p := range patterns(f.targets.calls) {
		if p == "ip_address:104.16.2.2" || p == "ip_address:40.107.5.5" {
			t.Fatalf("a shared address joined an all-waiting add: %s", p)
		}
	}
}

func TestAddressDecisions_GroupSelection(t *testing.T) {
	f := selectionFixture(t, "203.0.113.4", "203.0.113.5", "198.51.100.9")
	res, err := f.d.Reject(context.Background(), f.tenant, person, AddressSelection{Groups: []string{"block:203.0.113.0/24"}})
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(res.Addresses)
	if fmt.Sprint(res.Addresses) != "[203.0.113.4 203.0.113.5]" {
		t.Fatalf("rejected %v", res.Addresses)
	}
	// SECURITY: another tenant cannot name this tenant's groups.
	if _, err := f.d.Reject(context.Background(), shared.NewID(), person, AddressSelection{Groups: []string{"block:203.0.113.0/24"}}); !errors.Is(err, ErrDecisionNotPending) {
		t.Fatalf("cross-tenant group: %v", err)
	}
}

type fakeLookupQueue struct{ ids [][]string }

func (f *fakeLookupQueue) RequeueNetworkLookup(_ context.Context, _ shared.ID, ids []string) (int, error) {
	f.ids = append(f.ids, ids)
	return len(ids), nil
}

// A retry only marks the sensor lookups due (the platform looks nothing up)
// and only for the caller's own addresses whose network is unknown.
func TestAddressDecisions_RetryLookup(t *testing.T) {
	f := selectionFixture(t, "203.0.113.4")
	q := &fakeLookupQueue{}
	if _, err := f.d.RetryLookup(context.Background(), f.tenant, AddressSelection{AllWaiting: true}); err == nil {
		t.Fatal("retry without a queue must be refused")
	}
	f.d.SetLookupQueue(q)
	res, err := f.d.RetryLookup(context.Background(), f.tenant, AddressSelection{Addresses: []string{"203.0.113.4", "40.107.5.5"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(q.ids) != 1 || fmt.Sprint(q.ids[0]) != "[id-203.0.113.4]" || res.Queued != 1 {
		t.Fatalf("requeued %v (an address with a known network is skipped)", q.ids)
	}
	if _, err := f.d.RetryLookup(context.Background(), shared.NewID(), AddressSelection{Addresses: []string{"203.0.113.4"}}); !errors.Is(err, ErrDecisionNotPending) {
		t.Fatalf("cross-tenant retry: %v", err)
	}
	if len(q.ids) != 1 {
		t.Fatal("requeued for another tenant")
	}
}

type fakeAutoPatterns map[string]bool

func (f fakeAutoPatterns) Seen(_ context.Context, _ shared.ID, ps []string) (map[string]bool, error) {
	out := map[string]bool{}
	for _, p := range ps {
		out[p] = f[p]
	}
	return out, nil
}

func TestNetworkLookup_SourceUnavailable(t *testing.T) {
	cases := []struct {
		in   LedgerLookup
		want string
	}{
		{LedgerLookup{State: "failed", Reason: "tool_error", LastError: `asn: routing dataset: fetch iptoasn.com: Bad Gateway`}, LookupSourceUnavailable},
		{LedgerLookup{State: "failed", Reason: LookupSourceUnavailable}, LookupSourceUnavailable},
		{LedgerLookup{State: "failed", Reason: "tool_error", LastError: "asn: bad input"}, "tool_error"},
		{LedgerLookup{State: "blocked", Reason: "no_entry"}, "no_entry"},
	}
	for _, tc := range cases {
		got := networkLookup(tc.in)
		if got.State != LookupFailed || got.Reason != tc.want {
			t.Errorf("%+v: %+v, want reason %s", tc.in, got, tc.want)
		}
	}
}

func TestAddressCard_LookupStatesAndSummary(t *testing.T) {
	at := time.Date(2026, 11, 6, 8, 0, 0, 0, time.UTC)
	rows := []AddressBehindNames{
		addr("203.0.113.1", nil, "a.acme.example"),
		addr("203.0.113.2", nil, "b.acme.example"),
		addr("203.0.113.3", nil, "c.acme.example"),
		addr("203.0.113.4", map[string]any{"asn": "AS64500"}, "d.acme.example"),
		addr("104.16.2.2", nil, "e.acme.example"),
		addr("198.51.100.7", nil, "f.acme.example"), // covered by an automatic entry
	}
	rows[1].Lookup = LedgerLookup{State: "blocked", Reason: "no_sensor", LastAttemptAt: &at}
	rows[2].Lookup = LedgerLookup{State: "covered", LastAttemptAt: &at}
	rows[3].Lookup = LedgerLookup{State: "failed"} // network known: no lookup state shown
	cover := coverSet{"198.51.100.7": true}
	for _, n := range []string{"a", "b", "c", "d", "e", "f"} {
		cover[n+".acme.example"] = true
	}
	svc := NewSuggestionService(&fakeSuggestionStore{addrs: rows}, cover, nil, nil, nil)
	svc.SetAutoAdded(fakeAutoPatterns{"198.51.100.7": true})
	out, err := svc.Cards(context.Background(), shared.NewID(), true)
	if err != nil || len(out.Cards) == 0 {
		t.Fatalf("cards %v %v", out, err)
	}
	c := out.Cards[0]
	states := map[string]*NetworkLookup{}
	for _, a := range c.Addresses {
		states[a.Address] = a.Lookup
	}
	if states["203.0.113.1"].State != LookupPending || states["203.0.113.2"].State != LookupFailed ||
		states["203.0.113.2"].Reason != "no_sensor" || states["203.0.113.3"].State != LookupNotFound || states["203.0.113.4"] != nil {
		t.Fatalf("lookup states %+v", states)
	}
	want := AddressSummary{AutoAdded: 1, ThirdParty: 1, NeedYou: 4, LookingUp: 1, LookupFailed: 1}
	if c.Summary == nil || *c.Summary != want {
		t.Fatalf("summary %+v, want %+v", c.Summary, want)
	}
}

// SECURITY: a shared mail provider's address is never added automatically,
// even when the tenant declared the provider's AS as its own and the holder
// name matches the organization.
func TestPlanAutoAdd_SharedMailProviderNever(t *testing.T) {
	old := time.Now().Add(-60 * 24 * time.Hour)
	rows := []AddressBehindNames{
		addr("40.107.5.5", map[string]any{"asn": "AS8075", "asn_org": "Acme Bank"}, "mail.acme.example", "autodiscover.acme.example", "smtp.acme.example"),
		addr("104.16.9.9", map[string]any{"asn": "AS8075"}, "www.acme.example"),
	}
	for i := range rows {
		rows[i].FirstSeen = old
	}
	cover := coverSet{"mail.acme.example": true, "autodiscover.acme.example": true, "smtp.acme.example": true, "www.acme.example": true}
	org := func(context.Context, shared.ID) (string, error) { return "Acme Bank", nil }
	seeds := func(context.Context, shared.ID) (easmseed.Networks, error) {
		return easmseed.Networks{ASNs: map[string]bool{"AS8075": true}, Prefixes: []string{"40.107.0.0/16"}}, nil
	}
	svc := NewSuggestionService(&fakeSuggestionStore{addrs: rows}, cover, nil, org, seeds)
	svc.SetGuardrails(scopedom.DefaultGuardrails())
	card, err := svc.addressCard(context.Background(), shared.NewID(), nil, maxSuggestionScan)
	if err != nil {
		t.Fatal(err)
	}
	if plan := PlanAutoAdd(card); len(plan) != 0 {
		t.Fatalf("auto plan %+v", plan)
	}
	if card.Summary.ThirdParty != 2 || card.Summary.NeedYou != 0 {
		t.Fatalf("summary %+v", card.Summary)
	}
}
