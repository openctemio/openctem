package easm

import (
	"context"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/scopeauth"
	"github.com/openctemio/openctem/api/pkg/domain/easmseed"
	scopedom "github.com/openctemio/openctem/api/pkg/domain/scope"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

type fakeSuggestionStore struct {
	addrs     []AddressBehindNames
	confirmed []SuggestionAsset
}

func (f *fakeSuggestionStore) AddressesBehindNames(context.Context, shared.ID, *shared.DataScope, int) ([]AddressBehindNames, error) {
	return f.addrs, nil
}

func (f *fakeSuggestionStore) ConfirmedByPerson(context.Context, shared.ID, *shared.DataScope, int) ([]SuggestionAsset, error) {
	return f.confirmed, nil
}

// coverSet covers exactly the listed names.
type coverSet map[string]bool

func (c coverSet) CoverOf(_ context.Context, _ shared.ID, names []string) (map[string]scopeauth.Via, error) {
	out := map[string]scopeauth.Via{}
	for _, n := range names {
		if c[n] {
			out[n] = scopeauth.Via{Kind: scopeauth.KindScopeTarget, ID: "t-" + n, Pattern: n}
		}
	}
	return out, nil
}

func addr(ip string, props map[string]any, names ...string) AddressBehindNames {
	return AddressBehindNames{AssetID: "id-" + ip, Address: ip, Props: props, AllNames: names, VisibleNames: names}
}

func TestSuggestionCards_AddressesBehindNames(t *testing.T) {
	store := &fakeSuggestionStore{addrs: []AddressBehindNames{
		addr("198.51.100.1", nil, "www.acme.example", "api.acme.example"),                                           // unknown network: offered, counted unknown
		addr("198.51.100.2", map[string]any{"asn": "AS64500", "asn_org": "Acme Corp"}, "mail.acme.example"),         // org matches: offered, known
		addr("198.51.100.3", map[string]any{"cdn": "examplecdn"}, "cdn.acme.example"),                               // CDN: shared
		addr("198.51.100.4", map[string]any{"asn_org": "Amazon.com, Inc."}, "s3.acme.example"),                      // provider: shared
		addr("104.16.1.1", nil, "edge.acme.example"),                                                                // published edge range: shared
		addr("198.51.100.5", nil, "a.acme.example", "x.other.example", "y.third.example"),                           // 3 registrable domains: shared
		addr("198.51.100.6", map[string]any{"asn": "AS64501", "asn_org": "Hosting Elsewhere"}, "h.acme.example"),    // other network: shared
		addr("198.51.100.7", nil, "out.notours.example"),                                                            // no in-scope name: dropped
		addr("198.51.100.8", nil, "ok.acme.example"),                                                                // address already covered: dropped
		addr("198.51.100.9", map[string]any{"asn": "AS64502", "asn_org": "Hosting Elsewhere"}, "seed.acme.example"), // other network but seeded AS: offered
	}}
	cover := coverSet{"198.51.100.8": true}
	for _, n := range []string{"www.acme.example", "api.acme.example", "mail.acme.example", "cdn.acme.example", "s3.acme.example",
		"edge.acme.example", "a.acme.example", "h.acme.example", "ok.acme.example", "seed.acme.example"} {
		cover[n] = true
	}
	org := func(context.Context, shared.ID) (string, error) { return "Acme", nil }
	seeds := func(context.Context, shared.ID) (easmseed.Networks, error) {
		return easmseed.Networks{ASNs: map[string]bool{"AS64502": true}}, nil
	}
	svc := NewSuggestionService(store, cover, nil, org, seeds)
	out, err := svc.Cards(context.Background(), shared.NewID(), true)
	if err != nil {
		t.Fatal(err)
	}
	if !out.CanAdd || len(out.Cards) != 1 || out.Cards[0].Kind != CardAddressesBehindNames {
		t.Fatalf("cards %+v", out)
	}
	c := out.Cards[0]
	offered := map[string]SuggestionAddress{}
	for _, a := range c.Addresses {
		offered[a.Address] = a
	}
	if c.Count != 3 || len(offered) != 3 {
		t.Fatalf("offered %v", c.Addresses)
	}
	if a := offered["198.51.100.1"]; a.Network.Known || len(a.ResolvedFrom) != 2 {
		t.Fatalf("unknown network address %+v", a)
	}
	if !offered["198.51.100.2"].Network.Known || offered["198.51.100.9"].Shared != "" {
		t.Fatalf("known / seeded addresses %+v", offered)
	}
	if c.UnknownNetworkCount != 1 {
		t.Fatalf("unknown count %d, want 1 (an unknown network is never presented as safe)", c.UnknownNetworkCount)
	}
	why := map[string]string{}
	for _, a := range c.SharedAddresses {
		why[a.Address] = a.Shared
	}
	want := map[string]string{"198.51.100.3": SharedCDN, "198.51.100.4": SharedProvider, "104.16.1.1": SharedEdgeRange,
		"198.51.100.5": SharedManyDomains, "198.51.100.6": SharedOtherNetwork}
	if len(why) != len(want) || c.SharedCount != len(want) {
		t.Fatalf("shared %v", why)
	}
	for a, w := range want {
		if why[a] != w {
			t.Fatalf("%s shared = %q, want %q", a, why[a], w)
		}
	}
	if c.NamesCount != 4 { // www, api, mail, seed
		t.Fatalf("names count %d", c.NamesCount)
	}
}

func TestSuggestionCards_ConfirmedOutOfScope(t *testing.T) {
	store := &fakeSuggestionStore{confirmed: []SuggestionAsset{
		{AssetID: "1", Name: "Kept.Acme.example.", TargetType: "domain"},
		{AssetID: "2", Name: "covered.acme.example", TargetType: "domain"},
		{AssetID: "3", Name: "10.0.0.4", TargetType: "ip_address"}, // private: zones gate it
		{AssetID: "4", Name: "203.0.113.4", TargetType: "ip_address"},
		{AssetID: "5", Name: "kept.acme.example", TargetType: "domain"}, // same name twice
	}}
	out, err := NewSuggestionService(store, coverSet{"covered.acme.example": true}, nil, nil, nil).Cards(context.Background(), shared.NewID(), false)
	if err != nil {
		t.Fatal(err)
	}
	if out.CanAdd || len(out.Cards) != 1 || out.Cards[0].Kind != CardConfirmedOutOfScope {
		t.Fatalf("cards %+v", out)
	}
	c := out.Cards[0]
	if c.Count != 2 || c.Assets[0].Name != "kept.acme.example" || c.Assets[1].Name != "203.0.113.4" {
		t.Fatalf("assets %+v", c.Assets)
	}
}

func TestSuggestionCards_NothingToDecide(t *testing.T) {
	out, err := NewSuggestionService(&fakeSuggestionStore{}, coverSet{}, nil, nil, nil).Cards(context.Background(), shared.NewID(), true)
	if err != nil || len(out.Cards) != 0 {
		t.Fatalf("%+v %v", out, err)
	}
	// Without coverage nothing can be told in or out of scope: no card.
	out, err = NewSuggestionService(&fakeSuggestionStore{confirmed: []SuggestionAsset{{AssetID: "1", Name: "a.example"}}}, nil, nil, nil, nil).
		Cards(context.Background(), shared.NewID(), true)
	if err != nil || len(out.Cards) != 0 {
		t.Fatalf("%+v %v", out, err)
	}
}

func TestNameRuleCards(t *testing.T) {
	if NameRuleCards(nil) != 0 {
		t.Fatal("nil")
	}
	rs := &RuleSuggestions{
		Suggestions: []RuleSuggestion{{Kind: "domain_wildcard"}, {Kind: "domain_wildcard"}, {Kind: "ip_cidr"}},
		Individual:  []IndividualItem{{Name: "203.0.113.5"}, {Name: "cname.target.example"}, {Name: "other.example"}},
	}
	// Two name rules and one card for the names no rule groups; address
	// rules and addresses belong to the addresses card.
	if n := NameRuleCards(rs); n != 3 {
		t.Fatalf("cards = %d, want 3", n)
	}
	if n := NameRuleCards(&RuleSuggestions{Individual: []IndividualItem{{Name: "198.51.100.1:443"}}}); n != 0 {
		t.Fatalf("address-only individuals = %d, want 0", n)
	}
}

// The card says what was seen on each address (ports, the other names) and
// offers the organization's own prefix as one rule, only when the platform
// guardrails accept it; a shared address is never given a prefix.
func TestSuggestionCards_EvidenceAndOwnPrefix(t *testing.T) {
	store := &fakeSuggestionStore{addrs: []AddressBehindNames{
		func() AddressBehindNames {
			a := addr("198.51.100.20", map[string]any{"asn": "AS64502", "asn_org": "Elsewhere",
				"ports": []any{map[string]any{"port": float64(22), "state": "open"}, map[string]any{"port": float64(25), "state": "closed"}}},
				"www.acme.example", "old.acme.example")
			a.Ports = []int{443, 8443}
			return a
		}(),
		addr("198.51.100.21", map[string]any{"asn": "AS64502", "asn_org": "Elsewhere"}, "api.acme.example"),
		addr("203.0.113.50", map[string]any{"asn": "AS64502", "asn_org": "Elsewhere"}, "big.acme.example"),
		addr("198.51.100.22", map[string]any{"cdn": "examplecdn"}, "cdn.acme.example"),
	}}
	cover := coverSet{"www.acme.example": true, "api.acme.example": true, "big.acme.example": true, "cdn.acme.example": true}
	seeds := func(context.Context, shared.ID) (easmseed.Networks, error) {
		return easmseed.Networks{ASNs: map[string]bool{"AS64502": true}, Prefixes: []string{"198.51.0.0/16", "198.51.100.0/24", "203.0.0.0/8"}}, nil
	}
	svc := NewSuggestionService(store, cover, nil, nil, seeds)
	// Without guardrails no prefix is offered (fail closed).
	out, err := svc.Cards(context.Background(), shared.NewID(), true)
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Cards[0].PrefixRules) != 0 {
		t.Fatalf("prefixes without guardrails: %v", out.Cards[0].PrefixRules)
	}
	svc.SetGuardrails(scopedom.DefaultGuardrails())
	out, err = svc.Cards(context.Background(), shared.NewID(), true)
	if err != nil {
		t.Fatal(err)
	}
	c := out.Cards[0]
	byAddr := map[string]SuggestionAddress{}
	for _, a := range c.Addresses {
		byAddr[a.Address] = a
	}
	first := byAddr["198.51.100.20"]
	if len(first.Ports) != 3 || first.Ports[0] != 22 || first.Ports[2] != 8443 {
		t.Fatalf("ports %v (open ports from the record and the services, closed left out)", first.Ports)
	}
	if len(first.OtherNames) != 1 || first.OtherNames[0] != "old.acme.example" {
		t.Fatalf("other names %v", first.OtherNames)
	}
	if first.Prefix != "198.51.100.0/24" || byAddr["198.51.100.21"].Prefix != "198.51.100.0/24" {
		t.Fatalf("most specific own prefix: %q %q", first.Prefix, byAddr["198.51.100.21"].Prefix)
	}
	if len(c.PrefixRules) != 1 || c.PrefixRules[0].Prefix != "198.51.100.0/24" || c.PrefixRules[0].Addresses != 2 {
		t.Fatalf("prefix rules %v", c.PrefixRules)
	}
	for _, a := range c.SharedAddresses {
		if a.Prefix != "" {
			t.Fatalf("a shared address got a prefix: %+v", a)
		}
	}
}

// While unclassified assets get low-impact checks, a known, unshared address
// needs no decision: it is listed apart and the card counts only the
// unknown ones. A card that offers nothing is not a decision.
func TestSuggestionCards_UnclassifiedChecksAndTotal(t *testing.T) {
	store := &fakeSuggestionStore{addrs: []AddressBehindNames{
		addr("198.51.100.20", nil, "u.acme.example"),                                                 // unknown network: waits
		addr("198.51.100.21", map[string]any{"asn": "AS64500", "asn_org": "Acme"}, "k.acme.example"), // known: checked
		addr("104.16.2.2", nil, "e.acme.example"),                                                    // edge: shared
	}}
	cover := coverSet{"u.acme.example": true, "k.acme.example": true, "e.acme.example": true}
	org := func(context.Context, shared.ID) (string, error) { return "Acme", nil }
	for _, tc := range []struct {
		mode               string
		count, checked, sh int
	}{
		{"low_impact", 1, 1, 1},
		{"full", 1, 1, 1},
		{"off", 2, 0, 1},
		{"garbage", 2, 0, 1},
	} {
		svc := NewSuggestionService(store, cover, nil, org, nil)
		mode := tc.mode
		svc.SetUnclassified(func(context.Context, shared.ID) (string, error) { return mode, nil })
		out, err := svc.Cards(context.Background(), shared.NewID(), true)
		if err != nil {
			t.Fatal(err)
		}
		c := out.Cards[0]
		if c.Count != tc.count || c.CheckedCount != tc.checked || len(c.CheckedAddresses) != tc.checked || c.SharedCount != tc.sh {
			t.Errorf("%s: count %d checked %d shared %d", tc.mode, c.Count, c.CheckedCount, c.SharedCount)
		}
		if tc.checked == 1 && c.CheckedAddresses[0].Address != "198.51.100.21" {
			t.Errorf("%s: checked %v", tc.mode, c.CheckedAddresses)
		}
		out.Finish(2)
		if out.Total != 3 || out.NameRules != 2 {
			t.Errorf("%s: total %d name rules %d", tc.mode, out.Total, out.NameRules)
		}
	}

	// Only shared addresses: the card comes back for the page, the badge
	// counts nothing.
	only := &fakeSuggestionStore{addrs: []AddressBehindNames{addr("104.16.3.3", nil, "e.acme.example")}}
	out, err := NewSuggestionService(only, cover, nil, org, nil).Cards(context.Background(), shared.NewID(), true)
	if err != nil {
		t.Fatal(err)
	}
	out.Finish(0)
	if len(out.Cards) != 1 || out.Cards[0].Count != 0 || out.Total != 0 {
		t.Fatalf("shared-only %+v", out)
	}
}
