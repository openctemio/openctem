package addrowner

import (
	"testing"
	"time"
)

var now = time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)

func ids(a Assessment) map[string]Kind {
	out := map[string]Kind{}
	for _, s := range a.Signals {
		out[s.ID] = s.Kind
	}
	return out
}

func TestAssessBands(t *testing.T) {
	seedASNs := map[string]bool{"AS64500": true}
	seedPrefixes := []string{"198.51.100.0/22", "198.51.100.0/24"}
	cases := []struct {
		name string
		in   Input
		want Band
		has  []string
	}{
		{
			name: "own prefix and reverse name under the same domain is high",
			in: Input{Address: "198.51.100.10", ASN: "64500", SeedPrefixes: seedPrefixes, SeedASNs: seedASNs,
				ReverseName: "mail.example.com.", InScopeNames: []string{"api.example.com", "mail.example.com"},
				FirstSeen: now.Add(-3 * 24 * time.Hour), Now: now},
			want: High, has: []string{SignalOwnPrefix, SignalReverseName},
		},
		{
			name: "own ASN and stable is high",
			in: Input{Address: "192.0.2.5", ASN: "AS64500", SeedASNs: seedASNs,
				InScopeNames: []string{"www.example.com"}, FirstSeen: now.Add(-30 * 24 * time.Hour), Now: now},
			want: High, has: []string{SignalOwnASN, SignalStable},
		},
		{
			name: "anchor alone is medium",
			in: Input{Address: "198.51.100.9", SeedPrefixes: seedPrefixes, InScopeNames: []string{"www.example.com"},
				FirstSeen: now.Add(-3 * 24 * time.Hour), Now: now},
			want: Medium, has: []string{SignalOwnPrefix},
		},
		{
			name: "anchor and corroborator held back by a new address is medium",
			in: Input{Address: "198.51.100.11", SeedPrefixes: seedPrefixes, ReverseName: "a.example.com",
				InScopeNames: []string{"a.example.com"}, FirstSeen: now.Add(-2 * time.Hour), Now: now},
			want: Medium, has: []string{SignalNewAddress},
		},
		{
			name: "two corroborators without an anchor is medium, never high",
			in: Input{Address: "203.0.113.40", ASN: "AS64511", Holder: "Example Metro Hosting", HolderMatches: true,
				InScopeNames: []string{"vpn.example.com", "portal.example.com", "sso.example.com"},
				FirstSeen:    now.Add(-60 * 24 * time.Hour), Now: now},
			want: Medium, has: []string{SignalHolderMatches, SignalManyNames, SignalStable},
		},
		{
			name: "known network without positive evidence is low",
			in: Input{Address: "203.0.113.7", ASN: "AS64999", InScopeNames: []string{"x.example.com"},
				FirstSeen: now.Add(-3 * 24 * time.Hour), Now: now},
			want: Low,
		},
		{
			name: "nothing known is unknown",
			in:   Input{Address: "192.0.2.77", InScopeNames: []string{"legacy.example.com"}, Now: now},
			want: Unknown,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := Assess(tc.in)
			if got.Band != tc.want {
				t.Fatalf("band = %s, want %s (signals %v)", got.Band, tc.want, got.Signals)
			}
			lo, hi := bandRange(got.Band)
			if got.Score < lo || got.Score > hi {
				t.Fatalf("score %d outside band %s range %d-%d", got.Score, got.Band, lo, hi)
			}
			have := ids(got)
			for _, id := range tc.has {
				if _, ok := have[id]; !ok {
					t.Fatalf("missing signal %s in %v", id, got.Signals)
				}
			}
		})
	}
}

// An outside party controls the DNS of a taken-over alias, the reverse name
// and the holder text of an address it holds, and how many names point at
// it. None of that, alone or together, may reach High.
func TestAttackerControlledEvidenceNeverHigh(t *testing.T) {
	in := Input{
		Address:       "203.0.113.66",
		ASN:           "AS64666",
		Holder:        "Example Corp Holdings", // free text in a sub-allocation
		HolderMatches: true,
		ReverseName:   "www.example.com",
		InScopeNames:  []string{"www.example.com", "a.example.com", "b.example.com", "c.example.com"},
		FirstSeen:     now.Add(-90 * 24 * time.Hour),
		Now:           now,
		SeedASNs:      map[string]bool{"AS64500": true},
		SeedPrefixes:  []string{"198.51.100.0/24"},
	}
	if got := Assess(in); got.Band == High {
		t.Fatalf("attacker-controlled evidence reached high: %v", got.Signals)
	}
}

func TestForeignNamesBlock(t *testing.T) {
	in := Input{Address: "198.51.100.12", SeedPrefixes: []string{"198.51.100.0/24"}, ReverseName: "w.example.com",
		InScopeNames: []string{"w.example.com"}, OtherNames: []string{"shop.other-org.test", "old.example.com"},
		FirstSeen: now.Add(-20 * 24 * time.Hour), Now: now}
	got := Assess(in)
	if got.Band != Medium {
		t.Fatalf("band = %s, want medium", got.Band)
	}
	if k := ids(got)[SignalForeignNames]; k != Blocker {
		t.Fatalf("foreign_names = %q, want blocker", k)
	}
}

func TestReverseNameOtherDomainIgnored(t *testing.T) {
	in := Input{Address: "198.51.100.13", ReverseName: "host-13.hoster.test", InScopeNames: []string{"a.example.com"}, Now: now}
	if _, ok := ids(Assess(in))[SignalReverseName]; ok {
		t.Fatal("reverse name under another domain counted")
	}
}

func TestReverseNameConfirmed(t *testing.T) {
	in := Input{Address: "198.51.100.14", ReverseName: "MAIL.example.com.", InScopeNames: []string{"mail.example.com"}, Now: now}
	for _, s := range Assess(in).Signals {
		if s.ID == SignalReverseName && s.Params["confirmed"] == "true" {
			return
		}
	}
	t.Fatal("forward-confirmed reverse name not marked")
}

func TestMostSpecificPrefixAndSignalOrder(t *testing.T) {
	in := Input{Address: "198.51.100.10", SeedPrefixes: []string{"198.51.96.0/20", "198.51.100.0/24", "bogus"},
		HolderMatches: true, Holder: "Example", InScopeNames: []string{"a.example.com"}, FirstSeen: now.Add(-time.Hour), Now: now}
	got := Assess(in)
	if got.Signals[0].ID != SignalOwnPrefix || got.Signals[0].Params["prefix"] != "198.51.100.0/24" {
		t.Fatalf("first signal = %+v", got.Signals[0])
	}
	if got.Signals[len(got.Signals)-1].Kind != Blocker {
		t.Fatalf("blockers not last: %v", got.Signals)
	}
}

func TestHolderMatchNeedsAHolder(t *testing.T) {
	if _, ok := ids(Assess(Input{Address: "192.0.2.1", HolderMatches: true, Now: now}))[SignalHolderMatches]; ok {
		t.Fatal("holder match without a holder")
	}
}

func TestMalformedInputs(t *testing.T) {
	got := Assess(Input{Address: "not-an-ip", ASN: "ASxyz", ReverseName: "192.0.2.1", SeedPrefixes: []string{"x"}})
	if got.Band != Unknown || len(got.Signals) != 0 || got.Signals == nil {
		t.Fatalf("got %+v", got)
	}
}

func TestRank(t *testing.T) {
	if !(Rank(High) < Rank(Medium) && Rank(Medium) < Rank(Low) && Rank(Low) < Rank(Unknown)) {
		t.Fatal("rank order")
	}
}

func TestSeedASNSpelling(t *testing.T) {
	got := Assess(Input{Address: "192.0.2.9", ASN: "64500", SeedASNs: map[string]bool{"as64500": true}, Now: now})
	if ids(got)[SignalOwnASN] != Anchor {
		t.Fatalf("seed AS spelled differently not matched: %v", got.Signals)
	}
}
