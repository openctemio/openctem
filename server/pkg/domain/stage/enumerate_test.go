package stage

import (
	"slices"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/asset"
)

// Active subdomain enumeration is a routed catalog stage: T1 (never passive,
// never intrusive), on a root domain, run by dnsx-enum one root per task,
// and its tool's job asks for the DNS label list.
func TestEnumerateSubdomains_ActiveAndRouted(t *testing.T) {
	s, ok := Lookup(EnumerateSubdomains)
	if !ok || !s.Available() {
		t.Fatal("enumerate.subdomains is not a routed stage")
	}
	if s.Tier != TierActive || s.Tier.Passive() {
		t.Fatalf("tier %s, want T1", s.Tier)
	}
	if s.ID() != "enumerate.subdomains@1" || s.DefaultTool() != "dnsx-enum" {
		t.Fatalf("id %s tool %s", s.ID(), s.DefaultTool())
	}
	if !slices.Equal(s.Inputs, []asset.TypeRef{tDomain}) {
		t.Fatalf("inputs %v, want the root domain only", s.Inputs)
	}
	if AcceptsTargetList("dnsx-enum") || s.ChunkSizeFor("dnsx-enum") != 0 {
		t.Fatal("dnsx-enum takes one root per task")
	}
	if ToolNetwork("dnsx-enum") != NetworkTargets {
		t.Fatal("an active stage counts as reaching its targets")
	}
	if IntensityTier("dnsx-enum", nil, nil) != TierActive {
		t.Fatal("a dnsx-enum scan needs the active intensity")
	}
	// The passive discovery tool is unchanged: subfinder stays T0.
	if st := ForTool("subfinder"); len(st) != 1 || st[0].Key != DiscoverSubdomains {
		t.Fatalf("subfinder stages %v", st)
	}
	if k, ok := s.ToolParamKey("dnsx-enum", "method"); !ok || k != "method" {
		t.Fatal("method is the tool's own key")
	}
}

func TestToolWordlists(t *testing.T) {
	want := []WordlistRequest{{Slot: "labels", Purpose: "dns-labels"}}
	if got := ToolWordlists(" DNSX-Enum "); !slices.Equal(got, want) {
		t.Fatalf("dnsx-enum asks for %v, want %v", got, want)
	}
	got := ToolWordlists("dnsx-enum")
	got[0].Slot = "changed"
	if ToolWordlists("dnsx-enum")[0].Slot != "labels" {
		t.Fatal("ToolWordlists returned the table itself")
	}
	for _, tool := range []string{"subfinder", "dnsx", "nuclei", ""} {
		if ToolWordlists(tool) != nil {
			t.Fatalf("%q asks for a wordlist", tool)
		}
	}
}

// The default policy enumerates every scope-entry root domain weekly; a name
// no scope entry covers never gets the rule (scope_entry).
func TestCoverageRules_DomainEnumeratedWeekly(t *testing.T) {
	for _, r := range asset.CoverageRules(asset.AssetTypeDomain, "") {
		if r.Capability != string(EnumerateSubdomains) {
			continue
		}
		if time.Duration(r.EverySeconds)*time.Second != 7*24*time.Hour {
			t.Fatalf("every %ds, want a week", r.EverySeconds)
		}
		if !slices.Contains(r.Requires, "scope_entry") {
			t.Fatalf("requires %v, want scope_entry", r.Requires)
		}
		return
	}
	t.Fatal("domain has no enumerate.subdomains coverage rule")
}
