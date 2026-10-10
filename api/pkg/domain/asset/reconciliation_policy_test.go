package asset

import (
	"errors"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func TestReconciliationPolicy_SourceRules(t *testing.T) {
	now := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	ob := func(kind SourceKind, name, value string, ago time.Duration) AttributeObservation {
		return AttributeObservation{Attribute: AttrExposure, Kind: kind, Name: name, Value: value,
			ObservedAt: now.Add(-ago), IngestedAt: now, Confidence: 100}
	}
	tests := []struct {
		name   string
		rules  []SourceRule
		obs    []AttributeObservation
		want   string // "" = no winner
		status map[string]CandidateStatus
	}{
		{
			name:  "a named source outranks its own kind",
			rules: []SourceRule{{Source: "scan:nmap", Trusted: true}, {Source: "integration", Trusted: true}, {Source: "scan", Trusted: true}},
			obs: []AttributeObservation{
				ob(SourceKindScan, "httpx", "private", time.Minute),
				ob(SourceKindIntegration, "cloud", "restricted", time.Minute),
				ob(SourceKindScan, "nmap", "public", time.Hour),
			},
			want:   "public",
			status: map[string]CandidateStatus{"nmap": CandidateWinner, "cloud": CandidateOutranked, "httpx": CandidateOutranked},
		},
		{
			name:  "an untrusted row keeps its place but never decides",
			rules: []SourceRule{{Source: "scan", Trusted: false}, {Source: "integration", Trusted: true}},
			obs:   []AttributeObservation{ob(SourceKindScan, "naabu", "public", time.Minute), ob(SourceKindIntegration, "cmdb", "private", time.Hour)},
			want:  "private", status: map[string]CandidateStatus{"naabu": CandidateUntrusted},
		},
		{
			name:  "a source without a row is not trusted",
			rules: []SourceRule{{Source: "integration", Trusted: true}},
			obs:   []AttributeObservation{ob(SourceKindFeed, "programfeed", "public", time.Minute)},
			want:  "", status: map[string]CandidateStatus{"programfeed": CandidateUntrusted},
		},
		{
			name:  "the TTL of the matching row applies",
			rules: []SourceRule{{Source: "scan:nmap", TTL: time.Hour, Trusted: true}, {Source: "scan", TTL: 30 * 24 * time.Hour, Trusted: true}},
			obs:   []AttributeObservation{ob(SourceKindScan, "nmap", "public", 2*time.Hour), ob(SourceKindScan, "httpx", "private", 3*time.Hour)},
			want:  "private", status: map[string]CandidateStatus{"nmap": CandidateStale},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := ReconciliationPolicy{Default: tc.rules}
			res := Resolve(AttrExposure, tc.obs, p, now)
			if tc.want == "" {
				if res.Winner != nil {
					t.Fatalf("winner %+v, want none", res.Winner)
				}
			} else if res.Winner == nil || res.Winner.Value != tc.want {
				t.Fatalf("winner %+v, want %s", res.Winner, tc.want)
			}
			for name, want := range tc.status {
				for _, c := range res.Candidates {
					if c.Name == name && c.Status != want {
						t.Errorf("%s: %s, want %s", name, c.Status, want)
					}
				}
			}
		})
	}
}

func TestReconciliationPolicy_ClassesInheritTheDefault(t *testing.T) {
	def := DefaultReconciliationPolicy()
	if def.Trusts(AttrCriticality, SourceKindScan, "nmap") || def.Trusts(AttrOwnerRef, SourceKindFeed, "") {
		t.Fatal("ownership must not trust scanners or feeds by default (D1)")
	}
	if !def.Trusts(AttrExposure, SourceKindScan, "") || def.rank(AttrExposure, AttributeObservation{Kind: SourceKindScan}) != 1 {
		t.Fatal("network exposure: an active scan first by default")
	}
	// A class without its own list uses the organization's default list.
	p := ReconciliationPolicy{Default: []SourceRule{{Source: "feed", Trusted: true}}}
	if !p.Trusts(AttrCriticality, SourceKindFeed, "x") || p.Trusts(AttrCriticality, SourceKindIntegration, "") {
		t.Fatal("ownership should inherit the default list")
	}
	p.Classes = map[AttributeClass][]SourceRule{AttrClassOwnership: {{Source: "integration", Trusted: true}}}
	if p.Trusts(AttrCriticality, SourceKindFeed, "x") || !p.Trusts(AttrExposure, SourceKindFeed, "x") {
		t.Fatal("an overridden class uses its own list; others keep the default")
	}
	// Locks always win, whatever the lists.
	if p.rank(AttrCriticality, AttributeObservation{Kind: SourceKindManual}) != 0 {
		t.Fatal("a lock ranks first")
	}
	for _, c := range AllAttributeClasses() {
		if !c.IsValid() {
			t.Fatalf("%s invalid", c)
		}
	}
	if len(AttrClassOwnership.Attributes()) != 3 || len(AttrClassNetwork.Attributes()) != 1 || len(AttrClassSoftware.Attributes()) != 0 {
		t.Fatal("class membership")
	}
}

func TestPolicyFromSettings(t *testing.T) {
	if p, err := PolicyFromSettings(nil, nil); err != nil || len(p.Classes) != 2 {
		t.Fatalf("empty settings are the defaults: %+v %v", p, err)
	}
	p, err := PolicyFromSettings(
		[]SourceRuleSetting{{Source: "scan:nmap", TTLDays: 7, Trusted: true}, {Source: "integration", TTLDays: 0, Trusted: true}},
		map[string][]SourceRuleSetting{"ownership": {{Source: "import", TTLDays: 90, Trusted: true}}},
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Default) != 2 || p.Default[0].TTL != 7*24*time.Hour || p.Default[1].TTL != 0 {
		t.Fatalf("default = %+v", p.Default)
	}
	if _, ok := p.Classes[AttrClassNetwork]; ok {
		t.Fatal("a class the settings leave out inherits the saved default, not the built-in override")
	}
	if got := SettingsFromRules(p.Default); got[0].Source != "scan:nmap" || got[0].TTLDays != 7 {
		t.Fatalf("round trip = %+v", got)
	}
	if !DefaultReconciliationPolicy().Classes[AttrClassOwnership][0].Trusted {
		t.Fatal("settings changed the defaults")
	}

	long := make([]SourceRuleSetting, MaxSourceRules+1)
	for i := range long {
		long[i] = SourceRuleSetting{Source: "scan:s" + string(rune('a'+i%26)) + string(rune('a'+i/26)), Trusted: true}
	}
	bad := []struct {
		def     []SourceRuleSetting
		classes map[string][]SourceRuleSetting
	}{
		{def: []SourceRuleSetting{{Source: "manual"}}},
		{def: []SourceRuleSetting{{Source: "cmdb"}}},
		{def: []SourceRuleSetting{{Source: "scan"}, {Source: "scan"}}},
		{def: []SourceRuleSetting{{Source: "scan", TTLDays: -1}}},
		{def: []SourceRuleSetting{{Source: "scan", TTLDays: MaxSourceTTLDays + 1}}},
		{def: []SourceRuleSetting{{Source: "scan:" + string(make([]byte, MaxSourceNameLength+1))}}},
		{classes: map[string][]SourceRuleSetting{"hostname": {{Source: "scan"}}}},
		{def: long},
	}
	for i, b := range bad {
		if _, err := PolicyFromSettings(b.def, b.classes); !errors.Is(err, shared.ErrValidation) {
			t.Errorf("case %d: want a validation error, got %v", i, err)
		}
	}
}

func TestDemotesAuthoritative(t *testing.T) {
	r := func(src string, trusted bool) SourceRule { return SourceRule{Source: SourceRef(src), Trusted: trusted} }
	base := ReconciliationPolicy{Default: []SourceRule{r("integration", true), r("scan", true), r("import", true)}}
	tests := []struct {
		name string
		next []SourceRule
		want bool
	}{
		{"unchanged", []SourceRule{r("integration", true), r("scan", true), r("import", true)}, false},
		{"reordering below the connector", []SourceRule{r("integration", true), r("import", true), r("scan", true)}, false},
		{"a TTL change only", []SourceRule{{Source: "integration", TTL: time.Hour, Trusted: true}, r("scan", true), r("import", true)}, false},
		{"a scanner moved above the connector", []SourceRule{r("scan", true), r("integration", true), r("import", true)}, true},
		{"the connector no longer trusted", []SourceRule{r("integration", false), r("scan", true), r("import", true)}, true},
		{"the connector removed", []SourceRule{r("scan", true), r("import", true)}, true},
		{"a new named source above the connector", []SourceRule{r("feed:x", true), r("integration", true), r("scan", true)}, true},
		{"an untrusted row above the connector does not demote it", []SourceRule{r("feed:x", false), r("integration", true), r("scan", true)}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := DemotesAuthoritative(base, ReconciliationPolicy{Default: tc.next}); got != tc.want {
				t.Fatalf("DemotesAuthoritative = %v, want %v", got, tc.want)
			}
		})
	}
	// Overriding one class with a list that drops the connector demotes it.
	next := ReconciliationPolicy{Default: base.Default, Classes: map[AttributeClass][]SourceRule{AttrClassOwnership: {r("import", true)}}}
	if !DemotesAuthoritative(base, next) {
		t.Fatal("a class override dropping the connector must demote")
	}
}

func TestPreviewSnapshots(t *testing.T) {
	now := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	id := shared.NewID()
	snap := AttributeSnapshot{AssetID: id, Name: "db", Current: map[TrackedAttribute]string{AttrCriticality: "high", AttrExposure: "public"},
		Observations: []AttributeObservation{
			{AssetID: id, Attribute: AttrCriticality, Kind: SourceKindIntegration, Name: "cmdb", Value: "high", ObservedAt: now.Add(-time.Hour)},
			{AssetID: id, Attribute: AttrCriticality, Kind: SourceKindImport, Name: "csv", Value: "low", ObservedAt: now.Add(-time.Minute)},
		}}
	pv := &PolicyPreview{}
	PreviewSnapshots(pv, []AttributeSnapshot{snap}, DefaultReconciliationPolicy(), now)
	if pv.ChangedValues != 0 || pv.ScannedAssets != 1 {
		t.Fatalf("defaults change nothing: %+v", pv)
	}
	importFirst := ReconciliationPolicy{Default: []SourceRule{{Source: "import", Trusted: true}, {Source: "integration", Trusted: true}}}
	pv = &PolicyPreview{}
	PreviewSnapshots(pv, []AttributeSnapshot{snap}, importFirst, now)
	if pv.ChangedAssets != 1 || pv.ChangedValues != 1 || len(pv.Samples) != 1 || pv.Samples[0].Next != "low" || pv.Samples[0].NextSource.Name != "csv" {
		t.Fatalf("import first: %+v", pv)
	}
}
