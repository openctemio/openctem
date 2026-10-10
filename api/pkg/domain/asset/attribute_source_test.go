package asset

import (
	"errors"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func TestResolve(t *testing.T) {
	now := time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)
	ago := func(d time.Duration) time.Time { return now.Add(-d) }
	day := 24 * time.Hour
	ob := func(attr TrackedAttribute, kind SourceKind, name, value string, observed time.Time) AttributeObservation {
		return AttributeObservation{Attribute: attr, Kind: kind, Name: name, Value: value,
			ObservedAt: observed, IngestedAt: now, Confidence: 100}
	}
	def := DefaultReconciliationPolicy()

	tests := []struct {
		name         string
		attr         TrackedAttribute
		obs          []AttributeObservation
		policy       ReconciliationPolicy
		wantValue    string // "" with wantNone: no winner
		wantNone     bool
		wantLocked   bool
		wantConflict bool
		wantStatus   map[string]CandidateStatus // by source name
	}{
		{
			name: "higher precedence wins over a more recent lower one",
			attr: AttrCriticality,
			obs: []AttributeObservation{
				ob(AttrCriticality, SourceKindImport, "csv", "low", ago(time.Hour)),
				ob(AttrCriticality, SourceKindIntegration, "cmdb", "high", ago(5*day)),
			},
			wantValue: "high", wantConflict: true,
			wantStatus: map[string]CandidateStatus{"cmdb": CandidateWinner, "csv": CandidateOutranked},
		},
		{
			name: "same rank: the most recent observation wins, not the last ingested",
			attr: AttrOwnerRef,
			obs: []AttributeObservation{
				// ingested later but observed earlier (out of order)
				{Attribute: AttrOwnerRef, Kind: SourceKindIntegration, Name: "a", Value: "old@x.io",
					ObservedAt: ago(3 * day), IngestedAt: now, Confidence: 100},
				{Attribute: AttrOwnerRef, Kind: SourceKindIntegration, Name: "b", Value: "new@x.io",
					ObservedAt: ago(day), IngestedAt: ago(2 * time.Hour), Confidence: 100},
			},
			wantValue: "new@x.io", wantConflict: true,
		},
		{
			name: "same rank and time: confidence breaks the tie",
			attr: AttrDataClassification,
			obs: []AttributeObservation{
				{Attribute: AttrDataClassification, Kind: SourceKindImport, Name: "a", Value: "internal", ObservedAt: ago(day), IngestedAt: now, Confidence: 40},
				{Attribute: AttrDataClassification, Kind: SourceKindImport, Name: "b", Value: "restricted", ObservedAt: ago(day), IngestedAt: now, Confidence: 90},
			},
			wantValue: "restricted", wantConflict: true,
		},
		{
			name: "a manual lock wins over every source, however recent",
			attr: AttrExposure,
			obs: []AttributeObservation{
				ob(AttrExposure, SourceKindScan, "httpx", "public", ago(time.Minute)),
				ob(AttrExposure, SourceKindManual, "user-1", "private", ago(400*day)),
			},
			wantValue: "private", wantLocked: true, wantConflict: true,
		},
		{
			name:      "a lock never goes stale",
			attr:      AttrCriticality,
			obs:       []AttributeObservation{ob(AttrCriticality, SourceKindManual, "u", "critical", ago(1000*day))},
			wantValue: "critical", wantLocked: true,
		},
		{
			name:       "scanners are not trusted for criticality by default",
			attr:       AttrCriticality,
			obs:        []AttributeObservation{ob(AttrCriticality, SourceKindScan, "nuclei", "low", ago(time.Hour))},
			wantNone:   true,
			wantStatus: map[string]CandidateStatus{"nuclei": CandidateUntrusted},
		},
		{
			name: "an untrusted source does not count as a conflict",
			attr: AttrOwnerRef,
			obs: []AttributeObservation{
				ob(AttrOwnerRef, SourceKindScan, "evil", "attacker@x.io", ago(time.Minute)),
				ob(AttrOwnerRef, SourceKindImport, "csv", "owner@x.io", ago(10*day)),
			},
			wantValue: "owner@x.io",
		},
		{
			name: "a stale higher-rank source stops winning",
			attr: AttrCriticality,
			obs: []AttributeObservation{
				ob(AttrCriticality, SourceKindIntegration, "cmdb", "critical", ago(31*day)),
				ob(AttrCriticality, SourceKindImport, "csv", "medium", ago(2*day)),
			},
			wantValue:  "medium",
			wantStatus: map[string]CandidateStatus{"cmdb": CandidateStale, "csv": CandidateWinner},
		},
		{
			name:     "every source stale: no winner, the asset keeps its value",
			attr:     AttrCriticality,
			obs:      []AttributeObservation{ob(AttrCriticality, SourceKindIntegration, "cmdb", "critical", ago(60*day))},
			wantNone: true,
		},
		{
			name: "scan beats integration for exposure by default",
			attr: AttrExposure,
			obs: []AttributeObservation{
				ob(AttrExposure, SourceKindIntegration, "cloud", "private", ago(time.Hour)),
				ob(AttrExposure, SourceKindScan, "naabu", "public", ago(2*day)),
			},
			wantValue: "public", wantConflict: true,
		},
		{
			name: "tenant policy reorders and drops kinds",
			attr: AttrExposure,
			obs: []AttributeObservation{
				ob(AttrExposure, SourceKindIntegration, "cloud", "private", ago(time.Hour)),
				ob(AttrExposure, SourceKindScan, "naabu", "public", ago(2*day)),
			},
			policy: ReconciliationPolicy{Precedence: map[TrackedAttribute][]SourceKind{
				AttrExposure: {SourceKindManual, SourceKindIntegration},
			}},
			wantValue:  "private",
			wantStatus: map[string]CandidateStatus{"naabu": CandidateUntrusted},
		},
		{
			name: "agreeing sources are not a conflict",
			attr: AttrExposure,
			obs: []AttributeObservation{
				ob(AttrExposure, SourceKindScan, "naabu", "public", ago(time.Hour)),
				ob(AttrExposure, SourceKindScan, "httpx", "public", ago(2*time.Hour)),
			},
			wantValue: "public",
		},
		{
			name:     "observations of other attributes are ignored",
			attr:     AttrCriticality,
			obs:      []AttributeObservation{ob(AttrExposure, SourceKindManual, "u", "public", ago(time.Hour))},
			wantNone: true,
		},
		{
			name: "a manual empty value (cleared) wins as a lock",
			attr: AttrOwnerRef,
			obs: []AttributeObservation{
				ob(AttrOwnerRef, SourceKindIntegration, "cmdb", "someone@x.io", ago(time.Hour)),
				ob(AttrOwnerRef, SourceKindManual, "u", "", ago(day)),
			},
			wantValue: "", wantLocked: true, wantConflict: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := tc.policy
			if p.Precedence == nil {
				p = def
			}
			res := Resolve(tc.attr, tc.obs, p, now)
			if tc.wantNone {
				if res.Winner != nil {
					t.Fatalf("want no winner, got %q from %s", res.Winner.Value, res.Winner.Name)
				}
			} else {
				if res.Winner == nil {
					t.Fatalf("want winner %q, got none", tc.wantValue)
				}
				if res.Winner.Value != tc.wantValue {
					t.Fatalf("winner = %q (%s), want %q", res.Winner.Value, res.Winner.Name, tc.wantValue)
				}
				if res.Candidates[0].Status != CandidateWinner {
					t.Fatalf("first candidate is %s, want the winner first", res.Candidates[0].Status)
				}
			}
			if res.Locked != tc.wantLocked {
				t.Errorf("locked = %v, want %v", res.Locked, tc.wantLocked)
			}
			if res.Conflict != tc.wantConflict {
				t.Errorf("conflict = %v, want %v", res.Conflict, tc.wantConflict)
			}
			for name, want := range tc.wantStatus {
				found := false
				for _, c := range res.Candidates {
					if c.Name == name {
						found = true
						if c.Status != want {
							t.Errorf("%s status = %s, want %s", name, c.Status, want)
						}
					}
				}
				if !found {
					t.Errorf("candidate %s missing", name)
				}
			}
		})
	}
}

func TestPolicyFromSettings(t *testing.T) {
	p, err := PolicyFromSettings(map[string][]string{"criticality": {"scan", "integration"}}, map[string]int{"scan": 0, "import": 7})
	if err != nil {
		t.Fatal(err)
	}
	if got := p.Precedence[AttrCriticality]; len(got) != 3 || got[0] != SourceKindManual || got[1] != SourceKindScan {
		t.Fatalf("criticality precedence = %v", got)
	}
	if got := p.Precedence[AttrExposure]; len(got) != 4 {
		t.Fatalf("exposure keeps the default, got %v", got)
	}
	if p.TTL[SourceKindScan] != 0 || p.TTL[SourceKindImport] != 7*24*time.Hour {
		t.Fatalf("ttl = %v", p.TTL)
	}
	if p.TTL[SourceKindIntegration] != 30*24*time.Hour {
		t.Fatalf("integration ttl keeps the default, got %v", p.TTL[SourceKindIntegration])
	}
	// A tenant's settings never change the default policy.
	if DefaultReconciliationPolicy().Trusts(AttrCriticality, SourceKindScan) {
		t.Fatal("default policy changed")
	}

	bad := []struct {
		prec map[string][]string
		ttl  map[string]int
	}{
		{prec: map[string][]string{"name": {"scan"}}},
		{prec: map[string][]string{"criticality": {"manual"}}},
		{prec: map[string][]string{"criticality": {"cmdb"}}},
		{prec: map[string][]string{"criticality": {"scan", "scan"}}},
		{ttl: map[string]int{"manual": 1}},
		{ttl: map[string]int{"scan": -1}},
		{ttl: map[string]int{"scan": MaxSourceTTLDays + 1}},
	}
	for i, b := range bad {
		if _, err := PolicyFromSettings(b.prec, b.ttl); !errors.Is(err, shared.ErrValidation) {
			t.Errorf("case %d: want a validation error, got %v", i, err)
		}
	}
}

func TestResolveIsDeterministic(t *testing.T) {
	now := time.Now()
	obs := []AttributeObservation{
		{Attribute: AttrExposure, Kind: SourceKindScan, Name: "b", Value: "public", ObservedAt: now, IngestedAt: now, Confidence: 50},
		{Attribute: AttrExposure, Kind: SourceKindScan, Name: "a", Value: "restricted", ObservedAt: now, IngestedAt: now, Confidence: 50},
	}
	first := Resolve(AttrExposure, obs, DefaultReconciliationPolicy(), now).Winner.Name
	obs[0], obs[1] = obs[1], obs[0]
	if second := Resolve(AttrExposure, obs, DefaultReconciliationPolicy(), now).Winner.Name; first != second {
		t.Fatalf("winner depends on input order: %s then %s", first, second)
	}
}

func TestNormalizeAttributeValue(t *testing.T) {
	cases := []struct {
		attr    TrackedAttribute
		in, out string
		bad     bool
	}{
		{AttrCriticality, "HIGH", "high", false},
		{AttrCriticality, "urgent", "", true},
		{AttrExposure, "public", "public", false},
		{AttrExposure, "everywhere", "", true},
		{AttrDataClassification, "Restricted", "restricted", false},
		{AttrDataClassification, "", "", false},
		{AttrDataClassification, "top", "", true},
		{AttrOwnerRef, "  a@b.io ", "a@b.io", false},
		{AttrOwnerRef, string(make([]byte, MaxOwnerRefLength+1)), "", true},
		{TrackedAttribute("name"), "x", "", true},
	}
	for _, c := range cases {
		got, err := NormalizeAttributeValue(c.attr, c.in)
		if c.bad {
			if !errors.Is(err, shared.ErrValidation) {
				t.Errorf("%s %q: want validation error, got %v", c.attr, c.in, err)
			}
			continue
		}
		if err != nil || got != c.out {
			t.Errorf("%s %q = %q, %v; want %q", c.attr, c.in, got, err, c.out)
		}
	}
}

func TestSetAttributeValueRoundTrip(t *testing.T) {
	a, err := NewAsset("db.example.com", AssetTypeHost, CriticalityMedium)
	if err != nil {
		t.Fatal(err)
	}
	for attr, v := range map[TrackedAttribute]string{
		AttrCriticality: "critical", AttrOwnerRef: "o@x.io", AttrExposure: "public", AttrDataClassification: "confidential",
	} {
		if err := a.SetAttributeValue(attr, v); err != nil {
			t.Fatalf("%s: %v", attr, err)
		}
		if got := a.AttributeValue(attr); got != v {
			t.Fatalf("%s = %q, want %q", attr, got, v)
		}
	}
}
