package approvalpolicy

import (
	"math/rand"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func TestFloorsAndDefaults(t *testing.T) {
	for _, k := range Kinds {
		for _, c := range Classes {
			if Default(k, c).Rank() < Floor(k, c).Rank() {
				t.Fatalf("default %s below floor %s for %s.%s", Default(k, c), Floor(k, c), k, c)
			}
			if k.IsAcceptance() && Floor(k, c).Rank() < TierPeer.Rank() {
				t.Fatalf("four-eyes on an acceptance is a floor: %s.%s floor %s", k, c, Floor(k, c))
			}
			if k.IsRule() && Floor(k, c) == TierSingle {
				t.Fatalf("a rule is never single: %s.%s", k, c)
			}
		}
	}
}

func TestPolicyValidate(t *testing.T) {
	bad := []Policy{
		{Tiers: map[string]Tier{"accepted.high": TierPeer}},                // below floor
		{Tiers: map[string]Tier{"accepted.standard": TierSingle}},          // below floor
		{Tiers: map[string]Tier{"rule_false_positive.standard": "single"}}, // below floor
		{Tiers: map[string]Tier{"nope.high": TierDual}},
		{Tiers: map[string]Tier{"accepted.high": "triple"}},
		{SecurityPoolGroupID: "not-a-uuid"},
		{SecurityPoolStrict: true},
		{MaxAcceptanceDays: map[Class]int{ClassHigh: 0}},
		{MaxAcceptanceDays: map[Class]int{ClassHigh: 400}},
		{MaxAcceptanceDays: map[Class]int{"weird": 10}},
		{DecideWithinDays: 15},
		{DecideWithinDays: -1},
		{EPSSThreshold: 0.6},
		{EPSSThreshold: 0.001},
		{OnMaterialChange: MaterialChangePolicy{Accepted: "ignore"}},
		{OnMaterialChange: MaterialChangePolicy{SinglePersonFP: "ignore"}},
	}
	for i, p := range bad {
		if err := p.Validate(); err == nil {
			t.Errorf("case %d: invalid policy accepted: %+v", i, p)
		}
	}
	good := Policy{
		Tiers:               map[string]Tier{"accepted.critical": TierSecurity, "false_positive.high": TierSecurity},
		SecurityPoolGroupID: shared.NewID().String(), SecurityPoolStrict: true, ExcludeAssignee: true,
		MaxAcceptanceDays: map[Class]int{ClassCritical: 7}, DecideWithinDays: 5, EPSSThreshold: 0.1,
		OnMaterialChange: MaterialChangePolicy{Accepted: AcceptedEndOnAnyChange, SinglePersonFP: SinglePersonFPRevoke},
	}
	if err := good.Validate(); err != nil {
		t.Fatalf("valid policy refused: %v", err)
	}
}

func TestRelaxes(t *testing.T) {
	g1, g2 := shared.NewID().String(), shared.NewID().String()
	cases := []struct {
		name     string
		cur, nxt Policy
		relaxes  bool
	}{
		{"same", Policy{}, Policy{}, false},
		{"raise a tier", Policy{}, Policy{Tiers: map[string]Tier{"accepted.standard": TierSecurity}}, false},
		{"relax critical accept to the floor", Policy{}, Policy{Tiers: map[string]Tier{"accepted.critical": TierSecurity}}, true},
		{"drop a raised tier", Policy{Tiers: map[string]Tier{"accepted.standard": TierDual}}, Policy{}, true},
		{"setting a cell to the default is no change", Policy{}, Policy{Tiers: map[string]Tier{"accepted.critical": TierDual}}, false},
		{"set a pool", Policy{}, Policy{SecurityPoolGroupID: g1}, false},
		{"remove the pool", Policy{SecurityPoolGroupID: g1}, Policy{}, true},
		{"change the pool", Policy{SecurityPoolGroupID: g1}, Policy{SecurityPoolGroupID: g2}, true},
		{"strict on", Policy{SecurityPoolGroupID: g1}, Policy{SecurityPoolGroupID: g1, SecurityPoolStrict: true}, false},
		{"strict off", Policy{SecurityPoolGroupID: g1, SecurityPoolStrict: true}, Policy{SecurityPoolGroupID: g1}, true},
		{"assignee rule off", Policy{ExcludeAssignee: true}, Policy{}, true},
		{"shorter cap", Policy{}, Policy{MaxAcceptanceDays: map[Class]int{ClassHigh: 30}}, false},
		{"longer cap", Policy{MaxAcceptanceDays: map[Class]int{ClassHigh: 30}}, Policy{MaxAcceptanceDays: map[Class]int{ClassHigh: 60}}, true},
		{"lower epss threshold", Policy{}, Policy{EPSSThreshold: 0.1}, false},
		{"higher epss threshold", Policy{EPSSThreshold: 0.1}, Policy{EPSSThreshold: 0.3}, true},
		{"shorter deadline", Policy{}, Policy{DecideWithinDays: 3}, false},
		{"longer deadline", Policy{DecideWithinDays: 3}, Policy{DecideWithinDays: 7}, true},
		{"end on any change", Policy{}, Policy{OnMaterialChange: MaterialChangePolicy{Accepted: AcceptedEndOnAnyChange}}, false},
		{"back to the floor", Policy{OnMaterialChange: MaterialChangePolicy{SinglePersonFP: SinglePersonFPRevoke}}, Policy{}, true},
		{"mixed change relaxes", Policy{ExcludeAssignee: true}, Policy{StepUpAllTiers: true}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := Relaxes(tc.cur, tc.nxt); got != tc.relaxes {
				t.Fatalf("Relaxes = %v, want %v (stricter=%+v)", got, tc.relaxes, Stricter(tc.cur, tc.nxt))
			}
		})
	}
}

func randomPolicy(rng *rand.Rand) Policy {
	var p Policy
	for _, k := range Kinds {
		for _, c := range Classes {
			if rng.Intn(3) == 0 {
				if p.Tiers == nil {
					p.Tiers = map[string]Tier{}
				}
				// Deliberately include below-floor values: TierFor and
				// Evaluate must still never go below the floor.
				p.Tiers[cellKey(k, c)] = Tiers[rng.Intn(len(Tiers))]
			}
		}
	}
	if rng.Intn(2) == 0 {
		p.SecurityPoolGroupID = shared.NewID().String()
		p.SecurityPoolStrict = rng.Intn(2) == 0
	}
	p.ExcludeAssignee = rng.Intn(2) == 0
	p.StepUpAllTiers = rng.Intn(2) == 0
	if rng.Intn(2) == 0 {
		p.MaxAcceptanceDays = map[Class]int{Classes[rng.Intn(3)]: 1 + rng.Intn(400)}
	}
	p.DecideWithinDays = rng.Intn(16)
	p.EPSSThreshold = rng.Float64()
	if rng.Intn(2) == 0 {
		p.OnMaterialChange.Accepted = AcceptedEndOnAnyChange
	}
	return p
}

func randomFacts(rng *rand.Rand) Facts {
	sev := []string{"critical", "high", "medium", "low", "info", ""}
	pri := []string{"P0", "P1", "P2", "P3", ""}
	f := Facts{
		Severity: sev[rng.Intn(len(sev))], PriorityClass: pri[rng.Intn(len(pri))],
		KEV: rng.Intn(5) == 0, ExploitValidated: rng.Intn(5) == 0,
		CrownJewel: rng.Intn(4) == 0, InternetExposed: rng.Intn(4) == 0,
	}
	if rng.Intn(2) == 0 {
		e := rng.Float64()
		f.EPSS = &e
	}
	return f
}

// TestProperty_NeverBelowFloor: whatever the organization's policy (even
// one that would not validate), the evaluated tier is never below the
// platform floor, an acceptance always needs another person, the acceptance
// cap never exceeds the platform's, and the stricter of two policies is at
// least as strict as each.
func TestProperty_NeverBelowFloor(t *testing.T) {
	rng := rand.New(rand.NewSource(20261016))
	levels := []string{FPLevelAll, FPLevelHighAndAbove, FPLevelOff, ""}
	u := ids(4)
	for i := 0; i < 5000; i++ {
		p := randomPolicy(rng)
		f := randomFacts(rng)
		k := Kinds[rng.Intn(len(Kinds))]
		r := Evaluate(p, Request{Kind: k, Facts: f, RequesterID: u[0], RequesterCanApprove: rng.Intn(2) == 0,
			FPLevel: levels[rng.Intn(len(levels))], Approvers: pool(u, u[1]), SecurityPoolConfigured: p.SecurityPoolGroupID != ""})
		if r.Tier.Rank() < Floor(k, r.Class).Rank() {
			t.Fatalf("iteration %d: tier %s below floor %s (%+v %+v)", i, r.Tier, Floor(k, r.Class), p, f)
		}
		if k.IsAcceptance() && r.Required < 1 {
			t.Fatalf("iteration %d: acceptance without another approver", i)
		}
		if k.IsAcceptance() && r.MaxAcceptance > PlatformAcceptanceCap(f.PriorityClass, f.KEV) {
			t.Fatalf("iteration %d: cap %v above platform", i, r.MaxAcceptance)
		}
		if r.Tier.NeedsStepUp() && !r.StepUp {
			t.Fatalf("iteration %d: %s without step-up", i, r.Tier)
		}
		if _, err := r.Sign(u[0], nil); err == nil {
			t.Fatalf("iteration %d: the requester signed off their own request", i)
		}
		if r.DecideWithin <= 0 || r.DecideWithin > PlatformDecideWithin {
			t.Fatalf("iteration %d: decide within %v", i, r.DecideWithin)
		}

		q := randomPolicy(rng)
		s := Stricter(p, q)
		for _, kk := range Kinds {
			for _, c := range Classes {
				if s.TierFor(kk, c).Rank() < p.TierFor(kk, c).Rank() || s.TierFor(kk, c).Rank() < q.TierFor(kk, c).Rank() {
					t.Fatalf("iteration %d: Stricter lowered %s.%s", i, kk, c)
				}
			}
		}
		if s.AcceptanceCap(f) > p.AcceptanceCap(f) || s.AcceptanceCap(f) > q.AcceptanceCap(f) {
			t.Fatalf("iteration %d: Stricter lengthened the cap", i)
		}
		if s.DecideWithin() > p.DecideWithin() || s.DecideWithin() > q.DecideWithin() {
			t.Fatalf("iteration %d: Stricter lengthened the deadline", i)
		}
		if Relaxes(p, s) {
			t.Fatalf("iteration %d: moving to the stricter policy counted as relaxing", i)
		}
	}
}

func TestMaterialChange(t *testing.T) {
	end := time.Now().Add(60 * 24 * time.Hour)
	now := time.Now()
	cases := []struct {
		name   string
		policy Policy
		d      Decision
		after  Facts
		want   Action
		signal Signal
	}{
		{"nothing changed", Policy{}, Decision{Kind: KindAccepted, DecidedTier: TierPeer, Baseline: medium, End: &end}, medium, ActionNone, ""},
		{"severity down is not material", Policy{}, Decision{Kind: KindAccepted, DecidedTier: TierSecurity, Baseline: high, End: &end}, medium, ActionNone, ""},
		{"KEV added ends a peer acceptance", Policy{}, Decision{Kind: KindAccepted, DecidedTier: TierPeer, Baseline: medium, End: &end}, Facts{Severity: "medium", PriorityClass: "P2", KEV: true}, ActionEnd, SignalKEVAdded},
		{"severity up to high ends a peer acceptance", Policy{}, Decision{Kind: KindAccepted, DecidedTier: TierPeer, Baseline: medium, End: &end}, high, ActionEnd, SignalSeverityRaised},
		{"EPSS crossing ends a peer acceptance", Policy{}, Decision{Kind: KindAccepted, DecidedTier: TierPeer, Baseline: epssLow, End: &end}, epssHigh, ActionEnd, SignalEPSSCrossed},
		{"exploit validated ends a peer acceptance", Policy{}, Decision{Kind: KindAccepted, DecidedTier: TierPeer, Baseline: low, End: &end}, Facts{Severity: "low", PriorityClass: "P3", ExploitValidated: true}, ActionEnd, SignalExploitValidated},
		{"internet exposure ends a peer acceptance", Policy{}, Decision{Kind: KindAccepted, DecidedTier: TierPeer, Baseline: medium, End: &end}, Facts{Severity: "medium", PriorityClass: "P2", InternetExposed: true}, ActionEnd, SignalExposureRaised},
		{"a dual acceptance with EPSS rising is flagged", Policy{}, Decision{Kind: KindAccepted, DecidedTier: TierDual, Baseline: Facts{Severity: "critical", PriorityClass: "P2", EPSS: f64(0.1)}, End: &end}, Facts{Severity: "critical", PriorityClass: "P2", EPSS: f64(0.9)}, ActionFlag, SignalEPSSCrossed},
		{"end on any change", Policy{OnMaterialChange: MaterialChangePolicy{Accepted: AcceptedEndOnAnyChange}}, Decision{Kind: KindAccepted, DecidedTier: TierDual, Baseline: Facts{Severity: "critical", PriorityClass: "P2", EPSS: f64(0.1)}, End: &end}, Facts{Severity: "critical", PriorityClass: "P2", EPSS: f64(0.9)}, ActionEnd, SignalEPSSCrossed},
		{"priority to P0 shortens the cap below the end", Policy{}, Decision{Kind: KindAccepted, DecidedTier: TierDual, Baseline: Facts{Severity: "critical", PriorityClass: "P2"}, End: &end}, Facts{Severity: "critical", PriorityClass: "P0"}, ActionEnd, SignalPriorityRaised},
		{"pre-tier decision uses its baseline tier", Policy{}, Decision{Kind: KindAccepted, Baseline: medium, End: &end}, high, ActionEnd, SignalSeverityRaised},
		{"single-person fp flagged", Policy{}, Decision{Kind: KindFalsePositive, Baseline: low}, Facts{Severity: "low", KEV: true}, ActionFlag, SignalKEVAdded},
		{"single-person fp revoked by policy", Policy{OnMaterialChange: MaterialChangePolicy{SinglePersonFP: SinglePersonFPRevoke}}, Decision{Kind: KindFalsePositive, Baseline: low}, high, ActionRevoke, SignalSeverityRaised},
		{"single-person fp, nothing changed", Policy{}, Decision{Kind: KindFalsePositive, Baseline: low}, low, ActionNone, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ch := MaterialChange(tc.policy, tc.d, tc.after, now)
			if ch.Action != tc.want {
				t.Fatalf("action %s, want %s (signals %v tierNow %s)", ch.Action, tc.want, ch.Signals, ch.TierNow)
			}
			if tc.signal != "" {
				found := false
				for _, s := range ch.Signals {
					found = found || s == tc.signal
				}
				if !found {
					t.Fatalf("signal %s missing: %v", tc.signal, ch.Signals)
				}
			}
		})
	}
}

func TestWorstFacts(t *testing.T) {
	w := WorstFacts([]Facts{low, {Severity: "high", EPSS: f64(0.3)}, {Severity: "medium", PriorityClass: "P1", KEV: true, EPSS: f64(0.1)}})
	if w.Severity != "high" || w.PriorityClass != "P1" || !w.KEV || w.EPSS == nil || *w.EPSS != 0.3 {
		t.Fatalf("worst facts %+v", w)
	}
	if c, _ := ClassOf(KindRuleAccepted, w, 0); c != ClassCritical {
		t.Fatalf("class %s", c)
	}
}

func TestPlatformAcceptanceCap(t *testing.T) {
	day := 24 * time.Hour
	for _, tc := range []struct {
		p    string
		kev  bool
		want time.Duration
	}{{"P0", false, 30 * day}, {"P3", true, 30 * day}, {"P1", false, 90 * day}, {"P2", false, 180 * day}, {"P3", false, 365 * day}, {"", false, 365 * day}} {
		if got := PlatformAcceptanceCap(tc.p, tc.kev); got != tc.want {
			t.Fatalf("%s/%v: %v want %v", tc.p, tc.kev, got, tc.want)
		}
	}
}

// A false-positive cell equal to the platform default still raises the
// organization's lower false-positive level after a save (Normalized keeps
// it), and removing it is a relaxation.
func TestNormalized_KeepsFalsePositiveCells(t *testing.T) {
	p := Policy{Tiers: map[string]Tier{"false_positive.standard": TierPeer, "accepted.standard": TierPeer}}.Normalized()
	if p.Tiers["false_positive.standard"] != TierPeer {
		t.Fatalf("false-positive cell dropped: %v", p.Tiers)
	}
	if _, ok := p.Tiers["accepted.standard"]; ok {
		t.Fatalf("a non-false-positive cell equal to the default was kept: %v", p.Tiers)
	}
	u := ids(2)
	r := Evaluate(p, Request{Kind: KindFalsePositive, Facts: low, RequesterID: u[0], RequesterCanApprove: true, FPLevel: FPLevelOff, Approvers: pool(u)})
	if r.Tier != TierPeer {
		t.Fatalf("level off with an explicit peer cell: %s", r.Tier)
	}
	if !Relaxes(p, Policy{}) {
		t.Fatal("removing the false-positive cell is a relaxation")
	}
	if Relaxes(Policy{}, p) {
		t.Fatal("adding a false-positive cell is not a relaxation")
	}
}
