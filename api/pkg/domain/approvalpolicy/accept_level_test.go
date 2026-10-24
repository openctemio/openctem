package approvalpolicy

import (
	"testing"
	"time"
)

// The organization's risk acceptance level gates who decides an accepted
// risk of one finding: all (and anything unknown or unset) keeps a second
// person; high_and_above lets one person decide a finding that is not
// material (the false-positive classifier); off lets one person decide any.
func TestEvaluate_AcceptLevelGatesAcceptedRisk(t *testing.T) {
	people := ids(3)
	base := func(level string, f Facts) Request {
		return Request{Kind: KindAccepted, Facts: f, RequesterID: people[0], RequesterCanApprove: true,
			AcceptLevel: level, Approvers: pool(people)}
	}
	material := []Facts{high, critical, kevLow, p1Low, p0Medium, exploit, exposed, jewelHi, epssHigh}
	for _, level := range []string{"", FPLevelAll, "sometimes"} {
		for _, f := range append([]Facts{low, medium}, material...) {
			if r := Evaluate(Policy{}, base(level, f)); r.SinglePerson() || r.Required < 1 {
				t.Fatalf("level %q, %+v: decided alone (tier %s)", level, f, r.Tier)
			}
		}
	}
	for _, f := range []Facts{low, medium, epssLow} {
		r := Evaluate(Policy{}, base(FPLevelHighAndAbove, f))
		if !r.SinglePerson() || r.Required != 0 || r.Floor != TierSingle || !hasReason(r, ReasonAcceptLevel) {
			t.Fatalf("high_and_above, %+v: %+v", f, r)
		}
		if r.MaxAcceptance <= 0 {
			t.Fatal("a single-person acceptance lost its cap")
		}
	}
	for _, f := range material {
		if r := Evaluate(Policy{}, base(FPLevelHighAndAbove, f)); r.SinglePerson() {
			t.Fatalf("high_and_above, material %+v: decided alone", f)
		}
	}
	for _, f := range append([]Facts{low, medium}, material...) {
		if r := Evaluate(Policy{}, base(FPLevelOff, f)); !r.SinglePerson() {
			t.Fatalf("off, %+v: tier %s", f, r.Tier)
		}
	}
	// The risk acceptance level never touches a false positive, and the
	// false-positive level never touches an accepted risk.
	fp := base(FPLevelOff, low)
	fp.Kind = KindFalsePositive
	if r := Evaluate(Policy{}, fp); r.SinglePerson() {
		t.Fatal("the risk acceptance level decided a false positive")
	}
	acc := base("", low)
	acc.FPLevel = FPLevelOff
	if r := Evaluate(Policy{}, acc); r.SinglePerson() {
		t.Fatal("the false-positive level decided an accepted risk")
	}
}

// No bypass: whatever the level, nothing but a person's own request on one
// finding, by a holder of the approve permission who does not own the
// asset, decides alone. Suppression rules, automation (actor) requests,
// requesters without the permission, asset owners and group decisions keep
// a second person.
func TestEvaluate_AcceptLevelNoBypass(t *testing.T) {
	people := ids(3)
	for _, level := range []string{FPLevelOff, FPLevelHighAndAbove} {
		rule := Evaluate(Policy{}, Request{Kind: KindRuleAccepted, Facts: low, RequesterID: people[0],
			RequesterCanApprove: true, AcceptLevel: level, Approvers: pool(people)})
		if rule.SinglePerson() || rule.Floor == TierSingle {
			t.Fatalf("%s: an accepted-risk rule was decided alone", level)
		}
		actor := Evaluate(Policy{}, Request{Kind: KindAccepted, Facts: low, ActorMade: true,
			AcceptLevel: level, Approvers: pool(people)})
		if actor.SinglePerson() || actor.Required < 2 {
			t.Fatalf("%s: an automation request: tier %s, required %d", level, actor.Tier, actor.Required)
		}
		noPerm := Evaluate(Policy{}, Request{Kind: KindAccepted, Facts: low, RequesterID: people[0],
			AcceptLevel: level, Approvers: pool(people)})
		if noPerm.SinglePerson() || !hasReason(noPerm, ReasonRequesterCannotSelf) {
			t.Fatalf("%s: a requester without the approve permission decided alone", level)
		}
		owner := Evaluate(Policy{}, Request{Kind: KindAccepted, Facts: low, RequesterID: people[0],
			RequesterCanApprove: true, AcceptLevel: level, AssetOwners: people[:1], Approvers: pool(people)})
		if owner.SinglePerson() || !hasReason(owner, ReasonRequesterOwnsAsset) {
			t.Fatalf("%s: the asset's owner decided alone", level)
		}
		single := Evaluate(Policy{}, Request{Kind: KindAccepted, Facts: low, RequesterID: people[0],
			RequesterCanApprove: true, AcceptLevel: level, Approvers: pool(people)})
		if g := Combine(Policy{}, false, []Result{single, single}); g.SinglePerson() || g.Required < 1 {
			t.Fatalf("%s: a group decision was decided alone", level)
		}
	}
}

// An organization cell above the platform default (an explicit tightening)
// still applies under a relaxing level; a cell at or below the default does
// not.
func TestEvaluate_AcceptLevelKeepsExplicitTightening(t *testing.T) {
	people := ids(3)
	req := Request{Kind: KindAccepted, Facts: low, RequesterID: people[0], RequesterCanApprove: true,
		AcceptLevel: FPLevelOff, Approvers: pool(people)}
	tight := Policy{Tiers: map[string]Tier{"accepted.standard": TierSecurity}}
	if r := Evaluate(tight, req); r.Tier != TierSecurity {
		t.Fatalf("tightened cell under off: tier %s", r.Tier)
	}
	relaxed := Policy{Tiers: map[string]Tier{"accepted.critical": TierSecurity}}
	req.Facts = critical
	if r := Evaluate(relaxed, req); !r.SinglePerson() {
		t.Fatalf("a cell below the default blocked off: tier %s", r.Tier)
	}
}

// A cell can never put an accepted risk below the platform floor: the level
// is the only way to one person.
func TestPolicy_AcceptedCellCannotBeSingle(t *testing.T) {
	if err := (Policy{Tiers: map[string]Tier{"accepted.standard": TierSingle}}).Validate(); err == nil {
		t.Fatal("a single accepted cell was accepted")
	}
}

// A material change to an acceptance one person decided: under off the tier
// stays single, so the decision is flagged for review (ended only under
// end_on_any_change); under high_and_above a finding that became material
// needs a second person now, so the acceptance ends.
func TestMaterialChange_SinglePersonAcceptance(t *testing.T) {
	end := time.Now().Add(30 * 24 * time.Hour)
	d := Decision{Kind: KindAccepted, DecidedTier: TierSingle, Baseline: low, End: &end, AcceptLevel: FPLevelOff}
	raised := Facts{Severity: "high", PriorityClass: "P3"}
	if ch := MaterialChange(Policy{}, d, raised, time.Now()); ch.Action != ActionFlag {
		t.Fatalf("off, severity raised: %s", ch.Action)
	}
	anyChange := Policy{OnMaterialChange: MaterialChangePolicy{Accepted: AcceptedEndOnAnyChange}}
	if ch := MaterialChange(anyChange, d, raised, time.Now()); ch.Action != ActionEnd {
		t.Fatalf("off, end_on_any_change: %s", ch.Action)
	}
	d.AcceptLevel = FPLevelHighAndAbove
	if ch := MaterialChange(Policy{}, d, raised, time.Now()); ch.Action != ActionEnd || ch.TierNow == TierSingle {
		t.Fatalf("high_and_above, became material: %s (tier now %s)", ch.Action, ch.TierNow)
	}
	// The level raised back to all after the decision: any change ends it.
	d.AcceptLevel = FPLevelAll
	if ch := MaterialChange(Policy{}, d, Facts{Severity: "low", PriorityClass: "P2"}, time.Now()); ch.Action != ActionEnd {
		t.Fatalf("level all, priority raised: %s", ch.Action)
	}
	// Nothing material: nothing happens.
	d.AcceptLevel = FPLevelOff
	if ch := MaterialChange(Policy{}, d, low, time.Now()); ch.Action != ActionNone {
		t.Fatalf("no change: %s", ch.Action)
	}
}

func TestLevelNeedsSecond(t *testing.T) {
	cases := []struct {
		level    string
		material bool
		want     bool
	}{
		{"", false, true}, {FPLevelAll, false, true}, {"bogus", false, true},
		{FPLevelHighAndAbove, true, true}, {FPLevelHighAndAbove, false, false},
		{FPLevelOff, true, false}, {FPLevelOff, false, false},
	}
	for _, c := range cases {
		if got := LevelNeedsSecond(c.level, c.material); got != c.want {
			t.Fatalf("LevelNeedsSecond(%q, %v) = %v", c.level, c.material, got)
		}
	}
}
