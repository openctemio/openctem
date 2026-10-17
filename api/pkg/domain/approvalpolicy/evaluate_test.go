package approvalpolicy

import (
	"errors"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func f64(v float64) *float64 { return &v }

var (
	low      = Facts{Severity: "low", PriorityClass: "P3"}
	medium   = Facts{Severity: "medium", PriorityClass: "P2"}
	high     = Facts{Severity: "high", PriorityClass: "P2"}
	critical = Facts{Severity: "critical", PriorityClass: "P1"}
	kevLow   = Facts{Severity: "low", KEV: true}
	p0Medium = Facts{Severity: "medium", PriorityClass: "P0"}
	p1Low    = Facts{Severity: "low", PriorityClass: "P1"}
	epssHigh = Facts{Severity: "medium", EPSS: f64(0.62)}
	epssLow  = Facts{Severity: "medium", EPSS: f64(0.2)}
	exploit  = Facts{Severity: "low", ExploitValidated: true}
	exposed  = Facts{Severity: "medium", InternetExposed: true}
	jewelHi  = Facts{Severity: "high", CrownJewel: true}
)

func TestClassOf(t *testing.T) {
	cases := []struct {
		name  string
		kind  Kind
		facts Facts
		epss  float64
		want  Class
	}{
		{"low", KindAccepted, low, 0, ClassStandard},
		{"medium", KindAccepted, medium, 0, ClassStandard},
		{"high", KindAccepted, high, 0, ClassHigh},
		{"critical", KindAccepted, critical, 0, ClassCritical},
		{"kev on low is critical", KindAccepted, kevLow, 0, ClassCritical},
		{"P0 on medium is critical", KindAccepted, p0Medium, 0, ClassCritical},
		{"P1 on low is high", KindAccepted, p1Low, 0, ClassHigh},
		{"epss above platform threshold", KindAccepted, epssHigh, 0, ClassHigh},
		{"epss below platform threshold", KindAccepted, epssLow, 0, ClassStandard},
		{"epss below platform but above a lowered threshold", KindAccepted, epssLow, 0.1, ClassHigh},
		{"a threshold above the platform's is ignored", KindAccepted, epssHigh, 0.9, ClassHigh},
		{"validated exploit", KindAccepted, exploit, 0, ClassHigh},
		{"internet exposed raises an acceptance", KindAccepted, exposed, 0, ClassHigh},
		{"internet exposed does not raise a false positive", KindFalsePositive, exposed, 0, ClassStandard},
		{"crown jewel raises high to critical", KindRuleAccepted, jewelHi, 0, ClassCritical},
		{"critical stays critical", KindAccepted, Facts{Severity: "critical", CrownJewel: true}, 0, ClassCritical},
		{"unknown severity is standard", KindAccepted, Facts{Severity: "weird"}, 0, ClassStandard},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, _ := ClassOf(tc.kind, tc.facts, tc.epss)
			if got != tc.want {
				t.Fatalf("ClassOf = %s, want %s", got, tc.want)
			}
		})
	}
}

// approvers builds a pool: ids[0] is the requester in most cases.
func ids(n int) []shared.ID {
	out := make([]shared.ID, n)
	for i := range out {
		out[i] = shared.NewID()
	}
	return out
}

func pool(all []shared.ID, inPool ...shared.ID) []Candidate {
	out := make([]Candidate, 0, len(all))
	for _, id := range all {
		out = append(out, Candidate{UserID: id, InSecurityPool: containsID(inPool, id)})
	}
	return out
}

// TestPolicyMatrix is the golden table of the default policy (RFC-111 §3.1)
// plus organization raises and false-positive levels.
func TestPolicyMatrix(t *testing.T) {
	u := ids(4)
	cases := []struct {
		name     string
		policy   Policy
		kind     Kind
		facts    Facts
		fpLevel  string
		canSelf  bool
		wantTier Tier
		wantReq  int
		stepUp   bool
	}{
		// Accepted risk: four-eyes always; security from high; dual for critical by default.
		{"accept low", Policy{}, KindAccepted, low, "", true, TierPeer, 1, false},
		{"accept medium", Policy{}, KindAccepted, medium, "", true, TierPeer, 1, false},
		{"accept high", Policy{}, KindAccepted, high, "", true, TierSecurity, 1, true},
		{"accept critical", Policy{}, KindAccepted, critical, "", true, TierDual, 2, true},
		{"accept KEV low", Policy{}, KindAccepted, kevLow, "", true, TierDual, 2, true},
		{"accept P0", Policy{}, KindAccepted, p0Medium, "", true, TierDual, 2, true},
		{"accept EPSS high", Policy{}, KindAccepted, epssHigh, "", true, TierSecurity, 1, true},
		{"accept on internet-exposed medium", Policy{}, KindAccepted, exposed, "", true, TierSecurity, 1, true},
		{"accept on crown-jewel high", Policy{}, KindAccepted, jewelHi, "", true, TierDual, 2, true},
		{"accept critical relaxed to the floor", Policy{Tiers: map[string]Tier{"accepted.critical": TierSecurity}}, KindAccepted, critical, "", true, TierSecurity, 1, true},
		{"accept medium raised to dual", Policy{Tiers: map[string]Tier{"accepted.standard": TierDual}}, KindAccepted, medium, "", true, TierDual, 2, true},
		{"accept: a below-floor cell is clamped", Policy{Tiers: map[string]Tier{"accepted.standard": TierSingle}}, KindAccepted, low, "", true, TierPeer, 1, false},
		{"accept low with step-up for every tier", Policy{StepUpAllTiers: true}, KindAccepted, low, "", true, TierPeer, 1, true},

		// False positive: the organization's level.
		{"fp low, level all", Policy{}, KindFalsePositive, low, FPLevelAll, true, TierPeer, 1, false},
		{"fp critical, level all", Policy{}, KindFalsePositive, critical, FPLevelAll, true, TierPeer, 1, false},
		{"fp low, high_and_above", Policy{}, KindFalsePositive, low, FPLevelHighAndAbove, true, TierSingle, 0, false},
		{"fp high, high_and_above", Policy{}, KindFalsePositive, high, FPLevelHighAndAbove, true, TierPeer, 1, false},
		{"fp exposed medium, high_and_above", Policy{}, KindFalsePositive, exposed, FPLevelHighAndAbove, true, TierPeer, 1, false},
		{"fp epss high, high_and_above", Policy{}, KindFalsePositive, epssHigh, FPLevelHighAndAbove, true, TierPeer, 1, false},
		{"fp critical, off", Policy{}, KindFalsePositive, critical, FPLevelOff, true, TierSingle, 0, false},
		{"fp off but requester cannot approve", Policy{}, KindFalsePositive, low, FPLevelOff, false, TierPeer, 1, false},
		{"fp off, critical raised by the organization", Policy{Tiers: map[string]Tier{"false_positive.critical": TierSecurity}}, KindFalsePositive, critical, FPLevelOff, true, TierSecurity, 1, true},
		{"fp off, organization cell peer for standard", Policy{Tiers: map[string]Tier{"false_positive.standard": TierPeer}}, KindFalsePositive, low, FPLevelOff, true, TierPeer, 1, false},

		// Suppression rules: never single.
		{"rule fp low", Policy{}, KindRuleFalsePositive, low, FPLevelOff, true, TierPeer, 1, false},
		{"rule fp high", Policy{}, KindRuleFalsePositive, high, "", true, TierSecurity, 1, true},
		{"rule accept critical", Policy{}, KindRuleAccepted, critical, "", true, TierDual, 2, true},
		{"rule fp critical relaxed to the floor", Policy{Tiers: map[string]Tier{"rule_false_positive.critical": TierPeer}}, KindRuleFalsePositive, critical, "", true, TierPeer, 1, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := Evaluate(tc.policy, Request{
				Kind: tc.kind, Facts: tc.facts, RequesterID: u[0], RequesterCanApprove: tc.canSelf,
				FPLevel: tc.fpLevel, Approvers: pool(u, u[1], u[2]), SecurityPoolConfigured: true,
			})
			if r.Tier != tc.wantTier || r.Required != tc.wantReq || r.StepUp != tc.stepUp {
				t.Fatalf("tier=%s required=%d stepUp=%v, want %s/%d/%v (reasons %v)",
					r.Tier, r.Required, r.StepUp, tc.wantTier, tc.wantReq, tc.stepUp, r.Reasons)
			}
			if r.Tier.Rank() < Floor(tc.kind, r.Class).Rank() {
				t.Fatalf("tier %s below floor %s", r.Tier, Floor(tc.kind, r.Class))
			}
		})
	}
}

func TestEvaluate_AssetOwnerNeverDecides(t *testing.T) {
	u := ids(4)
	// The requester owns the asset: no single-person false positive.
	r := Evaluate(Policy{}, Request{Kind: KindFalsePositive, Facts: low, RequesterID: u[0], RequesterCanApprove: true,
		FPLevel: FPLevelOff, AssetOwners: []shared.ID{u[0]}, Approvers: pool(u)})
	if r.Tier != TierPeer || !hasReason(r, ReasonRequesterOwnsAsset) {
		t.Fatalf("owner requester got tier %s reasons %v, want peer with %s", r.Tier, r.Reasons, ReasonRequesterOwnsAsset)
	}
	// Another owner may not approve.
	r = Evaluate(Policy{}, Request{Kind: KindAccepted, Facts: low, RequesterID: u[0], AssetOwners: []shared.ID{u[1]}, Approvers: pool(u)})
	if r.Excluded[u[1]] != ExcludedAssetOwner || containsID(r.Eligible, u[1]) {
		t.Fatalf("asset owner not excluded: %v", r.Excluded)
	}
	if _, err := r.Sign(u[1], nil); !isRefusal(err, ExcludedAssetOwner) {
		t.Fatalf("asset owner sign-off: %v, want refusal asset_owner", err)
	}
	if done, err := r.Sign(u[2], nil); err != nil || !done {
		t.Fatalf("another approver: done=%v err=%v", done, err)
	}
}

func TestEvaluate_RequesterAndAssignee(t *testing.T) {
	u := ids(3)
	assignee := u[1]
	r := Evaluate(Policy{ExcludeAssignee: true}, Request{Kind: KindAccepted, Facts: low, RequesterID: u[0], AssigneeID: &assignee, Approvers: pool(u)})
	if _, err := r.Sign(u[0], nil); !isRefusal(err, ExcludedRequester) {
		t.Fatalf("requester sign-off: %v", err)
	}
	if _, err := r.Sign(u[1], nil); !isRefusal(err, ExcludedAssignee) {
		t.Fatalf("assignee sign-off: %v", err)
	}
	// Without the organization's rule the assignee may approve.
	r = Evaluate(Policy{}, Request{Kind: KindAccepted, Facts: low, RequesterID: u[0], AssigneeID: &assignee, Approvers: pool(u)})
	if _, err := r.Sign(u[1], nil); err != nil {
		t.Fatalf("assignee without the rule: %v", err)
	}
	// Somebody outside the approver pool.
	if _, err := r.Sign(shared.NewID(), nil); !isRefusal(err, RefusedNotApprover) {
		t.Fatalf("outsider sign-off: %v", err)
	}
}

func TestEvaluate_ActorRequestHasNoRequester(t *testing.T) {
	u := ids(2)
	r := Evaluate(Policy{}, Request{Kind: KindFalsePositive, Facts: low, FPLevel: FPLevelOff, Approvers: pool(u)})
	if r.Tier != TierPeer {
		t.Fatalf("an actor request is never decided alone: tier %s", r.Tier)
	}
	if len(r.Eligible) != 2 {
		t.Fatalf("every approver is eligible for an actor request: %v", r.Eligible)
	}
}

func TestEvaluate_ActorMadeNeedsOneMoreSignoff(t *testing.T) {
	u := ids(4)
	// A person's peer request needs one sign-off; the same request made by a
	// ticket actor needs two, so the person who moved the ticket cannot
	// complete it with one account.
	byPerson := Evaluate(Policy{}, Request{Kind: KindAccepted, Facts: low, RequesterID: u[0], RequesterCanApprove: true, Approvers: pool(u)})
	byActor := Evaluate(Policy{}, Request{Kind: KindAccepted, Facts: low, ActorMade: true, Approvers: pool(u)})
	if byActor.Required != byPerson.Required+1 {
		t.Fatalf("actor request needs %d, person request %d", byActor.Required, byPerson.Required)
	}
	done, err := byActor.Sign(u[1], nil)
	if err != nil || done {
		t.Fatalf("one sign-off must not complete an actor request: done=%v err=%v", done, err)
	}
	if done, err := byActor.Sign(u[2], []Signoff{{UserID: u[1]}}); err != nil || !done {
		t.Fatalf("second sign-off completes: done=%v err=%v", done, err)
	}
	// Two approvers in the organization cannot satisfy a dual-tier actor request.
	few := Evaluate(Policy{}, Request{Kind: KindAccepted, Facts: critical, ActorMade: true, Approvers: pool(u[:2])})
	if few.Satisfiable() {
		t.Fatalf("3 sign-offs cannot come from 2 approvers")
	}
}

func TestSign_Dual(t *testing.T) {
	u := ids(5) // u0 requester, u1 u2 security pool, u3 u4 others
	r := Evaluate(Policy{}, Request{Kind: KindAccepted, Facts: critical, RequesterID: u[0], Approvers: pool(u, u[1], u[2]), SecurityPoolConfigured: true})
	if r.Tier != TierDual || r.PoolFallback {
		t.Fatalf("tier %s fallback %v", r.Tier, r.PoolFallback)
	}
	// First sign-off by a non-pool approver is fine.
	done, err := r.Sign(u[3], nil)
	if err != nil || done {
		t.Fatalf("first sign-off: done=%v err=%v", done, err)
	}
	prior := []Signoff{{UserID: u[3]}}
	// Second non-pool sign-off is refused: the last must come from the pool.
	if _, err := r.Sign(u[4], prior); !isRefusal(err, RefusedNotInPool) {
		t.Fatalf("second non-pool sign-off: %v", err)
	}
	// The same person twice.
	if _, err := r.Sign(u[3], prior); !isRefusal(err, RefusedAlreadySigned) {
		t.Fatalf("double sign-off: %v", err)
	}
	if done, err := r.Sign(u[1], prior); err != nil || !done {
		t.Fatalf("pool sign-off completes: done=%v err=%v", done, err)
	}
	// A prior signer who no longer qualifies (now an asset owner) does not count.
	r2 := Evaluate(Policy{}, Request{Kind: KindAccepted, Facts: critical, RequesterID: u[0], AssetOwners: []shared.ID{u[3]},
		Approvers: pool(u, u[1], u[2]), SecurityPoolConfigured: true})
	if done, err := r2.Sign(u[1], prior); err != nil || done {
		t.Fatalf("stale prior counted: done=%v err=%v", done, err)
	}
}

func TestSign_SecurityPoolFallbackAndStrict(t *testing.T) {
	u := ids(3)
	// No pool configured: fallback to the approver pool.
	r := Evaluate(Policy{}, Request{Kind: KindAccepted, Facts: high, RequesterID: u[0], Approvers: pool(u)})
	if !r.PoolFallback || !hasReason(r, ReasonPoolFallback) {
		t.Fatalf("expected fallback: %v", r.Reasons)
	}
	if done, err := r.Sign(u[1], nil); err != nil || !done {
		t.Fatalf("fallback approver: done=%v err=%v", done, err)
	}
	// Pool configured, its only member is the requester: fallback.
	r = Evaluate(Policy{SecurityPoolGroupID: shared.NewID().String()}, Request{Kind: KindAccepted, Facts: high, RequesterID: u[0],
		Approvers: pool(u, u[0]), SecurityPoolConfigured: true})
	if !r.PoolFallback {
		t.Fatal("expected fallback when the pool has nobody else")
	}
	// Strict: no fallback, nobody can complete.
	strict := Policy{SecurityPoolGroupID: shared.NewID().String(), SecurityPoolStrict: true}
	r = Evaluate(strict, Request{Kind: KindAccepted, Facts: high, RequesterID: u[0], Approvers: pool(u, u[0]), SecurityPoolConfigured: true})
	if r.PoolFallback || r.Satisfiable() || !hasReason(r, ReasonNoEligibleApprover) {
		t.Fatalf("strict pool: fallback=%v satisfiable=%v reasons=%v", r.PoolFallback, r.Satisfiable(), r.Reasons)
	}
	if _, err := r.Sign(u[1], nil); err == nil {
		t.Fatal("a non-pool approver completed a strict security request")
	}
}

func TestSign_NotEnoughApprovers(t *testing.T) {
	u := ids(2) // a two-person organization
	r := Evaluate(Policy{}, Request{Kind: KindAccepted, Facts: critical, RequesterID: u[0], Approvers: pool(u)})
	if r.Satisfiable() || !hasReason(r, ReasonNotEnoughApprovers) {
		t.Fatalf("dual in a two-person organization: satisfiable=%v reasons=%v", r.Satisfiable(), r.Reasons)
	}
	_, err := r.Sign(u[1], nil)
	ref, ok := IsRefusal(err)
	if !ok || ref.Code != CodeNoEligibleApprover || !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("expected NO_ELIGIBLE_APPROVER conflict, got %v", err)
	}
}

func TestSign_SingleTierIsNotSigned(t *testing.T) {
	u := ids(2)
	r := Evaluate(Policy{}, Request{Kind: KindFalsePositive, Facts: low, RequesterID: u[0], RequesterCanApprove: true, FPLevel: FPLevelOff, Approvers: pool(u)})
	if _, err := r.Sign(u[1], nil); err == nil {
		t.Fatal("a single-person request took a sign-off")
	}
}

func TestEvaluate_CapsAndDeadline(t *testing.T) {
	day := 24 * time.Hour
	r := Evaluate(Policy{}, Request{Kind: KindAccepted, Facts: kevLow})
	if r.MaxAcceptance != 30*day {
		t.Fatalf("KEV cap %v", r.MaxAcceptance)
	}
	r = Evaluate(Policy{}, Request{Kind: KindAccepted, Facts: low})
	if r.MaxAcceptance != 365*day || r.DecideWithin != PlatformDecideWithin {
		t.Fatalf("P3 cap %v deadline %v", r.MaxAcceptance, r.DecideWithin)
	}
	p := Policy{MaxAcceptanceDays: map[Class]int{ClassStandard: 60, ClassCritical: 400}, DecideWithinDays: 3}
	r = Evaluate(p, Request{Kind: KindAccepted, Facts: low})
	if r.MaxAcceptance != 60*day || r.DecideWithin != 3*day {
		t.Fatalf("organization cap %v deadline %v", r.MaxAcceptance, r.DecideWithin)
	}
	// An organization cap above the platform's never lengthens it.
	r = Evaluate(p, Request{Kind: KindAccepted, Facts: kevLow})
	if r.MaxAcceptance != 30*day {
		t.Fatalf("cap above platform lengthened: %v", r.MaxAcceptance)
	}
	if r := Evaluate(Policy{}, Request{Kind: KindFalsePositive, Facts: low}); r.MaxAcceptance != 0 {
		t.Fatalf("a false positive has no end: %v", r.MaxAcceptance)
	}
}

func TestEvaluate_MinNote(t *testing.T) {
	if r := Evaluate(Policy{}, Request{Kind: KindAccepted, Facts: low}); r.MinNoteLength != 1 {
		t.Fatalf("peer note %d", r.MinNoteLength)
	}
	if r := Evaluate(Policy{}, Request{Kind: KindAccepted, Facts: high}); r.MinNoteLength != 20 {
		t.Fatalf("security note %d", r.MinNoteLength)
	}
}

func TestCombine_GroupTakesTheWorstMember(t *testing.T) {
	u := ids(5)
	req := func(f Facts, owners ...shared.ID) Result {
		return Evaluate(Policy{}, Request{Kind: KindAccepted, Facts: f, RequesterID: u[0], AssetOwners: owners,
			Approvers: pool(u, u[1], u[2]), SecurityPoolConfigured: true})
	}
	g := Combine(Policy{}, true, []Result{req(low), req(medium, u[3]), req(critical)})
	if g.Tier != TierDual || g.Required != 2 || g.Class != ClassCritical || !g.StepUp {
		t.Fatalf("group tier %s required %d class %s", g.Tier, g.Required, g.Class)
	}
	if g.Excluded[u[3]] != ExcludedAssetOwner || containsID(g.Eligible, u[3]) {
		t.Fatalf("owner of one member asset not excluded from the group: %v", g.Excluded)
	}
	// critical P1 → 90 days, low P3 → 365: the shortest is reported.
	if g.MaxAcceptance != 90*24*time.Hour {
		t.Fatalf("shortest member cap %v", g.MaxAcceptance)
	}
	// A group of low false positives is never decided alone.
	fp := Evaluate(Policy{}, Request{Kind: KindFalsePositive, Facts: low, RequesterID: u[0], RequesterCanApprove: true, FPLevel: FPLevelOff, Approvers: pool(u)})
	if fp.Tier != TierSingle {
		t.Fatalf("member alone: %s", fp.Tier)
	}
	g = Combine(Policy{}, false, []Result{fp, fp})
	if g.Tier != TierPeer || g.Required != 1 {
		t.Fatalf("group of single-person false positives: %s/%d", g.Tier, g.Required)
	}
	if containsID(g.Eligible, u[0]) {
		t.Fatal("requester eligible for their own group request")
	}
	if g := Combine(Policy{}, false, nil); g.Satisfiable() {
		t.Fatal("an empty group is not satisfiable")
	}
}

func hasReason(r Result, reason string) bool {
	for _, v := range r.Reasons {
		if v == reason {
			return true
		}
	}
	return false
}

func isRefusal(err error, reason any) bool {
	ref, ok := IsRefusal(err)
	if !ok {
		return false
	}
	switch v := reason.(type) {
	case ExcludeReason:
		return ref.Reason == string(v)
	case string:
		return ref.Reason == v
	}
	return false
}
