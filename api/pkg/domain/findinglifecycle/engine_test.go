package findinglifecycle

import (
	"reflect"
	"slices"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

func allPermsActor(kind vulnerability.TransitionActorKind) Actor {
	return Actor{
		TransitionActor: vulnerability.TransitionActor{
			Kind: kind, UserID: shared.NewID(),
			CanStatus: true, CanVerify: true, CanFixApply: true, CanTriage: true, CanWrite: true,
		},
		Permissions: GuardPermissions(),
	}
}

func memberActor() Actor {
	return Actor{
		TransitionActor: vulnerability.TransitionActor{
			Kind: vulnerability.TransitionActorPerson, UserID: shared.NewID(), CanStatus: true, CanFixApply: true,
		},
		Permissions: []string{"findings:status", "findings:fix_apply"},
	}
}

func facts(status vulnerability.FindingStatus, sub shared.ID) Facts {
	return Facts{
		TransitionFacts: vulnerability.TransitionFacts{
			Status: status, Source: vulnerability.FindingSourceSAST, Severity: vulnerability.SeverityMedium, CanClaimFix: true,
		},
		SubStatus: sub,
	}
}

func blockCodes(d Decision) []string {
	out := make([]string, 0, len(d.Blocked))
	for _, b := range d.Blocked {
		out = append(out, b.Code)
	}
	return out
}

// With no scheme (the system lifecycle), and with a scheme that adds
// nothing, every canonical move is decided exactly as the platform decides it.
func TestEvaluateMove_SystemLifecycleEqualsPlatform(t *testing.T) {
	cat := newTestCatalog()
	empty := compileOK(t, cat, Spec{SubStatuses: cat.all()})
	actors := []Actor{
		allPermsActor(vulnerability.TransitionActorPerson), memberActor(),
		allPermsActor(vulnerability.TransitionActorAPIKey), allPermsActor(vulnerability.TransitionActorWorkflow),
		allPermsActor(vulnerability.TransitionActorTicket), {},
	}
	for _, from := range CanonicalStatuses() {
		for _, to := range CanonicalStatuses() {
			if to == from {
				continue
			}
			for _, a := range actors {
				f := facts(from, shared.ID{})
				want := vulnerability.EvaluateTransition(f.TransitionFacts, a.TransitionActor, to)
				for name, c := range map[string]*Compiled{"system": nil, "empty scheme": empty} {
					got := EvaluateMove(c, f, a, Target{Status: to})
					if !reflect.DeepEqual(got.TransitionDecision, want) {
						t.Errorf("%s %s -> %s as %s: %+v, platform %+v", name, from, to, a.Kind, got.TransitionDecision, want)
					}
				}
			}
		}
	}
}

func TestEvaluateMove_Guards(t *testing.T) {
	cat := newTestCatalog()
	c := compileOK(t, cat, Spec{
		SubStatuses: cat.all(),
		Transitions: []TransitionSpec{
			{ID: "claim_pr", Name: "Mark fixed (PR)", From: []string{"status:in_progress"}, To: cat.qaPassed.ID.String(),
				When: []Condition{{Field: "priority_class", Op: "in", Value: []any{"P0", "P1"}}},
				Guards: []Guard{
					{Kind: GuardRequireFields, Fields: []string{"fix_reference"}},
					{Kind: GuardRequireNote, MinLen: 20},
					{Kind: GuardRequirePermission, AnyOf: []string{"findings:verify", "findings:approve"}},
				}},
			{ID: "to_review", Name: "Send to review", From: []string{cat.inDev.ID.String()}, To: cat.inReview.ID.String(),
				Guards: []Guard{{Kind: GuardDenyActorKinds, Kinds: []string{"workflow", "api_key"}}}},
		},
	})
	qa := Target{Status: vulnerability.FindingStatusFixApplied, SubStatus: cat.qaPassed.ID}

	// P1: the guards apply on top of the platform's fix-claim rules.
	f := facts(vulnerability.FindingStatusInProgress, cat.inDev.ID)
	f.PriorityClass = "P1"
	d := EvaluateMove(c, f, memberActor(), qa)
	if d.Allowed || !slices.Contains(blockCodes(d), BlockLifecyclePermission) {
		t.Errorf("member without verify: %+v", d)
	}
	if !slices.Contains(d.Fields, FieldFixReference) || d.NoteMinLen != 20 || !slices.Contains(d.Requires, vulnerability.RequireNote) {
		t.Errorf("requirements: fields %v note %d requires %v", d.Fields, d.NoteMinLen, d.Requires)
	}
	if d.Transition != "claim_pr" || d.ToSubStatus != cat.qaPassed.ID {
		t.Errorf("transition %q sub %s", d.Transition, d.ToSubStatus)
	}
	if d := EvaluateMove(c, f, allPermsActor(vulnerability.TransitionActorPerson), qa); !d.Allowed {
		t.Errorf("verifier: %+v", d)
	}
	// P3: when does not match, so only the platform rules apply.
	f.PriorityClass = "P3"
	if d := EvaluateMove(c, f, memberActor(), qa); !d.Allowed || len(d.Fields) != 0 || d.NoteMinLen != 0 {
		t.Errorf("P3 claim: %+v", d)
	}
	// The platform rule still binds: a person who cannot claim the fix is refused.
	f.CanClaimFix = false
	if d := EvaluateMove(c, f, allPermsActor(vulnerability.TransitionActorPerson), qa); d.Allowed || !slices.Contains(blockCodes(d), vulnerability.BlockNotFixOwner) {
		t.Errorf("not the fix owner: %+v", d)
	}

	// deny_actor_kinds keeps automation off a label move.
	review := Target{Status: vulnerability.FindingStatusInProgress, SubStatus: cat.inReview.ID}
	dev := facts(vulnerability.FindingStatusInProgress, cat.inDev.ID)
	if d := EvaluateMove(c, dev, allPermsActor(vulnerability.TransitionActorWorkflow), review); d.Allowed || !slices.Contains(blockCodes(d), BlockActorKindDenied) {
		t.Errorf("workflow label move: %+v", d)
	}
	if d := EvaluateMove(c, dev, memberActor(), review); !d.Allowed {
		t.Errorf("person label move: %+v", d)
	}
}

func TestEvaluateMove_LabelMoves(t *testing.T) {
	cat := newTestCatalog()
	c := compileOK(t, cat, Spec{SubStatuses: cat.all(), Transitions: []TransitionSpec{
		{ID: "to_review", Name: "Review", From: []string{"status:in_progress"}, To: cat.inReview.ID.String()},
		{ID: "bounty", Name: "Bounty paid", From: []string{"status:resolved"}, To: cat.bounty.ID.String()},
	}})
	review := Target{Status: vulnerability.FindingStatusInProgress, SubStatus: cat.inReview.ID}

	viewer := Actor{TransitionActor: vulnerability.TransitionActor{Kind: vulnerability.TransitionActorPerson, UserID: shared.NewID()}}
	if d := EvaluateMove(c, facts(vulnerability.FindingStatusInProgress, shared.ID{}), viewer, review); d.Allowed || !slices.Contains(blockCodes(d), vulnerability.BlockMissingPermission) {
		t.Errorf("label move without findings:status: %+v", d)
	}
	if d := EvaluateMove(c, facts(vulnerability.FindingStatusInProgress, cat.inReview.ID), memberActor(), review); d.Allowed || !slices.Contains(blockCodes(d), BlockSameSubStatus) {
		t.Errorf("same sub-status: %+v", d)
	}
	// An unlisted label move to a specific sub-status is not offered.
	dev := Target{Status: vulnerability.FindingStatusInProgress, SubStatus: cat.inDev.ID}
	if d := EvaluateMove(c, facts(vulnerability.FindingStatusInProgress, cat.inReview.ID), memberActor(), dev); d.Allowed || !slices.Contains(blockCodes(d), BlockNotInLifecycle) {
		t.Errorf("unlisted label move: %+v", d)
	}
	// Under a closed status, the label must keep the finding's closure reason.
	bounty := Target{Status: vulnerability.FindingStatusResolved, SubStatus: cat.bounty.ID}
	resolved := facts(vulnerability.FindingStatusResolved, shared.ID{})
	resolved.ClosureReason = vulnerability.ClosureReasonMitigated
	if d := EvaluateMove(c, resolved, memberActor(), bounty); d.Allowed || !slices.Contains(blockCodes(d), BlockClosureReasonChange) {
		t.Errorf("relabel across closure reasons: %+v", d)
	}
	resolved.ClosureReason = vulnerability.ClosureReasonFixed
	if d := EvaluateMove(c, resolved, memberActor(), bounty); !d.Allowed || d.ClosureReason != vulnerability.ClosureReasonFixed {
		t.Errorf("relabel with the same reason: %+v", d)
	}
	// A ticket may relabel only inside the statuses it may report.
	ticket := allPermsActor(vulnerability.TransitionActorTicket)
	if d := EvaluateMove(c, facts(vulnerability.FindingStatusInProgress, shared.ID{}), ticket, review); !d.Allowed {
		t.Errorf("ticket relabel in progress: %+v", d)
	}
	if d := EvaluateMove(c, resolved, ticket, bounty); d.Allowed {
		t.Errorf("ticket relabel of a resolved finding: %+v", d)
	}
	// A pentest finding belongs to its module.
	pf := facts(vulnerability.FindingStatusInProgress, shared.ID{})
	pf.Source = vulnerability.FindingSourcePentest
	if d := EvaluateMove(c, pf, allPermsActor(vulnerability.TransitionActorPerson), review); d.Allowed {
		t.Errorf("pentest relabel: %+v", d)
	}
}

// A closed sub-status binds its reason: a canonical move onto it sets that
// reason, and a reason only the platform sets (an obsolete asset) cannot be
// chosen by a person.
func TestEvaluateMove_ClosedSubStatusBinding(t *testing.T) {
	cat := newTestCatalog()
	c := compileOK(t, cat, Spec{SubStatuses: cat.all(), Transitions: []TransitionSpec{
		{ID: "close_fixed", Name: "Bounty paid", From: []string{"status:fix_applied"}, To: cat.bounty.ID.String()},
		{ID: "close_gone", Name: "Repo gone", From: []string{"status:fix_applied"}, To: cat.obsoleteRepo.ID.String()},
		{ID: "wont_fix", Name: "Won't fix", From: []string{"status:confirmed"}, To: cat.wontFix.ID.String()},
	}})
	f := facts(vulnerability.FindingStatusFixApplied, shared.ID{})
	f.ChecklistComplete = true
	verifier := allPermsActor(vulnerability.TransitionActorPerson)
	if d := EvaluateMove(c, f, verifier, Target{Status: vulnerability.FindingStatusResolved, SubStatus: cat.bounty.ID}); !d.Allowed || d.ClosureReason != vulnerability.ClosureReasonFixed {
		t.Errorf("close as bounty paid: %+v", d)
	}
	if d := EvaluateMove(c, f, verifier, Target{Status: vulnerability.FindingStatusResolved, SubStatus: cat.obsoleteRepo.ID}); d.Allowed || !slices.Contains(blockCodes(d), BlockPlatformSubStatus) {
		t.Errorf("person picks an obsolete reason: %+v", d)
	}
	// Accept as "won't fix" stays a four-eyes request.
	d := EvaluateMove(c, facts(vulnerability.FindingStatusConfirmed, shared.ID{}), verifier, Target{Status: vulnerability.FindingStatusAccepted, SubStatus: cat.wontFix.ID})
	if !d.Allowed || d.Mode != vulnerability.TransitionRequest || d.ClosureReason != vulnerability.ClosureReasonWontFix {
		t.Errorf("won't fix: %+v", d)
	}
	// A sub-status of another status, or not in the scheme, is not a target.
	if d := EvaluateMove(c, f, verifier, Target{Status: vulnerability.FindingStatusResolved, SubStatus: cat.inDev.ID}); d.Allowed {
		t.Errorf("mismatched sub-status: %+v", d)
	}
	if d := EvaluateMove(nil, f, verifier, Target{Status: vulnerability.FindingStatusResolved, SubStatus: cat.bounty.ID}); d.Allowed {
		t.Errorf("sub-status under the system lifecycle: %+v", d)
	}
}

func TestEvaluateMove_ListedOnly(t *testing.T) {
	cat := newTestCatalog()
	c := compileOK(t, cat, Spec{SubStatuses: cat.all(), PersonMoves: PersonMovesListedOnly, Transitions: []TransitionSpec{
		{ID: "triage", Name: "Confirm", From: []string{"status:new"}, To: "status:confirmed"},
		{ID: "start", Name: "Start", From: []string{"status:confirmed"}, To: cat.inDev.ID.String()},
		{ID: "claim", Name: "Claim fix", From: []string{"status:in_progress"}, To: "status:fix_applied"},
		{ID: "resolve", Name: "Resolve", From: []string{"status:fix_applied"}, To: "status:resolved"},
		{ID: "fp", Name: "Not an issue", From: []string{"status:new", "status:confirmed"}, To: "status:false_positive"},
		{ID: "accept", Name: "Accept", From: []string{"status:confirmed"}, To: "status:accepted"},
		{ID: "back", Name: "Back", From: []string{"status:in_progress"}, To: "status:confirmed"},
		{ID: "reject", Name: "Reject", From: []string{"status:fix_applied"}, To: "status:in_progress"},
	}})
	verifier := allPermsActor(vulnerability.TransitionActorPerson)
	// confirmed -> resolved is a platform edge but not listed: refused.
	if d := EvaluateMove(c, facts(vulnerability.FindingStatusConfirmed, shared.ID{}), verifier, Target{Status: vulnerability.FindingStatusResolved}); d.Allowed || !slices.Contains(blockCodes(d), BlockNotInLifecycle) {
		t.Errorf("unlisted canonical move: %+v", d)
	}
	// The listed start lands on In development, not on the default.
	if d := EvaluateMove(c, facts(vulnerability.FindingStatusConfirmed, shared.ID{}), verifier, Target{Status: vulnerability.FindingStatusInProgress}); d.Allowed {
		t.Errorf("start to the default label under listed_only: %+v", d)
	}
	moves := AvailableMoves(c, facts(vulnerability.FindingStatusConfirmed, shared.ID{}), verifier)
	var targets []Target
	for _, m := range moves {
		targets = append(targets, Target{Status: m.To, SubStatus: m.ToSubStatus})
	}
	want := []Target{
		{Status: vulnerability.FindingStatusFalsePositive}, {Status: vulnerability.FindingStatusAccepted},
		{Status: vulnerability.FindingStatusInProgress, SubStatus: cat.inDev.ID},
	}
	for _, w := range want {
		if !slices.Contains(targets, w) {
			t.Errorf("available moves %v lack %v", targets, w)
		}
	}
	if slices.Contains(targets, Target{Status: vulnerability.FindingStatusResolved}) {
		t.Errorf("available moves offer an unlisted resolve: %v", targets)
	}
}

func TestAvailableMoves_CanonicalPlusListed(t *testing.T) {
	cat := newTestCatalog()
	c := compileOK(t, cat, Spec{SubStatuses: cat.all(), Transitions: []TransitionSpec{
		{ID: "to_review", Name: "Review", From: []string{cat.inDev.ID.String()}, To: cat.inReview.ID.String()},
	}})
	moves := AvailableMoves(c, facts(vulnerability.FindingStatusInProgress, cat.inDev.ID), memberActor())
	var got []Target
	for _, m := range moves {
		got = append(got, Target{Status: m.To, SubStatus: m.ToSubStatus})
	}
	want := []Target{
		{Status: vulnerability.FindingStatusFixApplied}, {Status: vulnerability.FindingStatusConfirmed},
		{Status: vulnerability.FindingStatusInProgress, SubStatus: cat.inReview.ID},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("moves %v, want %v", got, want)
	}
	pf := facts(vulnerability.FindingStatusInProgress, shared.ID{})
	pf.Source = vulnerability.FindingSourcePentest
	if len(AvailableMoves(c, pf, memberActor())) != 0 {
		t.Error("a pentest finding was offered moves")
	}
}

func TestSelectScheme(t *testing.T) {
	cat := newTestCatalog()
	def := compileOK(t, cat, Spec{})
	kev := compileOK(t, cat, Spec{})
	sast := compileOK(t, cat, Spec{})
	kevSel, v := CompileContext([]Condition{{Field: "is_kev", Op: "eq", Value: true}})
	if !v.OK() {
		t.Fatal(v.Errors)
	}
	sastSel, _ := CompileContext([]Condition{{Field: "source", Op: "in", Value: []any{"sast", "secret"}}})
	cands := []Candidate{
		{Scheme: sast, Context: sastSel, Priority: 20},
		{Scheme: def, Default: true},
		{Scheme: kev, Context: kevSel, Priority: 10},
	}
	if got := SelectScheme(cands, ConditionFacts{Source: "sast", IsKEV: true}); got != kev {
		t.Error("the higher priority context did not win")
	}
	if got := SelectScheme(cands, ConditionFacts{Source: "sast"}); got != sast {
		t.Error("the matching context scheme was not picked")
	}
	if got := SelectScheme(cands, ConditionFacts{Source: "dast"}); got != def {
		t.Error("the default scheme was not the fallback")
	}
	if got := SelectScheme(nil, ConditionFacts{}); got != nil {
		t.Error("no scheme should mean the system lifecycle")
	}
	if _, v := CompileContext(nil); v.OK() {
		t.Error("an empty context selector was accepted")
	}
}

func TestConditions(t *testing.T) {
	cases := []struct {
		c    Condition
		f    ConditionFacts
		want bool
	}{
		{Condition{Field: "severity", Op: "gte", Value: "high"}, ConditionFacts{Severity: "critical"}, true},
		{Condition{Field: "severity", Op: "gte", Value: "high"}, ConditionFacts{Severity: "medium"}, false},
		{Condition{Field: "severity", Op: "lte", Value: "low"}, ConditionFacts{Severity: "info"}, true},
		{Condition{Field: "priority_class", Op: "gte", Value: "P1"}, ConditionFacts{PriorityClass: "P0"}, true},
		{Condition{Field: "priority_class", Op: "gte", Value: "P1"}, ConditionFacts{PriorityClass: "P2"}, false},
		{Condition{Field: "priority_class", Op: "gte", Value: "P1"}, ConditionFacts{}, false},
		{Condition{Field: "priority_class", Op: "exists", Value: false}, ConditionFacts{}, true},
		{Condition{Field: "is_kev", Op: "neq", Value: true}, ConditionFacts{IsKEV: false}, true},
		{Condition{Field: "tool_name", Op: "not_in", Value: []any{"nuclei"}}, ConditionFacts{ToolName: "semgrep"}, true},
		{Condition{Field: "finding_type", Op: "eq", Value: "secret"}, ConditionFacts{FindingType: "secret"}, true},
	}
	for _, c := range cases {
		cc, err := compileCondition(c.c)
		if err != nil {
			t.Fatalf("%+v: %v", c.c, err)
		}
		if got := cc.match(c.f); got != c.want {
			t.Errorf("%+v on %+v = %v, want %v", c.c, c.f, got, c.want)
		}
	}
}
