package findinglifecycle

import (
	"encoding/json"
	"math/rand/v2"
	"slices"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// TestEvaluateMove_NeverWiderThanThePlatform is the tenant layer's safety
// property (RFC-110 T1): over random schemes, findings, actors and targets,
// a move the organization's lifecycle allows is always a move the platform
// allows, with at least the platform's requirements, and a platform request
// (four-eyes) stays a request. Label moves (same status) are never platform
// moves, so they must at least hold findings:status (or be an explicit
// system move or a ticket reporting work state) and keep the closure reason.
func TestEvaluateMove_NeverWiderThanThePlatform(t *testing.T) {
	rng := rand.New(rand.NewPCG(158, 110)) //nolint:gosec // deterministic test data
	cat := newTestCatalog()
	compiled := 0
	for range 400 {
		spec := randomSpec(rng, cat)
		c, v := Compile(spec, cat.refs, Meta{})
		if !v.OK() {
			continue
		}
		compiled++
		for range 200 {
			f := randomFacts(rng, cat)
			a := randomActor(rng)
			to := randomTarget(rng, cat)
			d := EvaluateMove(c, f, a, to)
			checkNotWider(t, c, f, a, to, d)
		}
		// Every offered move obeys the same property.
		f := randomFacts(rng, cat)
		a := randomActor(rng)
		for _, d := range AvailableMoves(c, f, a) {
			checkNotWider(t, c, f, a, Target{Status: d.To, SubStatus: d.ToSubStatus}, d)
		}
	}
	if compiled < 100 {
		t.Fatalf("only %d random specs compiled; the generator no longer exercises the engine", compiled)
	}
}

func checkNotWider(t *testing.T, c *Compiled, f Facts, a Actor, to Target, d Decision) {
	t.Helper()
	if to.Status != f.Status {
		p := vulnerability.EvaluateTransition(f.TransitionFacts, a.TransitionActor, to.Status)
		if d.Allowed && !p.Allowed {
			t.Fatalf("tenant layer allowed a move the platform refuses: %s -> %+v as %+v\nplatform %+v\ntenant %+v", f.Status, to, a.Kind, p, d)
		}
		for _, r := range p.Requires {
			if !slices.Contains(d.Requires, r) {
				t.Fatalf("tenant layer dropped platform requirement %s: %+v", r, d)
			}
		}
		for _, b := range p.Blocked {
			if !slices.ContainsFunc(d.Blocked, func(x vulnerability.TransitionBlock) bool { return x.Code == b.Code }) {
				t.Fatalf("tenant layer cleared platform block %s: %+v", b.Code, d)
			}
		}
		if p.Mode == vulnerability.TransitionRequest && d.Mode != vulnerability.TransitionRequest {
			t.Fatalf("a four-eyes request became %s: %+v", d.Mode, d)
		}
		if d.Mode != p.Mode {
			t.Fatalf("mode changed from %s to %s", p.Mode, d.Mode)
		}
		return
	}
	if !d.Allowed {
		return
	}
	if f.Source == vulnerability.FindingSourcePentest {
		t.Fatalf("label move on a pentest finding allowed: %+v", d)
	}
	switch a.Kind {
	case vulnerability.TransitionActorWorkflow:
	case vulnerability.TransitionActorTicket:
		if !to.Status.IsTicketInboundTarget() {
			t.Fatalf("ticket relabelled a %s finding", to.Status)
		}
	default:
		if !a.CanStatus {
			t.Fatalf("label move without findings:status allowed: %+v", d)
		}
	}
	if ref, ok := c.SubStatus(to.SubStatus); ok && ref.ClosureReason != "" && ref.ClosureReason != f.ClosureReason {
		t.Fatalf("label move changed the closure reason %s -> %s", f.ClosureReason, ref.ClosureReason)
	}
	if to.SubStatus == f.SubStatus {
		t.Fatalf("a move to the same sub-status was allowed")
	}
}

func randomRef(rng *rand.Rand, cat testCatalog) string {
	if rng.IntN(3) == 0 {
		return statusRefPrefix + string(CanonicalStatuses()[rng.IntN(8)])
	}
	refs := cat.refs[:len(cat.refs)-1] // not the archived one
	return refs[rng.IntN(len(refs))].ID.String()
}

func randomSpec(rng *rand.Rand, cat testCatalog) Spec {
	s := Spec{SubStatuses: cat.all()}
	if rng.IntN(4) == 0 {
		// listed_only must keep every closed status reachable: start from
		// the canonical edges, listed, and add random moves on top.
		s.PersonMoves = PersonMovesListedOnly
		for from, tos := range vulnerability.ValidStatusTransitions {
			if !IsCanonical(from) {
				continue
			}
			for _, to := range tos {
				s.Transitions = append(s.Transitions, TransitionSpec{
					ID: "c_" + string(from) + "_" + string(to), Name: "C",
					From: []string{statusRefPrefix + string(from)}, To: statusRefPrefix + string(to),
				})
			}
		}
		slices.SortFunc(s.Transitions, func(a, b TransitionSpec) int { return strings.Compare(a.ID, b.ID) })
	}
	n := rng.IntN(12)
	for i := range n {
		ts := TransitionSpec{ID: "t_" + string(rune('a'+i)), Name: "T"}
		ts.To = randomRef(rng, cat)
		// Mostly legal sources (an edge of the lifecycle or a label move),
		// sometimes anything, so the compiler's refusals are exercised too.
		for range 1 + rng.IntN(3) {
			from := randomRef(rng, cat)
			for range 20 {
				if rng.IntN(40) == 0 || legalSource(cat, from, ts.To) {
					break
				}
				from = randomRef(rng, cat)
			}
			ts.From = append(ts.From, from)
		}
		if rng.IntN(2) == 0 {
			ts.When = []Condition{randomCondition(rng)}
		}
		for range rng.IntN(4) {
			ts.Guards = append(ts.Guards, randomGuard(rng))
		}
		s.Transitions = append(s.Transitions, ts)
	}
	// Round-trip through JSON, as a stored spec would.
	raw, _ := json.Marshal(s)
	out, err := ParseSpec(raw)
	if err != nil {
		panic(err)
	}
	return out
}

func refStatus(cat testCatalog, ref string) (vulnerability.FindingStatus, vulnerability.ClosureReason) {
	if st, ok := strings.CutPrefix(ref, statusRefPrefix); ok {
		return vulnerability.FindingStatus(st), ""
	}
	for _, r := range cat.refs {
		if r.ID.String() == ref {
			return r.Status, r.ClosureReason
		}
	}
	return "", ""
}

func legalSource(cat testCatalog, from, to string) bool {
	fs, fr := refStatus(cat, from)
	ts, tr := refStatus(cat, to)
	if fs != ts {
		return fs.CanTransitionTo(ts)
	}
	return from != to && (fr == "" || tr == "" || fr == tr)
}

func randomCondition(rng *rand.Rand) Condition {
	switch rng.IntN(5) {
	case 0:
		return Condition{Field: CondSeverity, Op: OpGte, Value: []string{"low", "medium", "high", "critical"}[rng.IntN(4)]}
	case 1:
		return Condition{Field: CondPriorityClass, Op: OpIn, Value: []any{"P0", "P1"}}
	case 2:
		return Condition{Field: CondIsKEV, Op: OpEq, Value: rng.IntN(2) == 0}
	case 3:
		return Condition{Field: CondSource, Op: OpNotIn, Value: []any{"dast"}}
	default:
		return Condition{Field: CondToolName, Op: OpExists, Value: true}
	}
}

func randomGuard(rng *rand.Rand) Guard {
	switch rng.IntN(4) {
	case 0:
		return Guard{Kind: GuardRequireNote, MinLen: 1 + rng.IntN(50)}
	case 1:
		return Guard{Kind: GuardRequireFields, Fields: []string{string(RequiredFields()[rng.IntN(len(RequiredFields()))])}}
	case 2:
		perms := GuardPermissions()
		return Guard{Kind: GuardRequirePermission, AnyOf: []string{perms[rng.IntN(len(perms))]}}
	default:
		kinds := DeniableActorKinds()
		return Guard{Kind: GuardDenyActorKinds, Kinds: []string{string(kinds[rng.IntN(len(kinds))])}}
	}
}

func randomFacts(rng *rand.Rand, cat testCatalog) Facts {
	st := CanonicalStatuses()[rng.IntN(8)]
	var sub shared.ID
	var subs []SubStatusRef
	for _, r := range cat.refs {
		if r.Status == st && !r.Archived {
			subs = append(subs, r)
		}
	}
	var reason vulnerability.ClosureReason
	if st.IsClosed() {
		reasons := vulnerability.ClosureReasonsFor(st)
		reason = reasons[rng.IntN(len(reasons))]
	}
	if len(subs) > 0 && rng.IntN(2) == 0 {
		r := subs[rng.IntN(len(subs))]
		sub = r.ID
		if r.ClosureReason != "" {
			reason = r.ClosureReason
		}
	}
	sources := []vulnerability.FindingSource{vulnerability.FindingSourceSAST, vulnerability.FindingSourceDAST, vulnerability.FindingSourcePentest}
	sevs := []vulnerability.Severity{vulnerability.SeverityLow, vulnerability.SeverityMedium, vulnerability.SeverityHigh, vulnerability.SeverityCritical}
	pcs := []string{"", "P0", "P1", "P2", "P3"}
	return Facts{
		TransitionFacts: vulnerability.TransitionFacts{
			Status: st, Source: sources[rng.IntN(3)], Severity: sevs[rng.IntN(4)], PriorityClass: pcs[rng.IntN(5)],
			IsKEV: rng.IntN(5) == 0, CanClaimFix: rng.IntN(2) == 0, ChecklistComplete: rng.IntN(2) == 0,
			ChecklistCompletedBy: shared.NewID(), RetestConfirmedFixed: rng.IntN(4) == 0,
		},
		SubStatus: sub, ClosureReason: reason, ToolName: []string{"", "semgrep"}[rng.IntN(2)],
	}
}

func randomActor(rng *rand.Rand) Actor {
	kinds := []vulnerability.TransitionActorKind{
		vulnerability.TransitionActorPerson, vulnerability.TransitionActorAPIKey,
		vulnerability.TransitionActorWorkflow, vulnerability.TransitionActorTicket,
	}
	a := Actor{TransitionActor: vulnerability.TransitionActor{
		Kind: kinds[rng.IntN(4)], CanStatus: rng.IntN(2) == 0, CanVerify: rng.IntN(2) == 0,
		CanFixApply: rng.IntN(2) == 0, CanTriage: rng.IntN(2) == 0, CanWrite: rng.IntN(2) == 0,
	}}
	if a.Kind == vulnerability.TransitionActorPerson {
		a.UserID = shared.NewID()
	}
	for _, p := range GuardPermissions() {
		if rng.IntN(2) == 0 {
			a.Permissions = append(a.Permissions, p)
		}
	}
	return a
}

func randomTarget(rng *rand.Rand, cat testCatalog) Target {
	if rng.IntN(2) == 0 {
		return Target{Status: CanonicalStatuses()[rng.IntN(8)]}
	}
	r := cat.refs[rng.IntN(len(cat.refs))]
	return Target{Status: r.Status, SubStatus: r.ID}
}

// FuzzCompile: no spec, however hostile, panics the parser or the compiler,
// and whatever compiles evaluates without panicking.
func FuzzCompile(f *testing.F) {
	cat := newTestCatalog()
	f.Add([]byte(`{"sub_statuses": [], "transitions": []}`))
	f.Add([]byte(`{"person_moves": "listed_only", "transitions": [{"id": "a_b", "name": "x", "from": ["status:new"], "to": "status:confirmed", "guards": [{"kind": "require_note", "min_len": 3}], "when": [{"field": "severity", "op": "gte", "value": "high"}]}]}`))
	f.Add([]byte(`{"transitions": [{"id": "a_b", "from": ["status:new", "x"], "to": 7, "when": [{"field": "is_kev", "op": "in", "value": [true]}]}]}`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		spec, err := ParseSpec(raw)
		if err != nil {
			return
		}
		c, v := Compile(spec, cat.refs, Meta{})
		if !v.OK() {
			return
		}
		fa := facts(vulnerability.FindingStatusInProgress, cat.inDev.ID)
		for _, a := range []Actor{memberActor(), allPermsActor(vulnerability.TransitionActorTicket)} {
			_ = AvailableMoves(c, fa, a)
			_ = EvaluateMove(c, fa, a, Target{Status: vulnerability.FindingStatusFixApplied, SubStatus: cat.qaPassed.ID})
		}
	})
}
