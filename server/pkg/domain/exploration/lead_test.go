package exploration

import (
	"errors"
	"testing"
	"time"

	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/domain/stage"
)

func leadInput(capability string) NewLeadInput {
	a := shared.NewID()
	return NewLeadInput{
		TenantID: shared.NewID(), ExplorationID: shared.NewID(), Type: "dns.takeover_check",
		Action: Action{Capability: capability}, SubjectAssetID: &a, ReasonCode: "cname_dangling",
		Origin: OriginRule, OriginRef: "dns.takeover_check@1",
	}
}

func TestInitialState_ByTier(t *testing.T) {
	cases := []struct {
		origin Origin
		tier   stage.Tier
		auto   bool
		want   LeadState
	}{
		{OriginRule, stage.TierPassive, false, StateOpen},
		{OriginRule, stage.TierActive, true, StateOpen},
		{OriginRule, stage.TierActive, false, StateAwaitingApproval},
		{OriginRule, stage.TierIntrusive, true, StateAwaitingApproval},
		{OriginUser, stage.TierIntrusive, true, StateAwaitingApproval},
		{OriginAIAgent, stage.TierPassive, true, StateProposed},
	}
	for _, c := range cases {
		if got := InitialState(c.origin, c.tier, c.auto); got != c.want {
			t.Errorf("%s %s auto=%v: got %s, want %s", c.origin, c.tier, c.auto, got, c.want)
		}
	}
}

func TestNewLead_TierFromCatalogNotOpener(t *testing.T) {
	in := leadInput("dast.web") // intrusive in the catalog
	in.AutoActive = true
	l, err := NewLead(in)
	if err != nil {
		t.Fatal(err)
	}
	if l.Tier != stage.TierIntrusive || l.State != StateAwaitingApproval {
		t.Fatalf("intrusive lead: tier %s state %s", l.Tier, l.State)
	}
}

func TestNewLead_Refuses(t *testing.T) {
	bad := map[string]func(*NewLeadInput){
		"unknown capability": func(in *NewLeadInput) { in.Action.Capability = "run.shell" },
		"no action":          func(in *NewLeadInput) { in.Action.Capability = "" },
		"two subjects":       func(in *NewLeadInput) { f := shared.NewID(); in.SubjectFindingID = &f },
		"no subject":         func(in *NewLeadInput) { in.SubjectAssetID = nil },
		"bad type":           func(in *NewLeadInput) { in.Type = "DROP TABLE" },
		"bad origin":         func(in *NewLeadInput) { in.Origin = "sensor" },
		"long rationale":     func(in *NewLeadInput) { in.Rationale = string(make([]rune, MaxRationale+1)) },
		"no tenant":          func(in *NewLeadInput) { in.TenantID = shared.ID{} },
		"bad likelihood":     func(in *NewLeadInput) { in.Likelihood = "certain" },
	}
	for name, mutate := range bad {
		in := leadInput("check.takeover")
		mutate(&in)
		if _, err := NewLead(in); !errors.Is(err, shared.ErrValidation) {
			t.Errorf("%s: got %v, want a validation error", name, err)
		}
	}
}

func TestNewLead_DedupAndActionHashStable(t *testing.T) {
	in := leadInput("check.takeover")
	in.Action.Params = map[string]any{"b": 1, "a": "x"}
	a, err := NewLead(in)
	if err != nil {
		t.Fatal(err)
	}
	in.Action.Params = map[string]any{"a": "x", "b": 1}
	in.Rationale = "different words, same question"
	b, err := NewLead(in)
	if err != nil {
		t.Fatal(err)
	}
	if a.DedupKey != b.DedupKey || a.ActionHash != b.ActionHash || len(a.ActionHash) != 64 {
		t.Fatalf("same question must keep its key and hash: %q %q", a.ActionHash, b.ActionHash)
	}
	in.Action.Params = map[string]any{"a": "y"}
	c, _ := NewLead(in)
	if c.ActionHash == a.ActionHash {
		t.Fatal("different params must hash differently")
	}
}

func TestMove_ClosedLeadNeverMoves(t *testing.T) {
	l, err := NewLead(leadInput("resolve.dns"))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	for _, s := range []LeadState{StateRunning, StateRefuted} {
		if err := l.Move(s, now); err != nil {
			t.Fatalf("move to %s: %v", s, err)
		}
	}
	if l.ClosedAt == nil {
		t.Fatal("a closing move stamps closed_at")
	}
	for _, s := range LiveStates {
		if err := l.Move(s, now); !errors.Is(err, ErrBadTransition) {
			t.Errorf("refuted -> %s: got %v", s, err)
		}
	}
	// Approval cannot be skipped: awaiting_approval never goes straight to running.
	if CanMove(StateAwaitingApproval, StateRunning) {
		t.Fatal("awaiting_approval -> running must not be allowed")
	}
}

func TestVerdict_ProofWording(t *testing.T) {
	user := shared.NewID()
	base := Verdict{TenantID: shared.NewID(), LeadID: shared.NewID(), Checker: "scan_run"}
	ok := []Verdict{
		{Verdict: VerdictProven, Tier: TierDeterministic},
		{Verdict: VerdictRefuted, Tier: TierHeuristic},
		{Verdict: VerdictProven, Tier: TierHuman, DecidedBy: &user, Checker: "user:" + user.String(), Evidence: []EvidenceRef{{Kind: "evidence", ID: "e1"}}},
	}
	for _, v := range ok {
		if v.Checker == "" {
			v.Checker = base.Checker
		}
		if err := v.Validate(); err != nil {
			t.Errorf("%s/%s: %v", v.Verdict, v.Tier, err)
		}
	}
	bad := []Verdict{
		{Verdict: VerdictProven, Tier: TierAI, Checker: "ai"},
		{Verdict: VerdictProven, Tier: TierHeuristic, Checker: "rule@1"},
		{Verdict: VerdictProven, Tier: TierHuman, DecidedBy: &user, Checker: "user:" + user.String()},
		{Verdict: VerdictRefuted, Tier: TierHuman, DecidedBy: &user, Checker: "user:someone-else"},
		{Verdict: "maybe", Tier: TierDeterministic, Checker: "x"},
	}
	for _, v := range bad {
		if err := v.Validate(); !errors.Is(err, shared.ErrValidation) {
			t.Errorf("%s/%s by %s: got %v", v.Verdict, v.Tier, v.Checker, err)
		}
	}
}

func TestLink_Validate(t *testing.T) {
	id := shared.NewID()
	ok := Link{TenantID: shared.NewID(), LeadID: shared.NewID(), Rel: RelDispatchedAs, EndKind: EndScanRun, EndID: &id}
	if err := ok.Validate(); err != nil {
		t.Fatal(err)
	}
	bad := ok
	bad.EndKind = EndAsset
	if err := bad.Validate(); err == nil {
		t.Fatal("dispatched_as must end at a run")
	}
	bad = ok
	bad.EndID = nil
	if err := bad.Validate(); err == nil {
		t.Fatal("a new link needs its end")
	}
}
