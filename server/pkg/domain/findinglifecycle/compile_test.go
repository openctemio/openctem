package findinglifecycle

import (
	"encoding/json"
	"strconv"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// testCatalog is a small organization catalog used across the tests.
type testCatalog struct {
	refs                                         []SubStatusRef
	inDev, inReview, qaPassed, needsInfo, bounty SubStatusRef
	segmented, notIssue, wontFix, obsoleteRepo   SubStatusRef
	archived                                     SubStatusRef
}

func newTestCatalog() testCatalog {
	mk := func(key string, st vulnerability.FindingStatus, reason vulnerability.ClosureReason) SubStatusRef {
		return SubStatusRef{ID: shared.NewID(), Key: key, Status: st, ClosureReason: reason}
	}
	c := testCatalog{
		needsInfo:    mk("needs_info", vulnerability.FindingStatusNew, ""),
		inDev:        mk("in_dev", vulnerability.FindingStatusInProgress, ""),
		inReview:     mk("in_review", vulnerability.FindingStatusInProgress, ""),
		qaPassed:     mk("qa_passed", vulnerability.FindingStatusFixApplied, ""),
		bounty:       mk("bounty_paid", vulnerability.FindingStatusResolved, vulnerability.ClosureReasonFixed),
		segmented:    mk("segmented", vulnerability.FindingStatusResolved, vulnerability.ClosureReasonMitigated),
		obsoleteRepo: mk("repo_gone", vulnerability.FindingStatusResolved, vulnerability.ClosureReasonObsoleteAsset),
		notIssue:     mk("not_issue", vulnerability.FindingStatusFalsePositive, vulnerability.ClosureReasonDetectionError),
		wontFix:      mk("wont_fix", vulnerability.FindingStatusAccepted, vulnerability.ClosureReasonWontFix),
		archived:     mk("old_lane", vulnerability.FindingStatusConfirmed, ""),
	}
	c.archived.Archived = true
	c.refs = []SubStatusRef{c.needsInfo, c.inDev, c.inReview, c.qaPassed, c.bounty, c.segmented, c.obsoleteRepo, c.notIssue, c.wontFix, c.archived}
	return c
}

func (c testCatalog) all() []string {
	out := []string{}
	for _, r := range c.refs {
		if !r.Archived {
			out = append(out, r.ID.String())
		}
	}
	return out
}

func compileOK(t *testing.T, cat testCatalog, s Spec) *Compiled {
	t.Helper()
	c, v := Compile(s, cat.refs, Meta{VersionID: shared.NewID(), Version: 1})
	if !v.OK() {
		t.Fatalf("spec refused: %+v", v.Errors)
	}
	return c
}

func codes(v Validation) []string {
	out := make([]string, 0, len(v.Errors))
	for _, e := range v.Errors {
		out = append(out, e.Code)
	}
	return out
}

func TestCompile_ValidSpec(t *testing.T) {
	cat := newTestCatalog()
	c := compileOK(t, cat, Spec{
		SubStatuses: cat.all(),
		Defaults:    map[string]string{"in_progress": cat.inDev.ID.String()},
		Transitions: []TransitionSpec{
			{ID: "to_review", Name: "Send to review", From: []string{cat.inDev.ID.String()}, To: cat.inReview.ID.String()},
			{ID: "claim_pr", Name: "Mark fixed (PR)", From: []string{"status:in_progress"}, To: cat.qaPassed.ID.String(),
				When:   []Condition{{Field: "priority_class", Op: "in", Value: []any{"P0", "P1"}}},
				Guards: []Guard{{Kind: GuardRequireFields, Fields: []string{"fix_reference"}}, {Kind: GuardRequireNote, MinLen: 20}}},
		},
	})
	if c.Default(vulnerability.FindingStatusInProgress) != cat.inDev.ID || c.Mode() != PersonMovesCanonicalPlusListed {
		t.Errorf("defaults %v mode %s", c.defaults, c.Mode())
	}
}

// The compiler refuses anything that would widen the platform lifecycle or
// that the engine cannot evaluate safely.
func TestCompile_Refusals(t *testing.T) {
	cat := newTestCatalog()
	id := func(r SubStatusRef) string { return r.ID.String() }
	cases := map[string]struct {
		spec Spec
		code string
	}{
		"unknown sub-status":  {Spec{SubStatuses: []string{shared.NewID().String()}}, IssueUnknownSubStatus},
		"archived sub-status": {Spec{SubStatuses: []string{id(cat.archived)}}, IssueArchivedSubStatus},
		"bad mode":            {Spec{PersonMoves: "anything"}, IssueInvalidMode},
		"default of another status": {Spec{SubStatuses: cat.all(),
			Defaults: map[string]string{"confirmed": id(cat.inDev)}}, IssueInvalidDefault},
		"default not in scheme": {Spec{SubStatuses: []string{id(cat.inReview)},
			Defaults: map[string]string{"in_progress": id(cat.inDev)}}, IssueInvalidDefault},
		// new -> resolved is a platform edge (any status may be resolved), but
		// in_progress -> new is not.
		"edge the lifecycle lacks": {Spec{SubStatuses: cat.all(), Transitions: []TransitionSpec{
			{ID: "back", Name: "Back", From: []string{id(cat.inDev)}, To: id(cat.needsInfo)}}}, IssueForbiddenEdge},
		"pentest status": {Spec{SubStatuses: cat.all(), Transitions: []TransitionSpec{
			{ID: "draft", Name: "Draft", From: []string{"status:new"}, To: "status:draft"}}}, IssueInvalidRef},
		"closure reason relabel": {Spec{SubStatuses: cat.all(), Transitions: []TransitionSpec{
			{ID: "relabel", Name: "Relabel", From: []string{id(cat.bounty)}, To: id(cat.segmented)}}}, IssueClosureReasonChange},
		"self move": {Spec{SubStatuses: cat.all(), Transitions: []TransitionSpec{
			{ID: "self", Name: "Self", From: []string{id(cat.inDev)}, To: id(cat.inDev)}}}, IssueInvalidTransition},
		"sub-status not in scheme": {Spec{SubStatuses: []string{id(cat.inDev)}, Transitions: []TransitionSpec{
			{ID: "x", Name: "X", From: []string{id(cat.inDev)}, To: id(cat.inReview)}}}, IssueInvalidRef},
		"bad transition id": {Spec{SubStatuses: cat.all(), Transitions: []TransitionSpec{
			{ID: "Bad Id", Name: "X", From: []string{"status:new"}, To: "status:confirmed"}}}, IssueInvalidTransition},
		"markup name": {Spec{SubStatuses: cat.all(), Transitions: []TransitionSpec{
			{ID: "x_y", Name: "<img>", From: []string{"status:new"}, To: "status:confirmed"}}}, IssueInvalidTransition},
		"unknown guard": {Spec{SubStatuses: cat.all(), Transitions: []TransitionSpec{
			{ID: "x_y", Name: "X", From: []string{"status:new"}, To: "status:confirmed", Guards: []Guard{{Kind: "skip_approval"}}}}}, IssueInvalidGuard},
		"unknown field": {Spec{SubStatuses: cat.all(), Transitions: []TransitionSpec{
			{ID: "x_y", Name: "X", From: []string{"status:new"}, To: "status:confirmed", Guards: []Guard{{Kind: GuardRequireFields, Fields: []string{"password"}}}}}}, IssueInvalidGuard},
		"unknown permission": {Spec{SubStatuses: cat.all(), Transitions: []TransitionSpec{
			{ID: "x_y", Name: "X", From: []string{"status:new"}, To: "status:confirmed", Guards: []Guard{{Kind: GuardRequirePermission, AnyOf: []string{"team:admin"}}}}}}, IssueInvalidGuard},
		"deny a person": {Spec{SubStatuses: cat.all(), Transitions: []TransitionSpec{
			{ID: "x_y", Name: "X", From: []string{"status:new"}, To: "status:confirmed", Guards: []Guard{{Kind: GuardDenyActorKinds, Kinds: []string{"person"}}}}}}, IssueInvalidGuard},
		"note too long": {Spec{SubStatuses: cat.all(), Transitions: []TransitionSpec{
			{ID: "x_y", Name: "X", From: []string{"status:new"}, To: "status:confirmed", Guards: []Guard{{Kind: GuardRequireNote, MinLen: 5000}}}}}, IssueInvalidGuard},
		"regex condition": {Spec{SubStatuses: cat.all(), Transitions: []TransitionSpec{
			{ID: "x_y", Name: "X", From: []string{"status:new"}, To: "status:confirmed", When: []Condition{{Field: "tool_name", Op: "matches", Value: ".*"}}}}}, IssueInvalidCondition},
		"unknown condition field": {Spec{SubStatuses: cat.all(), Transitions: []TransitionSpec{
			{ID: "x_y", Name: "X", From: []string{"status:new"}, To: "status:confirmed", When: []Condition{{Field: "assignee_email", Op: "eq", Value: "a"}}}}}, IssueInvalidCondition},
		"gte on a text field": {Spec{SubStatuses: cat.all(), Transitions: []TransitionSpec{
			{ID: "x_y", Name: "X", From: []string{"status:new"}, To: "status:confirmed", When: []Condition{{Field: "source", Op: "gte", Value: "sast"}}}}}, IssueInvalidCondition},
		"severity outside the scale": {Spec{SubStatuses: cat.all(), Transitions: []TransitionSpec{
			{ID: "x_y", Name: "X", From: []string{"status:new"}, To: "status:confirmed", When: []Condition{{Field: "severity", Op: "eq", Value: "urgent"}}}}}, IssueInvalidCondition},
		"duplicate transition id": {Spec{SubStatuses: cat.all(), Transitions: []TransitionSpec{
			{ID: "x_y", Name: "X", From: []string{"status:new"}, To: "status:confirmed"},
			{ID: "x_y", Name: "Y", From: []string{"status:confirmed"}, To: "status:in_progress"}}}, IssueDuplicateTransition},
	}
	for name, c := range cases {
		_, v := Compile(c.spec, cat.refs, Meta{})
		found := false
		for _, code := range codes(v) {
			if code == c.code {
				found = true
			}
		}
		if !found {
			t.Errorf("%s: errors %v, want %s", name, codes(v), c.code)
		}
	}
}

func TestCompile_Limits(t *testing.T) {
	cat := newTestCatalog()
	many := Spec{SubStatuses: cat.all()}
	for i := 0; i <= MaxTransitions; i++ {
		many.Transitions = append(many.Transitions, TransitionSpec{
			ID: "t_" + strconv.Itoa(i), Name: "T", From: []string{"status:new"}, To: "status:confirmed",
		})
	}
	if _, v := Compile(many, cat.refs, Meta{}); v.OK() {
		t.Error("more than the transition limit accepted")
	}
	guards := make([]Guard, MaxGuardsPerMove+1)
	for i := range guards {
		guards[i] = Guard{Kind: GuardRequireNote, MinLen: 1}
	}
	if _, v := Compile(Spec{Transitions: []TransitionSpec{{ID: "g_g", Name: "G", From: []string{"status:new"}, To: "status:confirmed", Guards: guards}}}, nil, Meta{}); v.OK() {
		t.Error("more than the guard limit accepted")
	}
	vals := make([]any, MaxListValues+1)
	for i := range vals {
		vals[i] = "tool" + strconv.Itoa(i)
	}
	if _, v := Compile(Spec{Transitions: []TransitionSpec{{ID: "c_c", Name: "C", From: []string{"status:new"}, To: "status:confirmed",
		When: []Condition{{Field: "tool_name", Op: "in", Value: vals}}}}}, nil, Meta{}); v.OK() {
		t.Error("more than the list limit accepted")
	}
}

// listed_only: every open place must still reach resolved, false positive
// and accepted, so an organization cannot lock its own findings in.
func TestCompile_ListedOnlyReachability(t *testing.T) {
	cat := newTestCatalog()
	// The canonical edges, listed (a status reference covers its sub-statuses).
	full := Spec{SubStatuses: cat.all(), PersonMoves: PersonMovesListedOnly, Transitions: []TransitionSpec{
		{ID: "triage", Name: "Confirm", From: []string{"status:new"}, To: "status:confirmed"},
		{ID: "start", Name: "Start", From: []string{"status:confirmed"}, To: "status:in_progress"},
		{ID: "claim", Name: "Claim fix", From: []string{"status:in_progress"}, To: "status:fix_applied"},
		{ID: "resolve", Name: "Resolve", From: []string{"status:confirmed", "status:fix_applied"}, To: "status:resolved"},
		{ID: "fp", Name: "Not an issue", From: []string{"status:new", "status:confirmed"}, To: "status:false_positive"},
		{ID: "accept", Name: "Accept", From: []string{"status:confirmed"}, To: "status:accepted"},
		{ID: "back", Name: "Back to backlog", From: []string{"status:in_progress"}, To: "status:confirmed"},
		{ID: "reject", Name: "Reject fix", From: []string{"status:fix_applied"}, To: "status:in_progress"},
		{ID: "dup", Name: "Duplicate", From: []string{"status:new", "status:confirmed"}, To: "status:duplicate"},
	}}
	if _, v := Compile(full, cat.refs, Meta{}); !v.OK() || len(v.Warnings) != 0 {
		t.Fatalf("complete listed_only refused: %+v %+v", v.Errors, v.Warnings)
	}
	stuck := full
	stuck.Transitions = full.Transitions[:4] // no way to a false positive or an acceptance
	_, v := Compile(stuck, cat.refs, Meta{})
	if v.OK() {
		t.Fatal("a listed_only scheme with no way to a false positive or an acceptance was accepted")
	}
	for _, e := range v.Errors {
		if e.Code != IssueUnreachable {
			t.Errorf("unexpected error %+v", e)
		}
	}
	noDup := full
	noDup.Transitions = full.Transitions[:8]
	if _, v := Compile(noDup, cat.refs, Meta{}); !v.OK() || len(v.Warnings) == 0 {
		t.Errorf("unreachable duplicate: errors %v, warnings %d (want a warning only)", codes(v), len(v.Warnings))
	}
}

func TestParseSpec_Strict(t *testing.T) {
	if _, err := ParseSpec([]byte(`{"sub_statuses": [], "transitions": [], "bypass_four_eyes": true}`)); err == nil {
		t.Error("unknown field accepted")
	}
	if _, err := ParseSpec([]byte(`{"transitions": []} {"x": 1}`)); err == nil {
		t.Error("trailing data accepted")
	}
	if _, err := ParseSpec([]byte(`{"transitions": "nope"}`)); err == nil || strings.Contains(err.Error(), "findinglifecycle") {
		t.Errorf("wrong type: %v", err)
	}
	big := `{"sub_statuses": ["` + strings.Repeat("a", MaxSpecBytes) + `"]}`
	if _, err := ParseSpec([]byte(big)); err == nil {
		t.Error("oversized spec accepted")
	}
	raw, _ := json.Marshal(Spec{Transitions: []TransitionSpec{{ID: "a_b", Name: "A", From: []string{"status:new"}, To: "status:confirmed",
		When: []Condition{{Field: "is_kev", Op: "eq", Value: true}, {Field: "severity", Op: "gte", Value: "high"}}}}})
	s, err := ParseSpec(raw)
	if err != nil {
		t.Fatal(err)
	}
	if _, v := Compile(s, nil, Meta{}); !v.OK() {
		t.Errorf("round-tripped spec refused: %+v", v.Errors)
	}
}
