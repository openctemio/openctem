package remediation

import (
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func cand(key string, owner Owner, class string, risk int) Candidate {
	return Candidate{FindingID: shared.NewID(), Key: key, Title: "Upgrade django to 4.2.30", Owner: owner,
		PriorityClass: class, RiskPoints: risk}
}

func TestBuildSuggestions_NewGroupPartitionedByOwner(t *testing.T) {
	tenant := shared.NewID()
	u1, g1 := shared.NewID(), shared.NewID()
	key := "upgrade:pypi:django:4.2.30"
	cands := []Candidate{
		cand(key, Owner{UserID: &u1}, "P1", 4),
		cand(key, Owner{UserID: &u1}, "P2", 2),
		cand(key, Owner{GroupID: &g1}, "P0", 8),
		cand(key, Owner{}, "", 1),
	}
	ss := BuildSuggestions(tenant, cands, nil, nil)
	if len(ss) != 1 {
		t.Fatalf("one key, one new_group suggestion; got %d", len(ss))
	}
	s := ss[0]
	if s.Kind != SuggestionNewGroup || s.MemberCount != 4 || s.RiskPoints != 15 || !s.HasUrgent {
		t.Fatalf("suggestion %+v", s)
	}
	if len(s.Partitions) != 3 {
		t.Fatalf("three owners (user, group, default queue); got %d", len(s.Partitions))
	}
	if s.Partitions[0].RiskPoints != 8 || s.Partitions[0].OwnerGroup != g1.String() {
		t.Fatalf("partitions ranked by risk: %+v", s.Partitions[0])
	}
	var queue *Partition
	for i := range s.Partitions {
		if s.Partitions[i].OwnerRule == "default_queue" {
			queue = &s.Partitions[i]
		}
	}
	if queue == nil || len(queue.FindingIDs) != 1 {
		t.Fatal("an unowned finding goes to the default queue")
	}
	if s.RiskParts.P0 != 1 || s.RiskParts.P1 != 1 || s.RiskParts.P2 != 1 || s.RiskParts.Unclassed != 1 {
		t.Fatalf("risk parts %+v", s.RiskParts)
	}
	if s.FixSpec["package"] != "django" || s.FixSpec["target_version"] != "4.2.30" || s.Confidence != 1.0 {
		t.Fatalf("fix spec %+v confidence %v", s.FixSpec, s.Confidence)
	}
	if s.Identity != Identity(SuggestionNewGroup, key, nil, nil, Owner{}) {
		t.Fatal("identity is the kind and key of a new group")
	}
}

func TestBuildSuggestions_Thresholds(t *testing.T) {
	tenant := shared.NewID()
	lone := cand("upgrade:npm:lodash:4.17.21", Owner{}, "P2", 2)
	urgent := cand("rotate:secret:abcdef0123", Owner{}, "P0", 8)
	kev := cand("upgrade:npm:axios:1.7.4", Owner{}, "P3", 1)
	kev.InKEV = true
	ss := BuildSuggestions(tenant, []Candidate{lone, urgent, kev}, nil, nil)
	got := map[string]bool{}
	for _, s := range ss {
		got[s.Key] = true
	}
	if got[lone.Key] {
		t.Error("a lone, non-urgent finding is not a group")
	}
	if !got[urgent.Key] || !got[kev.Key] {
		t.Error("a single P0 or KEV finding is suggested")
	}
}

func TestBuildSuggestions_AcceptedActionJoinsOrRoutes(t *testing.T) {
	tenant := shared.NewID()
	u1, u2 := shared.NewID(), shared.NewID()
	key := "upgrade:pypi:django:4.2.30"
	action := AcceptedAction{ID: shared.NewID(), Key: key, Tasks: []ActionTask{
		{ID: shared.NewID(), Owner: Owner{UserID: &u1}, State: TaskStateInProgress},
		{ID: shared.NewID(), Owner: Owner{UserID: &u2}, State: TaskStateDone},
	}}
	cands := []Candidate{cand(key, Owner{UserID: &u1}, "P1", 4), cand(key, Owner{UserID: &u2}, "P1", 4)}
	ss := BuildSuggestions(tenant, cands, map[string]AcceptedAction{key: action}, nil)
	if len(ss) != 2 {
		t.Fatalf("one per owner; got %d", len(ss))
	}
	kinds := map[SuggestionKind]Suggestion{}
	for _, s := range ss {
		kinds[s.Kind] = s
	}
	join, ok := kinds[SuggestionJoin]
	if !ok || *join.TargetTaskID != action.Tasks[0].ID || join.MemberCount != 1 {
		t.Fatalf("u1's finding joins u1's live task: %+v", join)
	}
	route, ok := kinds[SuggestionTaskRoute]
	if !ok || route.TargetTaskID != nil || *route.TargetActionID != action.ID {
		t.Fatalf("u2's task is done: a new task is proposed: %+v", route)
	}
	for _, s := range ss {
		if s.Kind == SuggestionNewGroup {
			t.Fatal("a key with an accepted action never gets a second group")
		}
	}
}

func TestBuildSuggestions_ExclusionsAndConfidence(t *testing.T) {
	tenant := shared.NewID()
	key := "upgrade:pypi:django:4.2.30"
	a, b, c := cand(key, Owner{}, "P1", 4), cand(key, Owner{}, "P1", 4), cand(key, Owner{}, "P1", 4)
	ss := BuildSuggestions(tenant, []Candidate{a, b, c}, nil, map[string]map[shared.ID]bool{key: {a.FindingID: true}})
	if len(ss) != 1 || ss[0].MemberCount != 2 {
		t.Fatalf("an excluded finding is left out: %+v", ss)
	}
	for _, id := range ss[0].FindingIDs {
		if id == a.FindingID {
			t.Fatal("excluded finding suggested again")
		}
	}
	sol := BuildSuggestions(tenant, []Candidate{cand("sol:dast:"+key, Owner{}, "P2", 2), cand("sol:dast:"+key, Owner{}, "P2", 2)}, nil, nil)
	if len(sol) != 1 || sol[0].Confidence >= 1 || sol[0].Confidence < MinConfidence {
		t.Fatalf("a solution-text group is suggested with lower confidence: %+v", sol)
	}
}

func TestRankSuggestions(t *testing.T) {
	soon, late := time.Now(), time.Now().Add(time.Hour)
	ss := []Suggestion{
		{Identity: "a", RiskPoints: 4, MemberCount: 1},
		{Identity: "b", RiskPoints: 8, MemberCount: 1},
		{Identity: "c", RiskPoints: 4, MemberCount: 3},
		{Identity: "d", RiskPoints: 4, MemberCount: 1, EarliestDeadline: &late},
		{Identity: "e", RiskPoints: 4, MemberCount: 1, EarliestDeadline: &soon},
	}
	RankSuggestions(ss)
	got := ""
	for _, s := range ss {
		got += s.Identity
	}
	if got != "bceda" {
		t.Fatalf("risk, members, earliest deadline, identity: got %s", got)
	}
}

func TestMateriallyChanged(t *testing.T) {
	prev := DismissedSnapshot{MemberCount: 10, RiskPoints: 20}
	cases := []struct {
		name string
		now  Suggestion
		want bool
	}{
		{"same", Suggestion{MemberCount: 10, RiskPoints: 20}, false},
		{"a few more", Suggestion{MemberCount: 13, RiskPoints: 26}, false},
		{"half again", Suggestion{MemberCount: 15, RiskPoints: 30}, true},
		{"ten more on a big group", Suggestion{MemberCount: 20, RiskPoints: 39}, true},
		{"risk doubled", Suggestion{MemberCount: 11, RiskPoints: 40}, true},
		{"became urgent", Suggestion{MemberCount: 10, RiskPoints: 20, HasUrgent: true}, true},
		{"fewer", Suggestion{MemberCount: 4, RiskPoints: 8}, false},
	}
	for _, tc := range cases {
		if got := MateriallyChanged(prev, tc.now); got != tc.want {
			t.Errorf("%s: got %v want %v", tc.name, got, tc.want)
		}
	}
	big := DismissedSnapshot{MemberCount: 100, RiskPoints: 200}
	if !MateriallyChanged(big, Suggestion{MemberCount: 110, RiskPoints: 220}) {
		t.Error("ten more members is material")
	}
}

func TestFixSpecForKey(t *testing.T) {
	spec := FixSpecForKey("upgrade:npm:@scope~pkg:1.2.3")
	if spec["package"] != "@scope/pkg" || spec["ecosystem"] != "npm" {
		t.Fatalf("npm scope restored: %+v", spec)
	}
	if FixSpecForKey("rotate:secret:0123456789abcdef")["secret_fingerprint_prefix"] != "01234567" {
		t.Fatal("only a fingerprint prefix is shown")
	}
}
