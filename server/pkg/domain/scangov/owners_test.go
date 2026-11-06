package scangov

import (
	"errors"
	"slices"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

const (
	ownerAlice = "a1000000-0000-4000-8000-000000000001"
	ownerBob   = "b1000000-0000-4000-8000-000000000001"
	groupDBA   = "d1000000-0000-4000-8000-000000000001"
	groupFall  = "f1000000-0000-4000-8000-000000000001"
)

func TestSplitByOwner(t *testing.T) {
	parts := SplitByOwner([]TargetOwners{
		{Target: "db.example.com", UserIDs: []string{ownerAlice}, GroupIDs: []string{groupDBA}},
		{Target: "app.example.com", UserIDs: []string{ownerBob}},
		{Target: "api.example.com", UserIDs: []string{ownerAlice}},
		{Target: "unowned.example.com"},
		{Target: "10.0.0.5"},
	}, groupFall)
	want := []Part{
		{Kind: OwnerUser, ID: ownerAlice, Targets: []string{"api.example.com", "db.example.com"}},
		{Kind: OwnerUser, ID: ownerBob, Targets: []string{"app.example.com"}},
		{Kind: OwnerGroup, ID: groupDBA, Targets: []string{"db.example.com"}},
		{Kind: OwnerFallback, ID: groupFall, Targets: []string{"10.0.0.5", "unowned.example.com"}},
	}
	if len(parts) != len(want) {
		t.Fatalf("parts %+v", parts)
	}
	for i := range want {
		if parts[i].Key() != want[i].Key() || !slices.Equal(parts[i].Targets, want[i].Targets) {
			t.Fatalf("part %d: %+v, want %+v", i, parts[i], want[i])
		}
	}
}

// Every part needs one of its own approvers; the requester and a
// self-approval never count; an approver of one part does not cover
// another.
func TestPartsApproved(t *testing.T) {
	parts := SplitByOwner([]TargetOwners{
		{Target: "db.example.com", GroupIDs: []string{groupDBA}},
		{Target: "app.example.com", UserIDs: []string{ownerBob}},
	}, groupFall)
	members := map[string][]string{"group:" + groupDBA: {ownerAlice}, "user:" + ownerBob: {ownerBob}}
	of := func(p Part) []string { return members[p.Key()] }

	ok, waiting := PartsApproved(parts, []Approval{{UserID: ownerAlice}}, ownerBob, of)
	if ok || !slices.Equal(waiting, []string{"user:" + ownerBob}) {
		t.Fatalf("bob (the requester) cannot approve his own part: %v %v", ok, waiting)
	}
	if ok, _ := PartsApproved(parts, []Approval{{UserID: ownerAlice}, {UserID: ownerBob, Self: true}}, "", of); ok {
		t.Fatal("a self-approval counted")
	}
	if ok, _ := PartsApproved(parts, []Approval{{UserID: ownerAlice}, {UserID: ownerBob}}, "", of); !ok {
		t.Fatal("both parts approved")
	}
	if ok, _ := PartsApproved(nil, []Approval{{UserID: ownerAlice}}, "", of); ok {
		t.Fatal("no parts is never approved")
	}
}

// The setting is refused until the request and gate paths enforce it: a
// saved rule never claims a control that is not applied.
func TestAssetOwnerApproversNotYetAvailable(t *testing.T) {
	_, err := Normalize([]Rule{{Name: "Owners approve", Enabled: true,
		Requirement: Requirement{Approvals: 1, ApproverSource: "asset_owners", FallbackGroupID: groupFall}}})
	if !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("asset_owners accepted before it is enforced: %v", err)
	}
	if _, err := Normalize([]Rule{{Name: "x", Enabled: true, Requirement: Requirement{Approvals: 1, FallbackGroupID: groupFall}}}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("a fallback group without asset_owners: %v", err)
	}
	rs, err := Normalize([]Rule{{Name: "x", Enabled: true, Requirement: Requirement{Approvals: 1, ApproverSource: "RULE"}}})
	if err != nil || rs[0].Requirement.ApproverSource != "" {
		t.Fatalf("rule is the default: %+v %v", rs, err)
	}
}
