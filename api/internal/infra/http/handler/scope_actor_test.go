package handler

import (
	"context"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

type namesFor map[string]string

func (n namesFor) MemberNames(_ context.Context, _ shared.ID, ids []string) (map[string]string, error) {
	out := map[string]string{}
	for _, id := range ids {
		if v, ok := n[id]; ok {
			out[id] = v
		}
	}
	return out, nil
}

func TestActorRef(t *testing.T) {
	id := shared.NewID().String()
	for raw, want := range map[string]ActorRef{
		id:                        {Kind: ActorKindUser, ID: id},
		"system:migration-000292": {Kind: ActorKindSystem, Code: ActorCodeWildcardSplit},
		"system:seed-migration":   {Kind: ActorKindSystem, Code: ActorCodeSeedMigration},
		"system:anything":         {Kind: ActorKindSystem, Code: ActorCodeSystem},
		"admin-a":                 {Kind: ActorKindSystem, Code: ActorCodeSystem},
	} {
		got := actorRef(raw)
		if got == nil || *got != want {
			t.Errorf("actorRef(%q) = %+v, want %+v", raw, got, want)
		}
	}
	if actorRef("  ") != nil {
		t.Error("an empty actor is a reference")
	}
}

// A member is named; a user who is not a member of this tenant (left, or
// another organization's) is a former member with no name; the raw system
// string never reaches the response.
func TestResolveActors(t *testing.T) {
	member, stranger := shared.NewID().String(), shared.NewID().String()
	resp := ScopeTargetResponse{
		CreatedBy:  actorRef(member),
		RejectedBy: actorRef(stranger),
		Approvals:  []ScopeApprovalResponse{{UserID: member, Approver: actorRef(member)}},
	}
	excl := ScopeExclusionResponse{CreatedBy: actorRef("system:migration-000292")}
	refs := append(targetActorRefs(&resp), exclusionActorRefs(&excl)...)
	resolveActors(context.Background(), namesFor{member: "Nguyen Manh"}, logger.NewNop(), shared.NewID().String(), refs)
	if resp.CreatedBy.Name != "Nguyen Manh" || resp.CreatedBy.FormerMember || resp.Approvals[0].Approver.Name != "Nguyen Manh" {
		t.Fatalf("member: %+v %+v", resp.CreatedBy, resp.Approvals[0].Approver)
	}
	if resp.RejectedBy.Name != "" || !resp.RejectedBy.FormerMember {
		t.Fatalf("non-member: %+v", resp.RejectedBy)
	}
	if excl.CreatedBy.Kind != ActorKindSystem || excl.CreatedBy.Code != ActorCodeWildcardSplit || excl.CreatedBy.ID != "" {
		t.Fatalf("system: %+v", excl.CreatedBy)
	}
	// Without a namer nothing is named (and nothing panics).
	bare := ScopeTargetResponse{CreatedBy: actorRef(member)}
	resolveActors(context.Background(), nil, nil, shared.NewID().String(), targetActorRefs(&bare))
	if bare.CreatedBy.Name != "" || bare.CreatedBy.FormerMember {
		t.Fatalf("no namer: %+v", bare.CreatedBy)
	}
}
