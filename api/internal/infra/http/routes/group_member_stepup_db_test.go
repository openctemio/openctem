package routes

// Adding a member to a team that carries a privileged role: the owner without
// a recent sign-in gets the step-up refusal (and succeeds after
// re-authenticating), an administrator gets the owner-only refusal, and a
// team without a privileged role is unaffected.

import (
	"context"
	"errors"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/accesscontrol"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
)

// teamStepUpGate refuses with the step-up error until the test re-authenticates.
type teamStepUpGate struct{ fresh *bool }

func (g teamStepUpGate) RequireRecentAuth(context.Context, string) error {
	if *g.fresh {
		return nil
	}
	return middleware.ErrStepUpRequired
}

func TestTeamMembership_PrivilegedTeamStepUpAndOwnerOnly(t *testing.T) {
	h := newGRBHarness(t)
	ctx := context.Background()
	fresh := false
	h.roleSvc.SetStepUpGate(teamStepUpGate{fresh: &fresh})

	// A team without a privileged role needs neither the owner nor step-up.
	plain := h.newTeam(h.tenant)
	if err := h.groups.BindRole(ctx, plain.String(), h.analyst.String(), h.actx(h.owner)); err != nil {
		t.Fatalf("bind plain role: %v", err)
	}
	if _, err := h.groups.AddMember(ctx, accesscontrol.AddGroupMemberInput{GroupID: plain.String(), UserID: h.member, Role: "member"}, h.actx(h.owner)); err != nil {
		t.Fatalf("owner adds to a non-privileged team without recent auth: %v", err)
	}

	// The privileged team (full data access): binding is a step-up action too.
	fresh = true
	if err := h.groups.BindRole(ctx, h.team.String(), h.fullData.String(), h.actx(h.owner)); err != nil {
		t.Fatalf("owner binds privileged role: %v", err)
	}
	fresh = false

	if err := h.addMember(h.owner, h.member); !errors.Is(err, middleware.ErrStepUpRequired) {
		t.Fatalf("owner without recent auth: got %v, want step-up required", err)
	}
	if err := h.addMember(h.admin, h.member); !errors.Is(err, accesscontrol.ErrPrivilegedTeamOwnerOnly) {
		t.Fatalf("administrator: got %v, want owner-only", err)
	}
	fresh = true
	if err := h.addMember(h.owner, h.member); err != nil {
		t.Fatalf("owner after re-authenticating: %v", err)
	}
}
