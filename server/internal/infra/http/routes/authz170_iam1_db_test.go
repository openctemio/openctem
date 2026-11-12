package routes

// Team activation is a grant: a holder of team:groups:write alone cannot
// revive a team bound to a full-data role.

import (
	"context"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/accesscontrol"
)

// IAM-1: re-activating a deactivated team re-grants its bound privileged role
// without the binding ceiling (mayGrant + owner-only + step-up).
func TestAuthz170_TeamReactivationBypassesBindingCeiling(t *testing.T) {
	h := newGRBHarness(t)
	ctx := context.Background()
	// The owner puts the delegated team lead in the team, binds a full-data
	// role (owner + step-up path), then suspends the team.
	if err := h.addMember(h.owner, h.lead); err != nil {
		t.Fatal(err)
	}
	if err := h.groups.BindRole(ctx, h.team.String(), h.fullData.String(), h.actx(h.owner)); err != nil {
		t.Fatalf("owner binds full-data role: %v", err)
	}
	off := false
	if _, err := h.groups.UpdateGroup(ctx, h.team.String(), accesscontrol.UpdateGroupInput{IsActive: &off}, h.actx(h.owner)); err != nil {
		t.Fatal(err)
	}
	full, _ := h.roles.HasFullDataAccess(ctx, rid(h.tenant), rid(h.lead))
	if full {
		t.Fatal("precondition: deactivated team must not grant")
	}
	// Control: the lead cannot bind or grant this role directly.
	if err := h.groups.BindRole(ctx, h.team.String(), h.fullData.String(), h.actx(h.lead)); err == nil {
		t.Fatal("control: lead could bind a full-data role")
	}
	// The lead (team:groups:write only) re-activates the team.
	on := true
	_, err := h.groups.UpdateGroup(ctx, h.team.String(), accesscontrol.UpdateGroupInput{IsActive: &on}, h.actx(h.lead))
	full, _ = h.roles.HasFullDataAccess(ctx, rid(h.tenant), rid(h.lead))
	if err == nil && full {
		t.Fatalf("IAM-1: team:groups:write holder re-activated a team bound to a full-data role and now has full data access (no owner, no step-up, no grant ceiling)")
	}
}

// IAM-3: an administrator demoted through the Roles API keeps the membership
