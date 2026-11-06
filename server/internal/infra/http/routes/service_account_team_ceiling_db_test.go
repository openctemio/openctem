package routes

// A service account never holds full data access, also through a team: the
// service refuses both orders (bind a full-data role to a team that has a
// service account; add a service account to a team that has one bound) and
// the schema refuses them for any writer that skips the service.

import (
	"context"
	"errors"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/accesscontrol"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/logger"
)

func TestServiceAccountTeamCeiling(t *testing.T) {
	h := newGRBHarness(t)
	ctx := context.Background()
	db := &postgres.DB{DB: h.db}
	repo := postgres.NewServiceAccountRepository(db)
	svc := accesscontrol.NewServiceAccountService(repo, nil, logger.NewNop())
	a, err := svc.Create(ctx, accesscontrol.CreateServiceAccountInput{Name: "bridge"}, h.actx(h.owner))
	if err != nil {
		t.Fatal(err)
	}

	// Service: the account is in the team first; the full-data binding is refused.
	if err := h.addMember(h.owner, a.ID); err != nil {
		t.Fatalf("a service account joins a plain team: %v", err)
	}
	if err := h.groups.BindRole(ctx, h.team.String(), h.fullData.String(), h.actx(h.owner)); !errors.Is(err, accesscontrol.ErrExternalTeamFullData) {
		t.Fatalf("full-data role bound to a team with a service account: %v", err)
	}
	// A plain role binds fine.
	if err := h.groups.BindRole(ctx, h.team.String(), h.analyst.String(), h.actx(h.owner)); err != nil {
		t.Fatalf("plain role: %v", err)
	}

	// Schema: the same two orders, written directly.
	if _, err := h.db.Exec(`INSERT INTO group_role_bindings (tenant_id, group_id, role_id) VALUES ($1, $2, $3)`,
		h.tenant.String(), h.team.String(), h.fullData.String()); err == nil {
		t.Error("the schema let a full-data role be bound to a team with a service account")
	}
	full := h.newTeam(h.tenant)
	h.exec(`INSERT INTO group_role_bindings (tenant_id, group_id, role_id) VALUES ($1, $2, $3)`, h.tenant.String(), full.String(), h.fullData.String())
	if _, err := h.db.Exec(`INSERT INTO group_members (group_id, user_id, role) VALUES ($1, $2, 'member')`, full.String(), a.ID.String()); err == nil {
		t.Error("the schema let a service account join a team with a full-data role")
	}
	// Service: the account cannot join it either.
	if _, err := h.groups.AddMember(ctx, accesscontrol.AddGroupMemberInput{GroupID: full.String(), UserID: a.ID, Role: "member"}, h.actx(h.owner)); !errors.Is(err, accesscontrol.ErrExternalTeamFullData) {
		t.Errorf("service account joins a full-data team: %v", err)
	}
	// A person is unaffected by the trigger.
	h.exec(`INSERT INTO group_members (group_id, user_id, role) VALUES ($1, $2, 'member')`, full.String(), h.member.String())
}
