package integration

// An outside member's privilege is judged on EFFECTIVE grants (RFC-095 §4.2):
// a team role binding that carries a permission above member (here
// team:members:invite) makes them privileged exactly like a direct role, so
// the two-factor rule at token mint applies. Joining such a team already
// needs the owner with a recent sign-in, for anyone (team binding rules).

import (
	"context"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/accesscontrol"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

func TestHoldsAboveMember_CountsTeamBindings(t *testing.T) {
	db := setupTestDB(t)
	t.Cleanup(func() { _ = db.Close() })
	ctx := context.Background()
	pg := &postgres.DB{DB: db}
	host := createTestTenant(t, db, "above-host")
	other := createTestTenant(t, db, "above-other")
	outsider := createTestUser(t, db, "out-"+shared.NewID().String()[24:]+"@gmail.com", "Out")
	createTestMembership(t, db, host, outsider, "member")
	createTestMembership(t, db, other, outsider, "viewer")
	t.Cleanup(func() {
		for _, tid := range []shared.ID{host, other} {
			_, _ = db.ExecContext(ctx, `DELETE FROM group_role_bindings WHERE tenant_id = $1`, tid.String())
			_, _ = db.ExecContext(ctx, `DELETE FROM group_members WHERE group_id IN (SELECT id FROM groups WHERE tenant_id = $1)`, tid.String())
			_, _ = db.ExecContext(ctx, `DELETE FROM groups WHERE tenant_id = $1`, tid.String())
			_, _ = db.ExecContext(ctx, `DELETE FROM user_roles WHERE tenant_id = $1`, tid.String())
			_, _ = db.ExecContext(ctx, `DELETE FROM tenant_members WHERE tenant_id = $1`, tid.String())
			_, _ = db.ExecContext(ctx, `DELETE FROM roles WHERE tenant_id = $1`, tid.String())
		}
		cleanupTestData(db, host, other)
	})
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := db.ExecContext(ctx, q, args...); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	svc := accesscontrol.NewRoleService(postgres.NewRoleRepository(pg), postgres.NewPermissionRepository(pg), logger.NewNop())

	above := func(tid shared.ID) bool {
		t.Helper()
		ok, err := svc.HoldsAboveMember(ctx, tid.String(), outsider.String())
		if err != nil {
			t.Fatal(err)
		}
		return ok
	}
	if above(host) {
		t.Fatal("the built-in member role is above member")
	}

	recruiter, team := shared.NewID().String(), shared.NewID().String()
	exec(`INSERT INTO roles (id, tenant_id, slug, name, is_system, hierarchy_level) VALUES ($1, $2, 'above-recruiter', 'Recruiter', false, 10)`, recruiter, host.String())
	exec(`INSERT INTO role_permissions (role_id, permission_id) VALUES ($1, 'team:members:invite')`, recruiter)
	exec(`INSERT INTO groups (id, tenant_id, name, slug) VALUES ($1, $2, 'Recruiters', 'above-recruiters')`, team, host.String())
	exec(`INSERT INTO group_role_bindings (tenant_id, group_id, role_id) VALUES ($1, $2, $3)`, host.String(), team, recruiter)
	exec(`INSERT INTO group_members (group_id, user_id) VALUES ($1, $2)`, team, outsider.String())

	if !above(host) {
		t.Fatal("a team role carrying team:members:invite does not count: the two-factor rule would be skipped")
	}
	// The grant is the host's only: the person's other organization is unaffected.
	if above(other) {
		t.Fatal("a team grant in one organization counted in another")
	}
	// An expired team membership no longer grants it.
	exec(`UPDATE group_members SET expires_at = now() - interval '1 minute' WHERE group_id = $1`, team)
	if above(host) {
		t.Fatal("an expired team membership still counts")
	}
}
