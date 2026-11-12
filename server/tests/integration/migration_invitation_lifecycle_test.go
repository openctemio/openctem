package integration

// Migration invitation_lifecycle: up, down (revoked rows, which used to be
// deleted, go so they do not become pending again), up.

import (
	"testing"

	"github.com/openctemio/openctem/api/internal/testdb"
)

func TestMigrationInvitationLifecycle(t *testing.T) {
	const dir = "../../migrations"
	v := testdb.MigrationVersion(t, dir, "invitation_lifecycle")
	db := testdb.PrivateDatabase(t, "miginvl", dir)
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := db.Exec(q, args...); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	const tid, uid = "a1111111-1111-4111-8111-111111111111", "b1111111-1111-4111-8111-111111111111"
	exec(`INSERT INTO tenants (id, name, slug) VALUES ($1, 'a', 'mig-invl')`, tid)
	exec(`INSERT INTO users (id, email, name) VALUES ($1, 'i@miginvl.test', 'i')`, uid)
	exec(`INSERT INTO tenant_invitations (tenant_id, email, role, token, invited_by, expires_at, invitee_kind, privileged)
		VALUES ($1, 'p@miginvl.test', 'member', 'p', $2, now() + interval '7 days', 'external', true),
		       ($1, 'r@miginvl.test', 'member', 'r', $2, now() + interval '7 days', 'internal', false)`, tid, uid)
	exec(`UPDATE tenant_invitations SET revoked_at = now() WHERE token = 'r'`)
	if _, err := db.Exec(`UPDATE tenant_invitations SET invitee_kind = 'alien' WHERE token = 'p'`); err == nil {
		t.Fatal("an unknown invitee kind was stored")
	}

	testdb.Migrate(t, db, dir, v, v, true)
	var n int
	if err := db.QueryRow(`SELECT count(*) FROM tenant_invitations WHERE tenant_id = $1`, tid).Scan(&n); err != nil || n != 1 {
		t.Fatalf("after down: %d invitations (%v), want the pending one only", n, err)
	}
	testdb.Migrate(t, db, dir, v, v, false)
	if err := db.QueryRow(`SELECT count(*) FROM tenant_invitations WHERE tenant_id = $1 AND resend_count = 0 AND revoked_at IS NULL`, tid).Scan(&n); err != nil || n != 1 {
		t.Fatalf("after up again: %d (%v)", n, err)
	}
}
