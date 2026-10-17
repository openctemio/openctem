package postgres

import (
	"context"
	"sort"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// The e-mail list of a CI admin alert is the tenant's active owners and
// administrators only: not members, not another tenant's administrators.
func TestActiveAdminEmails_DB(t *testing.T) {
	ctx := context.Background()
	db := openGroupsDB(t)
	repo := NewMemberLifecycleRepository(&DB{DB: db})
	tenant := seedTestTenant(ctx, t, db)
	other := seedTestTenant(ctx, t, db)

	const ownerRole, adminRole, memberRole = "00000000-0000-0000-0000-000000000001", "00000000-0000-0000-0000-000000000002", "00000000-0000-0000-0000-000000000003"
	add := func(tn shared.ID, role string) string {
		u := seedGroupsUser(ctx, t, db, "adm.mail")
		if _, err := db.ExecContext(ctx, `INSERT INTO tenant_members (tenant_id, user_id, role, status) VALUES ($1, $2, 'member', 'active')`, tn.String(), u.String()); err != nil {
			t.Fatal(err)
		}
		// A trigger gives every new member the member role: replace it.
		if _, err := db.ExecContext(ctx, `DELETE FROM user_roles WHERE user_id = $1 AND tenant_id = $2`, u.String(), tn.String()); err != nil {
			t.Fatal(err)
		}
		if _, err := db.ExecContext(ctx, `INSERT INTO user_roles (user_id, tenant_id, role_id) VALUES ($1, $2, $3)`, u.String(), tn.String(), role); err != nil {
			t.Fatal(err)
		}
		var email string
		if err := db.QueryRowContext(ctx, `SELECT email FROM users WHERE id = $1`, u.String()).Scan(&email); err != nil {
			t.Fatal(err)
		}
		return email
	}
	owner, admin := add(tenant, ownerRole), add(tenant, adminRole)
	add(tenant, memberRole)
	add(other, adminRole)

	got, err := repo.ActiveAdminEmails(ctx, tenant)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{owner, admin}
	sort.Strings(got)
	sort.Strings(want)
	if len(got) != 2 || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("emails = %v, want %v", got, want)
	}
}
