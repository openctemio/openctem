package postgres

import (
	"context"
	"slices"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// The requester profile of the scan approval rules reads only the tenant's
// own roles, groups and service accounts (RFC-073 §4.1): the same user's
// membership, groups and roles in another tenant never show.
func TestScanApprovals_RequesterProfile_TenantScoped_DB(t *testing.T) {
	ctx := context.Background()
	db := openScanDB(t)
	tenant := seedScanTriggerTenant(ctx, t, db)
	other := seedScanTriggerTenant(ctx, t, db)
	repo := NewScanApprovalRepository(&DB{DB: db})
	const memberRole = "00000000-0000-0000-0000-000000000003"
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := db.ExecContext(ctx, q, args...); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}

	person := shared.NewID()
	exec(`INSERT INTO users (id, email, name, status) VALUES ($1, $2, 'P', 'active')`, person.String(), person.String()+"@requester.test")
	exec(`INSERT INTO tenant_members (user_id, tenant_id, role, status) VALUES ($1, $2, 'member', 'active')`, person.String(), tenant.String())
	exec(`INSERT INTO tenant_members (user_id, tenant_id, role, status) VALUES ($1, $2, 'member', 'active')`, person.String(), other.String())
	mine, theirs := shared.NewID(), shared.NewID()
	exec(`INSERT INTO groups (id, tenant_id, name, slug, is_active) VALUES ($1, $2, 'Ops', $3, true)`, mine.String(), tenant.String(), "ops-"+mine.String()[:8])
	exec(`INSERT INTO groups (id, tenant_id, name, slug, is_active) VALUES ($1, $2, 'Ops', $3, true)`, theirs.String(), other.String(), "ops-"+theirs.String()[:8])
	exec(`INSERT INTO group_members (group_id, user_id) VALUES ($1, $2), ($3, $2)`, mine.String(), person.String(), theirs.String())

	p, err := repo.RequesterProfile(ctx, tenant, person.String())
	if err != nil {
		t.Fatal(err)
	}
	if p.ServiceAccount || !slices.Contains(p.Roles, memberRole) || !slices.Contains(p.Roles, "member") {
		t.Fatalf("profile %+v", p)
	}
	if len(p.GroupIDs) != 1 || p.GroupIDs[0] != mine.String() {
		t.Fatalf("groups %v, want only this tenant's group", p.GroupIDs)
	}

	bot := shared.NewID()
	exec(`INSERT INTO users (id, email, name, status, kind, service_tenant_id) VALUES ($1, $2, 'Bot', 'active', 'service', $3)`,
		bot.String(), "svc-"+bot.String()+"@service-accounts.invalid", tenant.String())
	exec(`INSERT INTO tenant_members (user_id, tenant_id, role, status) VALUES ($1, $2, 'member', 'active')`, bot.String(), tenant.String())
	if p, err := repo.RequesterProfile(ctx, tenant, bot.String()); err != nil || !p.ServiceAccount {
		t.Fatalf("service account: %+v %v", p, err)
	}
	// Not a member of the other tenant: an empty profile there.
	if p, err := repo.RequesterProfile(ctx, other, bot.String()); err != nil || p.ServiceAccount || len(p.Roles) != 0 {
		t.Fatalf("another tenant: %+v %v", p, err)
	}
	if p, err := repo.RequesterProfile(ctx, tenant, "not-a-uuid"); err != nil || len(p.Roles) != 0 {
		t.Fatalf("malformed id: %+v %v", p, err)
	}
}
