package postgres

// The scope approver directory and the approval rows (RFC-054 §7,
// amendment 2026-10-09), against a migrated database.

import (
	"context"
	"database/sql"
	"testing"
	"time"

	_ "github.com/lib/pq"

	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/domain/scope"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func openScopeApproversDB(t *testing.T) *sql.DB {
	t.Helper()
	dbURL := testdb.URL()
	if dbURL == "" {
		t.Skip("DATABASE_URL not set; skipping scope approvers test")
	}
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		t.Skipf("open db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.PingContext(context.Background()); err != nil {
		testdb.Skipf(t, "cannot reach DATABASE_URL: %v", err)
	}
	return db
}

type approverSeed struct {
	t      *testing.T
	db     *sql.DB
	tenant shared.ID
}

func newApproverSeed(t *testing.T, db *sql.DB) approverSeed {
	t.Helper()
	id := shared.NewID()
	if _, err := db.Exec(`INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $2)`, id.String(), "approvers-"+id.String()); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	t.Cleanup(func() { _, _ = db.Exec(`DELETE FROM tenants WHERE id = $1`, id.String()) })
	return approverSeed{t: t, db: db, tenant: id}
}

// member adds a user with a membership of the given status and system role.
func (s approverSeed) member(name, role, status string) string {
	s.t.Helper()
	uid := shared.NewID().String()
	if _, err := s.db.Exec(`INSERT INTO users (id, email, name, status) VALUES ($1, $2, $3, 'active')`,
		uid, uid+"@approvers.test", name); err != nil {
		s.t.Fatalf("seed user: %v", err)
	}
	s.t.Cleanup(func() { _, _ = s.db.Exec(`DELETE FROM users WHERE id = $1`, uid) })
	if _, err := s.db.Exec(`INSERT INTO tenant_members (user_id, tenant_id, role, status) VALUES ($1, $2, $3, $4)`,
		uid, s.tenant.String(), role, status); err != nil {
		s.t.Fatalf("seed membership: %v", err)
	}
	roleIDs := map[string]string{"owner": "00000000-0000-0000-0000-000000000001", "admin": "00000000-0000-0000-0000-000000000002",
		"member": "00000000-0000-0000-0000-000000000003", "viewer": "00000000-0000-0000-0000-000000000004"}
	if _, err := s.db.Exec(`INSERT INTO user_roles (user_id, tenant_id, role_id) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING`,
		uid, s.tenant.String(), roleIDs[role]); err != nil {
		s.t.Fatalf("seed role: %v", err)
	}
	return uid
}

// customApprover gives uid a custom role of the tenant holding the scope
// approval permission.
func (s approverSeed) customApprover(uid string) {
	s.t.Helper()
	rid := shared.NewID().String()
	if _, err := s.db.Exec(`INSERT INTO roles (id, tenant_id, slug, name, is_system) VALUES ($1, $2, $3, $3, false)`,
		rid, s.tenant.String(), "scope-approver-"+rid[:8]); err != nil {
		s.t.Fatalf("seed custom role: %v", err)
	}
	if _, err := s.db.Exec(`INSERT INTO role_permissions (role_id, permission_id) VALUES ($1, 'attack_surface:scope:approve')`, rid); err != nil {
		s.t.Fatalf("seed role permission: %v", err)
	}
	if _, err := s.db.Exec(`INSERT INTO user_roles (user_id, tenant_id, role_id) VALUES ($1, $2, $3)`, uid, s.tenant.String(), rid); err != nil {
		s.t.Fatalf("assign custom role: %v", err)
	}
}

func TestScopeApprovers_Directory(t *testing.T) {
	db := openScopeApproversDB(t)
	s := newApproverSeed(t, db)
	owner := s.member("Olivia Owner", "owner", "active")
	admin := s.member("Adam Admin", "admin", "active")
	custom := s.member("Carla Custom", "member", "active")
	s.customApprover(custom)
	plain := s.member("Max Member", "member", "active")
	suspended := s.member("Sam Suspended", "admin", "suspended")

	// Another organization's admin, and the same custom approver's
	// membership there, never show up here.
	other := newApproverSeed(t, db)
	otherAdmin := other.member("Other Admin", "admin", "active")

	repo := NewScopeActorRepository(&DB{DB: db})
	got, err := repo.ScopeApprovers(context.Background(), s.tenant)
	if err != nil {
		t.Fatal(err)
	}
	ids := map[string]scope.Approver{}
	for _, a := range got {
		ids[a.UserID] = a
	}
	for _, want := range []string{owner, admin, custom} {
		if _, ok := ids[want]; !ok {
			t.Fatalf("approver %s missing from %+v", want, got)
		}
	}
	for _, not := range []string{plain, suspended, otherAdmin} {
		if _, ok := ids[not]; ok {
			t.Fatalf("%s listed as an approver", not)
		}
	}
	if !ids[owner].Owner || ids[admin].Owner || ids[custom].Owner {
		t.Fatalf("owner flags wrong: %+v", got)
	}
	if got[0].UserID != owner {
		t.Fatal("owners are not listed first")
	}
}

func TestScopeApprovers_SelfApprovalRowAndReminder(t *testing.T) {
	db := openScopeApproversDB(t)
	s := newApproverSeed(t, db)
	owner := s.member("Olivia Owner", "owner", "active")
	repo := NewScopeTargetRepository(&DB{DB: db})
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Microsecond)
	exp := now.Add(72 * time.Hour)
	e, err := scope.NewEntry(s.tenant, scope.TargetTypeDomain, "t2.approvers.example", "", owner, scope.EntryOptions{
		Reason: "window", ExpiresAt: &exp, MaxTier: scope.TierIntrusive, ApprovalsRequired: 1, Now: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := repo.Create(ctx, e); err != nil {
		t.Fatal(err)
	}

	ok, err := repo.MarkReminded(ctx, s.tenant, e.ID(), now, time.Hour)
	if err != nil || !ok {
		t.Fatalf("first reminder: %v %v", ok, err)
	}
	if ok, _ := repo.MarkReminded(ctx, s.tenant, e.ID(), now.Add(time.Minute), time.Hour); ok {
		t.Fatal("a second reminder within the hour was recorded")
	}
	if ok, _ := repo.MarkReminded(ctx, shared.NewID(), e.ID(), now.Add(2*time.Hour), time.Hour); ok {
		t.Fatal("another tenant recorded a reminder")
	}

	if err := e.SelfApprove(owner, "only owner", now); err != nil {
		t.Fatal(err)
	}
	if err := repo.Update(ctx, e); err != nil {
		t.Fatal(err)
	}
	got, err := repo.GetByID(ctx, s.tenant, e.ID())
	if err != nil {
		t.Fatal(err)
	}
	if got.RemindedAt() == nil || !got.InEffect(time.Now()) {
		t.Fatalf("reloaded entry: reminded %v status %s", got.RemindedAt(), got.Status())
	}
	if len(got.Approvals()) != 1 || !got.Approvals()[0].Self || got.Approvals()[0].Reason != "only owner" {
		t.Fatalf("approval row %+v, want a self-approval with its reason", got.Approvals())
	}
	// The database refuses a self-approval row without a reason.
	if _, err := db.Exec(`INSERT INTO scope_target_approvals (tenant_id, target_id, approver_id, self_approved, reason)
		VALUES ($1, $2, 'someone', true, ' ')`, s.tenant.String(), e.ID().String()); err == nil {
		t.Fatal("a self-approval without a reason was stored")
	}
	if ok, _ := repo.MarkReminded(ctx, s.tenant, e.ID(), now.Add(3*time.Hour), time.Hour); ok {
		t.Fatal("a reminder was recorded for an entry in effect")
	}
}
