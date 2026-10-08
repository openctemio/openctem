package integration

// External members against a real database (RFC-058): the owner role can
// never be held by an external member (trigger and CHECK), the external
// fields round-trip, and an expired membership is suspended in its own
// organization and re-enabled with a new end date.

import (
	"context"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/internal/app/tenant"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	tenantdom "github.com/openctemio/openctem/api/pkg/domain/tenant"
	"github.com/openctemio/openctem/api/pkg/logger"
)

type extFixture struct {
	repo           *postgres.TenantRepository
	svc            *tenant.TenantService
	host, home, b  shared.ID
	owner, outside shared.ID
	ownerCtx       audit.AuditContext
}

func newExtFixture(t *testing.T) (*extFixture, func(q string, args ...any) error) {
	t.Helper()
	db := setupTestDB(t)
	t.Cleanup(func() { _ = db.Close() })
	pdb := &postgres.DB{DB: db}
	f := &extFixture{repo: postgres.NewTenantRepository(pdb)}
	f.svc = tenant.NewTenantService(f.repo, logger.NewNop())
	f.svc.SetLifecycleRepository(postgres.NewMemberLifecycleRepository(pdb))
	f.host = createTestTenant(t, db, "ext-host")
	f.home = createTestTenant(t, db, "ext-home")
	f.b = createTestTenant(t, db, "ext-other")
	stamp := time.Now().UnixNano()
	f.owner = createTestUser(t, db, "owner-"+shared.NewID().String()+"@pti.example", "Owner")
	f.outside = createTestUser(t, db, "nam-"+shared.NewID().String()+"@ipas.example", "Nam")
	_ = stamp
	createTestMembership(t, db, f.host, f.owner, "owner")
	f.ownerCtx = audit.AuditContext{TenantID: f.host.String(), ActorID: f.owner.String()}
	t.Cleanup(func() {
		bg := context.Background()
		for _, tid := range []shared.ID{f.host, f.home, f.b} {
			_, _ = db.ExecContext(bg, `DELETE FROM audit_logs WHERE tenant_id = $1`, tid.String())
			_, _ = db.ExecContext(bg, `DELETE FROM tenant_members WHERE tenant_id = $1`, tid.String())
		}
		cleanupTestData(db, f.host, f.home, f.b)
	})
	exec := func(q string, args ...any) error {
		_, err := db.ExecContext(context.Background(), q, args...)
		return err
	}
	return f, exec
}

func (f *extFixture) addExternal(t *testing.T, until *time.Time) *tenantdom.Membership {
	t.Helper()
	m, err := tenantdom.NewMembership(f.outside, f.host, tenantdom.RoleViewer, &f.owner)
	if err != nil {
		t.Fatal(err)
	}
	home := f.home
	if err := m.Classify(tenantdom.Classification{Kind: tenantdom.MemberKindExternal, HomeTenantID: &home, Domain: "ipas.example"},
		tenantdom.ExternalAccess{ExpiresAt: until, Reason: "project"}, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if err := f.repo.CreateMembership(context.Background(), m); err != nil {
		t.Fatalf("create external membership: %v", err)
	}
	return m
}

func TestExternalMember_RoundTripAndNeverOwner(t *testing.T) {
	f, exec := newExtFixture(t)
	until := time.Now().Add(48 * time.Hour).UTC().Truncate(time.Second)
	f.addExternal(t, &until)

	got, err := f.repo.GetMembership(context.Background(), f.outside, f.host)
	if err != nil {
		t.Fatal(err)
	}
	if !got.IsExternal() || got.HomeTenantID() == nil || *got.HomeTenantID() != f.home ||
		got.ExpiresAt() == nil || !got.ExpiresAt().Equal(until) || got.ExpiryReason() != "project" {
		t.Fatalf("external fields lost: kind=%s home=%v exp=%v reason=%q", got.Kind(), got.HomeTenantID(), got.ExpiresAt(), got.ExpiryReason())
	}

	// The owner role, through user_roles or the membership row, is refused
	// by the database for an external member.
	if err := exec(`INSERT INTO user_roles (user_id, tenant_id, role_id) VALUES ($1, $2, '00000000-0000-0000-0000-000000000001')`,
		f.outside.String(), f.host.String()); err == nil {
		t.Fatal("an external member must not get the owner role in user_roles")
	}
	if err := exec(`UPDATE tenant_members SET role = 'owner' WHERE user_id = $1 AND tenant_id = $2`,
		f.outside.String(), f.host.String()); err == nil {
		t.Fatal("an external membership must not get the owner role")
	}
	// ... and the owner cannot be turned external.
	if err := exec(`UPDATE tenant_members SET kind = 'external' WHERE user_id = $1 AND tenant_id = $2`,
		f.owner.String(), f.host.String()); err == nil {
		t.Fatal("the owner must not become an external member")
	}

	// The members list names the home organization.
	list, err := f.repo.ListMembersWithUserInfo(context.Background(), f.host)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, m := range list {
		if m.UserID == f.outside {
			found = true
			if m.Kind != tenantdom.MemberKindExternal || m.HomeTenantName == "" || m.ExpiresAt == nil {
				t.Fatalf("list row: kind=%s home=%q exp=%v", m.Kind, m.HomeTenantName, m.ExpiresAt)
			}
		}
	}
	if !found {
		t.Fatal("external member not listed")
	}
}

func TestExternalMember_ExpiryAndExtension(t *testing.T) {
	f, exec := newExtFixture(t)
	until := time.Now().Add(time.Hour).UTC()
	m := f.addExternal(t, &until)
	// The same person is also a member elsewhere: expiry in the host must not
	// touch that membership.
	if err := exec(`INSERT INTO tenant_members (id, user_id, tenant_id, role) VALUES ($1, $2, $3, 'member')`,
		shared.NewID().String(), f.outside.String(), f.b.String()); err != nil {
		t.Fatal(err)
	}

	// Not expired yet.
	if n, err := f.svc.ExpireMemberships(context.Background(), time.Now().UTC(), 50); err != nil || n != 0 {
		t.Fatalf("nothing expired yet: n=%d err=%v", n, err)
	}
	// Two hours later the access has ended.
	n, err := f.svc.ExpireMemberships(context.Background(), time.Now().Add(2*time.Hour).UTC(), 50)
	if err != nil || n != 1 {
		t.Fatalf("expired: n=%d err=%v", n, err)
	}
	got, _ := f.repo.GetMembership(context.Background(), f.outside, f.host)
	if !got.IsSuspended() || got.SuspendedReason() != tenantdom.SuspendedReasonExpired {
		t.Fatalf("status=%s reason=%q", got.Status(), got.SuspendedReason())
	}
	other, _ := f.repo.GetMembership(context.Background(), f.outside, f.b)
	if other == nil || !other.IsActive() {
		t.Fatal("the person's membership in another organization must stay active")
	}

	// A plain reactivation is refused: the access has ended.
	if err := f.svc.ReactivateMember(context.Background(), m.ID().String(), f.ownerCtx); err == nil {
		t.Fatal("reactivating an expired member without a new end date must be refused")
	}
	// A new end date re-enables them.
	next := time.Now().Add(30 * 24 * time.Hour).UTC()
	if _, err := f.svc.ExtendMemberAccess(context.Background(), m.ID().String(),
		tenant.ExtendMemberAccessInput{ExpiresAt: &next, Reason: "renewed"}, f.ownerCtx); err != nil {
		t.Fatalf("extend: %v", err)
	}
	got, _ = f.repo.GetMembership(context.Background(), f.outside, f.host)
	if !got.IsActive() || got.ExpiresAt() == nil || got.ExpiresAt().Before(next.Add(-time.Second)) || got.SuspendedReason() != "" {
		t.Fatalf("after extension: status=%s exp=%v reason=%q", got.Status(), got.ExpiresAt(), got.SuspendedReason())
	}
	// More than 365 days is refused.
	tooLate := time.Now().Add(400 * 24 * time.Hour)
	if _, err := f.svc.ExtendMemberAccess(context.Background(), m.ID().String(),
		tenant.ExtendMemberAccessInput{ExpiresAt: &tooLate}, f.ownerCtx); err == nil {
		t.Fatal("an end date beyond 365 days must be refused")
	}
	// An internal member has no access end date.
	ownerM, _ := f.repo.GetMembership(context.Background(), f.owner, f.host)
	if _, err := f.svc.ExtendMemberAccess(context.Background(), ownerM.ID().String(),
		tenant.ExtendMemberAccessInput{ExpiresAt: &next}, f.ownerCtx); err == nil {
		t.Fatal("an internal member must not get an access end date")
	}
}
