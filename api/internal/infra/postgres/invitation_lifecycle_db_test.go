package postgres

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/tenant"
)

// Invitation lifecycle against the database (RFC-095 §5): a revoked
// invitation keeps its row (the daily limit counts what was sent) but its
// token, pending listing and resend stop working; acceptance is single use;
// an inviter is capped per hour; the send history round-trips; and nothing
// crosses organizations.
func TestInvitationLifecycle_DB(t *testing.T) {
	db := openRoleRaceDB(t)
	ctx := context.Background()
	repo := NewTenantRepository(db)
	tenantA, tenantB := seedTenant(ctx, t, db), seedTenant(ctx, t, db)
	inviter := seedUser(ctx, t, db)
	t.Cleanup(func() {
		_, _ = db.ExecContext(context.Background(), `DELETE FROM tenant_invitations WHERE invited_by = $1`, inviter.String())
	})

	newInv := func(tid shared.ID, email string) *tenant.Invitation {
		t.Helper()
		inv, err := tenant.NewInvitation(tid, email, tenant.RoleMember, inviter, []string{"00000000-0000-0000-0000-000000000003"})
		if err != nil {
			t.Fatal(err)
		}
		if err := inv.SetInviteeInfo(tenant.InviteeInfo{Kind: tenant.MemberKindExternal, Privileged: true}); err != nil {
			t.Fatal(err)
		}
		if err := repo.CreateInvitation(ctx, inv); err != nil {
			t.Fatalf("create: %v", err)
		}
		return inv
	}

	inv := newInv(tenantA, "life-"+shared.NewID().String()[:8]+"@gmail.com")
	got, err := repo.GetInvitationByToken(ctx, inv.Token())
	if err != nil {
		t.Fatal(err)
	}
	if info := got.InviteeInfo(); info.Kind != tenant.MemberKindExternal || !info.Privileged || got.ResendCount() != 0 {
		t.Fatalf("round trip: %+v resends=%d", info, got.ResendCount())
	}

	// Resend history persists.
	if err := got.MarkResent(time.Now().Add(tenant.ResendCooldown)); err != nil {
		t.Fatal(err)
	}
	if err := repo.UpdateInvitation(ctx, got); err != nil {
		t.Fatal(err)
	}
	again, _ := repo.GetInvitationByID(ctx, tenantA, inv.ID())
	if again.ResendCount() != 1 {
		t.Fatalf("resend count = %d", again.ResendCount())
	}

	// Another organization neither reads nor revokes it.
	if _, err := repo.GetInvitationByID(ctx, tenantB, inv.ID()); !errors.Is(err, shared.ErrNotFound) {
		t.Errorf("tenant B reads A's invitation: %v", err)
	}
	if err := repo.DeleteInvitation(ctx, tenantB, inv.ID()); !errors.Is(err, shared.ErrNotFound) {
		t.Errorf("tenant B revokes A's invitation: %v", err)
	}

	// Revoke: the row stays, the token, by-id lookup and pending list stop.
	if err := repo.DeleteInvitation(ctx, tenantA, inv.ID()); err != nil {
		t.Fatal(err)
	}
	var rows int
	_ = db.QueryRowContext(ctx, `SELECT count(*) FROM tenant_invitations WHERE id = $1 AND revoked_at IS NOT NULL`, inv.ID().String()).Scan(&rows)
	if rows != 1 {
		t.Fatal("the revoked invitation was deleted instead of kept")
	}
	if _, err := repo.GetInvitationByToken(ctx, inv.Token()); !errors.Is(err, shared.ErrNotFound) {
		t.Errorf("a revoked token still resolves: %v", err)
	}
	if _, err := repo.GetPendingInvitationByEmail(ctx, tenantA, inv.Email()); !errors.Is(err, shared.ErrNotFound) {
		t.Errorf("a revoked invitation is still pending: %v", err)
	}
	if err := repo.DeleteInvitation(ctx, tenantA, inv.ID()); !errors.Is(err, shared.ErrNotFound) {
		t.Errorf("revoking twice: %v", err)
	}

	// Single use: accepting an already accepted invitation updates nothing.
	inv2 := newInv(tenantA, "once-"+shared.NewID().String()[:8]+"@gmail.com")
	if err := inv2.Accept(); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE tenant_invitations SET accepted_at = now() WHERE id = $1`, inv2.ID().String()); err != nil {
		t.Fatal(err)
	}
	m, _ := tenant.NewMembership(seedUser(ctx, t, db), tenantA, tenant.RoleMember, &inviter)
	if err := repo.AcceptInvitationTx(ctx, inv2, m); !errors.Is(err, shared.ErrNotFound) {
		t.Errorf("second acceptance: %v, want not found", err)
	}

	// Per-inviter hourly cap.
	if _, err := db.ExecContext(ctx, `
		INSERT INTO tenant_invitations (tenant_id, email, role, token, invited_by, expires_at)
		SELECT $1, 'bulk-' || g || '-' || $3 || '@example.com', 'member', 'bulk-' || g || '-' || $3, $2, now() + interval '7 days'
		FROM generate_series(1, $4) g`, tenantA.String(), inviter.String(), shared.NewID().String()[:8], tenant.InvitationsPerInviterPerHour); err != nil {
		t.Fatal(err)
	}
	over, _ := tenant.NewInvitation(tenantA, "over@example.com", tenant.RoleMember, inviter, []string{"00000000-0000-0000-0000-000000000003"})
	if err := repo.CreateInvitation(ctx, over); !errors.Is(err, tenant.ErrInvitationRateLimited) {
		t.Errorf("over the hourly cap: %v", err)
	}
}
