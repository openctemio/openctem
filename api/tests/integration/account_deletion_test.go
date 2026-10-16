package integration

// Self-service account deletion and leaving an organization (RFC-104), end
// to end on the database.

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/internal/app/accountdeletion"
	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/internal/app/auth"
	"github.com/openctemio/openctem/api/internal/app/tenant"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	sessiondom "github.com/openctemio/openctem/api/pkg/domain/session"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	tenantdom "github.com/openctemio/openctem/api/pkg/domain/tenant"
	"github.com/openctemio/openctem/api/pkg/logger"
)

func TestAccountDeletionAndLeave(t *testing.T) {
	db := setupTestDB(t)
	t.Cleanup(func() { _ = db.Close() })
	ctx := context.Background()
	pdb := &postgres.DB{DB: db}
	repo := postgres.NewTenantRepository(pdb)
	sessions := auth.NewSessionService(postgres.NewSessionRepository(db), postgres.NewRefreshTokenRepository(db), logger.NewNop())
	tsvc := tenant.NewTenantService(repo, logger.NewNop())
	tsvc.SetLifecycleRepository(postgres.NewMemberLifecycleRepository(pdb))
	tsvc.SetSessionService(sessions)
	tsvc.SetUserService(tenant.NewUserService(postgres.NewUserRepository(pdb), logger.NewNop()))
	deletions := postgres.NewAccountDeletionRepository(pdb)
	svc := accountdeletion.NewService(deletions, tsvc, sessions, nil, tenant.ErasedUserLabel, logger.NewNop())

	org := createTestTenant(t, db, "acctdel")
	other := createTestTenant(t, db, "acctdel-other")
	stamp := shared.NewID().String()[28:]
	owner := createTestUser(t, db, "owner-"+stamp+"@acctdel.example", "Owner")
	member := createTestUser(t, db, "member-"+stamp+"@acctdel.example", "Member")
	leaver := createTestUser(t, db, "leaver-"+stamp+"@acctdel.example", "Leaver")
	t.Cleanup(func() {
		bg := context.Background()
		for _, tid := range []shared.ID{org, other} {
			_, _ = db.ExecContext(bg, `DELETE FROM audit_logs WHERE tenant_id = $1`, tid.String())
			_, _ = db.ExecContext(bg, `DELETE FROM user_roles WHERE tenant_id = $1`, tid.String())
			_, _ = db.ExecContext(bg, `DELETE FROM tenant_members WHERE tenant_id = $1`, tid.String())
		}
		for _, u := range []shared.ID{owner, member, leaver} {
			_, _ = db.ExecContext(bg, `DELETE FROM sessions WHERE user_id = $1`, u.String())
			_, _ = db.ExecContext(bg, `DELETE FROM users WHERE id = $1`, u.String())
		}
		cleanupTestData(db, org, other)
	})
	join := func(tid, uid shared.ID, role tenantdom.Role) {
		t.Helper()
		m, err := tenantdom.NewMembership(uid, tid, role, nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := repo.CreateMembership(ctx, m); err != nil {
			t.Fatal(err)
		}
	}
	join(org, owner, tenantdom.RoleOwner)
	join(org, member, tenantdom.RoleMember)
	join(other, member, tenantdom.RoleViewer)
	join(org, leaver, tenantdom.RoleViewer)

	// The only owner cannot delete their account; the organization is named
	// to them.
	_, err := svc.Request(ctx, owner, auditapp.AuditContext{})
	var sole *accountdeletion.SoleOwnerError
	if !errors.As(err, &sole) || len(sole.Organizations) != 1 || sole.Organizations[0] != "acctdel" {
		t.Fatalf("the only owner must be refused with the organization named, got %v", err)
	}
	// ... nor leave.
	if err := tsvc.LeaveOrganization(ctx, org, owner, auditapp.AuditContext{}); !errors.Is(err, tenant.ErrSoleOwnerCannotLeave) {
		t.Fatalf("the only owner cannot leave, got %v", err)
	}

	// A member asks: sessions end and keys are revoked at once.
	sess, _ := sessiondom.New(member, "tok-"+stamp, "127.0.0.1", "UA", time.Hour)
	if err := postgres.NewSessionRepository(db).Create(ctx, sess); err != nil {
		t.Fatal(err)
	}
	keyID := shared.NewID().String()
	if _, err := db.Exec(`INSERT INTO api_keys (id, tenant_id, user_id, name, key_hash, key_prefix, status, created_at, updated_at)
		VALUES ($1, $2, $3, 'k', $4, 'ock_x', 'active', NOW(), NOW())`, keyID, org.String(), member.String(), "h-"+keyID); err != nil {
		t.Fatalf("api key: %v", err)
	}
	t.Cleanup(func() { _, _ = db.Exec(`DELETE FROM api_keys WHERE id = $1`, keyID) })
	eraseAfter, err := svc.Request(ctx, member, auditapp.AuditContext{})
	if err != nil || eraseAfter.Before(time.Now().Add(13*24*time.Hour)) {
		t.Fatalf("request: %v %v", eraseAfter, err)
	}
	var active int
	_ = db.QueryRow(`SELECT COUNT(*) FROM sessions WHERE user_id = $1 AND status = 'active'`, member.String()).Scan(&active)
	var keyStatus string
	_ = db.QueryRow(`SELECT status FROM api_keys WHERE id = $1`, keyID).Scan(&keyStatus)
	if active != 0 || keyStatus != "revoked" {
		t.Fatalf("sessions and keys end at the request: %d active sessions, key %s", active, keyStatus)
	}

	// Signing in again cancels it.
	svc.CancelOnSignIn(ctx, member)
	if _, err := svc.Status(ctx, member); !errors.Is(err, accountdeletion.ErrNotScheduled) {
		t.Fatalf("signing in cancels the deletion, got %v", err)
	}

	// Asked again and the grace period ends: the account leaves every
	// organization and its personal data is erased.
	if _, err := svc.Request(ctx, member, auditapp.AuditContext{}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE account_deletions SET erase_after = NOW() - interval '1 minute' WHERE user_id = $1`, member.String()); err != nil {
		t.Fatal(err)
	}
	if n, err := svc.EraseDue(ctx); err != nil || n != 1 {
		t.Fatalf("erase due: %d %v", n, err)
	}
	var email, name, status string
	if err := db.QueryRow(`SELECT email, name, status FROM users WHERE id = $1`, member.String()).Scan(&email, &name, &status); err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(email, "@erased.invalid") || !strings.HasPrefix(name, "Deleted user #") || status != "inactive" {
		t.Fatalf("the account must be anonymised: %s %s %s", email, name, status)
	}
	for _, tid := range []shared.ID{org, other} {
		m, err := repo.GetMembership(ctx, member, tid)
		if err != nil || !m.IsOffboarded() {
			t.Fatalf("membership in %s must be offboarded: %+v %v", tid, m, err)
		}
	}
	if _, err := svc.Status(ctx, member); !errors.Is(err, accountdeletion.ErrNotScheduled) {
		t.Fatal("the request is removed once the account is erased")
	}

	// A member leaves on their own: offboarded, the owner stays.
	if err := tsvc.LeaveOrganization(ctx, org, leaver, auditapp.AuditContext{ActorEmail: "leaver"}); err != nil {
		t.Fatalf("leave: %v", err)
	}
	if m, err := repo.GetMembership(ctx, leaver, org); err != nil || !m.IsOffboarded() {
		t.Fatalf("the leaver is offboarded: %+v %v", m, err)
	}
	if err := tsvc.LeaveOrganization(ctx, other, leaver, auditapp.AuditContext{}); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("leaving an organization one is not in answers not found, got %v", err)
	}
}
