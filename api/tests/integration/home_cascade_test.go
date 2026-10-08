package integration

// The home cascade against a real database (RFC-058): the home organization
// controls the person. Disabling them at home suspends their external
// memberships in other organizations (and ends every session); re-enabling
// them restores those memberships; the home losing their email domain
// suspends them too, and proving it again restores them.

import (
	"context"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/internal/app/auth"
	"github.com/openctemio/openctem/api/internal/app/tenant"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	sessiondom "github.com/openctemio/openctem/api/pkg/domain/session"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	tenantdom "github.com/openctemio/openctem/api/pkg/domain/tenant"
	"github.com/openctemio/openctem/api/pkg/logger"
)

type cascadeOwners map[string]shared.ID

func (o cascadeOwners) OwnerOfDomain(_ context.Context, d string) (shared.ID, bool, error) {
	id, ok := o[d]
	return id, ok, nil
}

func TestHomeCascade(t *testing.T) {
	db := setupTestDB(t)
	t.Cleanup(func() { _ = db.Close() })
	ctx := context.Background()
	pdb := &postgres.DB{DB: db}
	repo := postgres.NewTenantRepository(pdb)
	svc := tenant.NewTenantService(repo, logger.NewNop())
	svc.SetLifecycleRepository(postgres.NewMemberLifecycleRepository(pdb))
	svc.SetSessionService(auth.NewSessionService(postgres.NewSessionRepository(db), postgres.NewRefreshTokenRepository(db), logger.NewNop()))

	home := createTestTenant(t, db, "cascade-home")
	hostA := createTestTenant(t, db, "cascade-host-a")
	hostB := createTestTenant(t, db, "cascade-host-b")
	domain := "partner-" + shared.NewID().String()[:8] + ".example"
	userRepo := postgres.NewUserRepository(pdb)
	userSvc := tenant.NewUserService(userRepo, logger.NewNop())
	svc.SetUserService(userSvc)
	svc.SetAddressClassifier(tenant.NewAddressClassifier(cascadeOwners{domain: home},
		func(context.Context, shared.ID) (bool, error) { return true, nil }))

	owner := createTestUser(t, db, "owner-"+shared.NewID().String()+"@"+domain, "Owner")
	nam := createTestUser(t, db, "nam-"+shared.NewID().String()+"@"+domain, "Nam")
	createTestMembership(t, db, home, owner, "owner")
	namHome := createTestMembership(t, db, home, nam, "member")
	t.Cleanup(func() {
		bg := context.Background()
		_, _ = db.ExecContext(bg, `DELETE FROM sessions WHERE user_id = $1`, nam.String())
		for _, tid := range []shared.ID{home, hostA, hostB} {
			_, _ = db.ExecContext(bg, `DELETE FROM audit_logs WHERE tenant_id = $1`, tid.String())
			_, _ = db.ExecContext(bg, `DELETE FROM tenant_members WHERE tenant_id = $1`, tid.String())
		}
		cleanupTestData(db, home, hostA, hostB)
	})

	addExternal := func(host shared.ID) {
		m, _ := tenantdom.NewMembership(nam, host, tenantdom.RoleViewer, nil)
		h := home
		if err := m.Classify(tenantdom.Classification{Kind: tenantdom.MemberKindExternal, HomeTenantID: &h, Domain: domain},
			tenantdom.ExternalAccess{}, time.Now()); err != nil {
			t.Fatal(err)
		}
		if err := repo.CreateMembership(ctx, m); err != nil {
			t.Fatal(err)
		}
	}
	addExternal(hostA)
	addExternal(hostB)
	sessRepo := postgres.NewSessionRepository(db)
	sess, _ := sessiondom.New(nam, "tok-"+shared.NewID().String(), "127.0.0.1", "UA", time.Hour)
	if err := sessRepo.Create(ctx, sess); err != nil {
		t.Fatal(err)
	}
	status := func(host shared.ID) (string, string) {
		m, err := repo.GetMembership(ctx, nam, host)
		if err != nil {
			t.Fatal(err)
		}
		return string(m.Status()), m.SuspendedReason()
	}

	// The home disables Nam.
	ownerCtx := audit.AuditContext{TenantID: home.String(), ActorID: owner.String()}
	if err := svc.SuspendMember(ctx, namHome.String(), ownerCtx); err != nil {
		t.Fatalf("suspend at home: %v", err)
	}
	for _, h := range []shared.ID{hostA, hostB} {
		if st, reason := status(h); st != "suspended" || reason != tenantdom.SuspendedReasonHomeAccessEnded {
			t.Fatalf("host membership after home suspension: %s / %s", st, reason)
		}
	}
	var got string
	if err := db.QueryRowContext(ctx, `SELECT status FROM sessions WHERE id = $1`, sess.ID().String()).Scan(&got); err != nil {
		t.Fatal(err)
	}
	if got != "revoked" {
		t.Fatalf("the home owns the identity: every session must end, got %q", got)
	}

	// The home re-enables Nam: both come back.
	if err := svc.ReactivateMember(ctx, namHome.String(), ownerCtx); err != nil {
		t.Fatalf("reactivate at home: %v", err)
	}
	for _, h := range []shared.ID{hostA, hostB} {
		if st, _ := status(h); st != "active" {
			t.Fatalf("host membership after home reactivation: %s", st)
		}
	}

	// A host suspends Nam itself; a later home cycle must not undo that.
	ma, _ := repo.GetMembership(ctx, nam, hostA)
	if err := svc.SuspendMember(ctx, ma.ID().String(), audit.AuditContext{TenantID: hostA.String()}); err != nil {
		t.Fatal(err)
	}

	// The home loses the domain: B's membership is suspended; proving it
	// again restores it, but A's own suspension stays.
	svc.HomeDomainLost(ctx, home, domain)
	if st, reason := status(hostB); st != "suspended" || reason != tenantdom.SuspendedReasonHomeDomainLapsed {
		t.Fatalf("host B after the domain lapsed: %s / %s", st, reason)
	}
	svc.HomeDomainRestored(ctx, home, domain)
	if st, _ := status(hostB); st != "active" {
		t.Fatalf("host B after the domain was proven again: %s", st)
	}
	if st, reason := status(hostA); st != "suspended" || reason != "" {
		t.Fatalf("host A's own suspension must stay: %s / %q", st, reason)
	}
}
