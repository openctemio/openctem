package integration

// Trusted organizations against a real database (RFC-058), as the
// least-privilege app role: the trust is visible only to its two
// organizations, the home accepts, and ending it suspends the host's external
// members homed there (in the host only).

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/internal/app/audit"
	orgtrustapp "github.com/openctemio/openctem/api/internal/app/orgtrust"
	"github.com/openctemio/openctem/api/internal/app/tenant"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/orgtrust"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	tenantdom "github.com/openctemio/openctem/api/pkg/domain/tenant"
	"github.com/openctemio/openctem/api/pkg/logger"
)

type trustOwners map[string]shared.ID

func (o trustOwners) OwnerOfDomain(_ context.Context, d string) (shared.ID, bool, error) {
	id, ok := o[d]
	return id, ok, nil
}

func TestOrgTrust_LifecycleAndIsolation(t *testing.T) {
	db := setupTestDB(t)
	t.Cleanup(func() { _ = db.Close() })
	ctx := context.Background()
	pdb := &postgres.DB{DB: db}
	tenantRepo := postgres.NewTenantRepository(pdb)
	trustRepo := postgres.NewOrgTrustRepository(pdb)
	tsvc := tenant.NewTenantService(tenantRepo, logger.NewNop())
	tsvc.SetLifecycleRepository(postgres.NewMemberLifecycleRepository(pdb))

	host := createTestTenant(t, db, "trust-host")
	home := createTestTenant(t, db, "trust-home")
	other := createTestTenant(t, db, "trust-other")
	owner := createTestUser(t, db, "owner-"+shared.NewID().String()+"@host.example", "Owner")
	homeOwner := createTestUser(t, db, "owner-"+shared.NewID().String()+"@home.example", "Home owner")
	nam := createTestUser(t, db, "nam-"+shared.NewID().String()+"@home.example", "Nam")
	t.Cleanup(func() {
		bg := context.Background()
		for _, tid := range []shared.ID{host, home, other} {
			_, _ = db.ExecContext(bg, `DELETE FROM audit_logs WHERE tenant_id = $1`, tid.String())
			_, _ = db.ExecContext(bg, `DELETE FROM tenant_trusts WHERE host_tenant_id = $1 OR home_tenant_id = $1`, tid.String())
			_, _ = db.ExecContext(bg, `DELETE FROM tenant_members WHERE tenant_id = $1`, tid.String())
		}
		cleanupTestData(db, host, home, other)
	})
	createTestMembership(t, db, host, owner, "owner")
	createTestMembership(t, db, home, homeOwner, "owner")

	svc := orgtrustapp.NewService(trustRepo, trustOwners{"home.example": home}, tsvc, nil, logger.NewNop())
	hostCtx := audit.AuditContext{TenantID: host.String(), ActorID: owner.String()}
	homeCtx := audit.AuditContext{TenantID: home.String(), ActorID: homeOwner.String()}

	// Unknown domain: refused.
	if _, err := svc.Request(ctx, host, owner, "nobody.example", orgtrust.DefaultSettings(), hostCtx); !orgtrustapp.IsNotFound(err) {
		t.Fatalf("unknown domain: want not found, got %v", err)
	}
	v, err := svc.Request(ctx, host, owner, "home.example", orgtrust.DefaultSettings(), hostCtx)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	if _, err := svc.Request(ctx, host, owner, "home.example", orgtrust.DefaultSettings(), hostCtx); !errors.Is(err, orgtrust.ErrExists) {
		t.Fatalf("second request: want ErrExists, got %v", err)
	}
	id := v.Trust.ID

	// A third organization cannot see or act on it.
	if _, err := trustRepo.GetForTenant(ctx, other, id); !errors.Is(err, orgtrust.ErrNotFound) {
		t.Fatalf("other organization must not see the trust, got %v", err)
	}
	if err := svc.Revoke(ctx, other, id, audit.AuditContext{TenantID: other.String()}); !errors.Is(err, orgtrust.ErrNotFound) {
		t.Fatalf("other organization must not end the trust, got %v", err)
	}
	// The host cannot accept its own request; only the home can.
	if _, err := svc.Accept(ctx, host, id, owner, false, hostCtx); !errors.Is(err, orgtrustapp.ErrNotYourSide) {
		t.Fatalf("host accepting: want ErrNotYourSide, got %v", err)
	}
	if _, err := svc.Accept(ctx, home, id, homeOwner, true, homeCtx); err != nil {
		t.Fatalf("home accepts: %v", err)
	}
	got, _ := trustRepo.GetPair(ctx, host, home)
	if !got.IsActive() || !got.HomeAttestsMFA {
		t.Fatalf("trust after acceptance: %+v", got)
	}
	// The home cannot change the host's settings.
	if _, err := svc.Update(ctx, home, id, orgtrust.DefaultSettings(), homeCtx); !errors.Is(err, orgtrustapp.ErrNotYourSide) {
		t.Fatalf("home updating: want ErrNotYourSide, got %v", err)
	}
	views, _ := svc.List(ctx, home)
	if len(views) != 1 || views[0].Direction != "incoming" {
		t.Fatalf("home list: %+v", views)
	}

	// Nam is an external member of the host homed there, and a member of
	// another organization too.
	m, _ := tenantdom.NewMembership(nam, host, tenantdom.RoleViewer, &owner)
	hm := home
	if err := m.Classify(tenantdom.Classification{Kind: tenantdom.MemberKindExternal, HomeTenantID: &hm, Domain: "home.example"}, tenantdom.ExternalAccess{}, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := tenantRepo.CreateMembership(ctx, m); err != nil {
		t.Fatal(err)
	}
	createTestMembership(t, db, other, nam, "member")

	// The home ends the trust: Nam is suspended in the host only.
	if err := svc.Revoke(ctx, home, id, homeCtx); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	inHost, _ := tenantRepo.GetMembership(ctx, nam, host)
	if !inHost.IsSuspended() || inHost.SuspendedReason() != tenantdom.SuspendedReasonTrustRevoked {
		t.Fatalf("host membership: status=%s reason=%q", inHost.Status(), inHost.SuspendedReason())
	}
	inOther, _ := tenantRepo.GetMembership(ctx, nam, other)
	if !inOther.IsActive() {
		t.Fatal("membership elsewhere must stay active")
	}
	if _, err := trustRepo.GetPair(ctx, host, home); !errors.Is(err, orgtrust.ErrNotFound) {
		t.Fatalf("trust must be gone, got %v", err)
	}
}

func TestOrgTrust_DatabaseConstraints(t *testing.T) {
	db := setupTestDB(t)
	t.Cleanup(func() { _ = db.Close() })
	a := createTestTenant(t, db, "trust-c1")
	t.Cleanup(func() { cleanupTestData(db, a) })
	if _, err := db.ExecContext(context.Background(),
		`INSERT INTO tenant_trusts (host_tenant_id, home_tenant_id) VALUES ($1, $1)`, a.String()); err == nil {
		t.Fatal("an organization must not trust itself")
	}
	b := createTestTenant(t, db, "trust-c2")
	t.Cleanup(func() {
		_, _ = db.ExecContext(context.Background(), `DELETE FROM tenant_trusts WHERE host_tenant_id = $1`, a.String())
		cleanupTestData(db, b)
	})
	if _, err := db.ExecContext(context.Background(),
		`INSERT INTO tenant_trusts (host_tenant_id, home_tenant_id, max_role) VALUES ($1, $2, 'admin')`, a.String(), b.String()); err == nil {
		t.Fatal("an external member is never an administrator: max_role admin must be refused")
	}
}
