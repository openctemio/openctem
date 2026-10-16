package integration

// The internal entitlements API's writes against a real Postgres
// (docs/architecture/limits.md): an organization provisioned by the control
// plane is created with its limits, denies and idle policy in one
// transaction; the control plane's limits apply only through its source;
// replacing them never touches the operator's rows or another organization.
//
// Requires DATABASE_URL pointing at a fully migrated database.

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/openctemio/openctem/api/internal/app/accesscontrol"
	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/internal/app/entitlement"
	tenantapp "github.com/openctemio/openctem/api/internal/app/tenant"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/limits"
	"github.com/openctemio/openctem/api/pkg/logger"
)

func TestControlPlaneProvisioningAndSource(t *testing.T) {
	pg := openConsoleDB(t)
	ctx := context.Background()
	log := logger.NewNop()
	tenantRepo := postgres.NewTenantRepository(pg)
	users := postgres.NewUserRepository(pg)
	roles := accesscontrol.NewRoleService(postgres.NewRoleRepository(pg), postgres.NewPermissionRepository(pg), log,
		accesscontrol.WithRoleMembershipReader(tenantRepo))
	prov := tenantapp.NewUserProvisioningService(tenantRepo, users, roles, nil, nil, log)
	tenants := tenantapp.NewTenantService(tenantRepo, log)
	creator := tenantapp.NewOrganizationCreator(tenants, prov, users, log)
	lims := postgres.NewLimitsRepository(pg)

	provision := func(slug string, in *tenantapp.ProvisionedEntitlements) (*tenantapp.CreatedOrganization, error) {
		t.Cleanup(func() {
			_, _ = pg.Exec(`DELETE FROM users WHERE id IN (SELECT m.user_id FROM tenant_members m JOIN tenants t ON t.id = m.tenant_id WHERE t.slug = $1)`, slug)
			_, _ = pg.Exec(`DELETE FROM tenants WHERE slug = $1`, slug)
		})
		return creator.Create(ctx, tenantapp.CreateOrganizationInput{
			Name: "Provisioned " + slug, Slug: slug, OwnerEmail: slug + "@example.com", Provisioned: in,
		}, auditapp.AuditContext{ActorEmail: entitlement.ControlPlaneActor})
	}

	slugA, slugB := "cp-a-"+uuid.NewString()[:8], "cp-b-"+uuid.NewString()[:8]
	a, err := provision(slugA, &tenantapp.ProvisionedEntitlements{
		Limits: limits.Limits{limits.Seats: 1, limits.Assets: 500}, DeniedFeatures: []string{"pentest"}, IdlePolicy: true, Reason: "service tier",
	})
	if err != nil {
		t.Fatalf("provision: %v", err)
	}
	b, err := provision(slugB, nil)
	if err != nil {
		t.Fatalf("provision without entitlements: %v", err)
	}
	aID, bID := a.Tenant.ID(), b.Tenant.ID()

	// Written with the organization.
	cp, err := lims.ListLimits(ctx, aID, limits.OriginControlPlane)
	if err != nil || len(cp) != 2 {
		t.Fatalf("control-plane limits: %+v %v", cp, err)
	}
	if d, _ := lims.ListDenies(ctx, aID, limits.OriginControlPlane); len(d) != 1 || d[0].Feature != "pentest" {
		t.Fatalf("control-plane denies: %+v", d)
	}
	var idle bool
	if err := pg.QueryRow(`SELECT policy_enabled FROM tenant_idle_lifecycle WHERE tenant_id = $1`, aID.String()).Scan(&idle); err != nil || !idle {
		t.Fatalf("idle policy: %v %v", idle, err)
	}
	if l, _ := lims.ListLimits(ctx, bID, limits.OriginControlPlane); len(l) != 0 {
		t.Fatalf("b got limits: %+v", l)
	}

	// The rows apply only through the control-plane source.
	ent := entitlement.NewService(lims, nil, log)
	if err := ent.Check(ctx, aID, limits.Seats, 1); err != nil {
		t.Fatalf("without the source the control plane's rows are ignored: %v", err)
	}
	ent.SetSources(entitlement.NewControlPlaneSource(lims))
	var lim *limits.ErrLimitReached
	if err := ent.Check(ctx, aID, limits.Seats, 1); !errors.As(err, &lim) || lim.Limit != 1 || lim.Used != 1 {
		t.Fatalf("one seat used by the owner, limit 1: %v", err)
	}
	if err := ent.Check(ctx, bID, limits.Seats, 1); err != nil {
		t.Fatalf("another organization is unaffected: %v", err)
	}

	// The operator's own limit wins, and survives a control-plane replace.
	if err := lims.SetLimit(ctx, limits.Limit{TenantID: aID, Key: limits.Seats, Value: 10, Origin: limits.OriginOperator, Reason: "support"}); err != nil {
		t.Fatal(err)
	}
	if err := ent.Check(ctx, aID, limits.Seats, 1); err != nil {
		t.Fatalf("operator limit wins: %v", err)
	}
	call := entitlement.ControlPlaneCall{Subject: "cloud", TokenID: "jti", Reason: "downgrade"}
	if err := ent.ApplyControlPlane(ctx, aID, limits.Limits{limits.Assets: 100}, nil, call); err != nil {
		t.Fatal(err)
	}
	if cp, _ := lims.ListLimits(ctx, aID, limits.OriginControlPlane); len(cp) != 1 || cp[0].Key != limits.Assets {
		t.Fatalf("replaced: %+v", cp)
	}
	if op, _ := lims.ListLimits(ctx, aID, limits.OriginOperator); len(op) != 1 || op[0].Value != 10 {
		t.Fatalf("the operator's row is untouched: %+v", op)
	}
	if d, _ := lims.ListDenies(ctx, aID, limits.OriginControlPlane); len(d) != 0 {
		t.Fatalf("deny lifted: %+v", d)
	}
	if err := ent.ApplyControlPlane(ctx, aID, limits.Limits{limits.OrgsPerUser: 1}, nil, call); !errors.Is(err, limits.ErrInvalid) {
		t.Fatalf("a per-person key is not per organization: %v", err)
	}

	// A taken slug creates nothing.
	if _, err := provision(slugA, &tenantapp.ProvisionedEntitlements{Limits: limits.Limits{limits.Seats: 1}, Reason: "dup"}); err == nil {
		t.Fatal("duplicate slug must be refused")
	}
	var n int
	if err := pg.QueryRow(`SELECT count(*) FROM tenants WHERE slug = $1`, slugA).Scan(&n); err != nil || n != 1 {
		t.Fatalf("duplicate created: %d %v", n, err)
	}
}
