package integration

// The deployment region set once in the console (RFC-079): only while no
// organization exists (the system tenant does not count), never again, and
// every organization created afterwards gets it even on a replica whose
// cache has not seen it yet.

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/openctemio/openctem/api/internal/app/consolesetting"
	"github.com/openctemio/openctem/api/internal/app/deploymentregion"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/domain/admin"
	"github.com/openctemio/openctem/api/pkg/domain/tenant"
)

func TestDeploymentRegion_OnceBeforeFirstOrganization(t *testing.T) {
	const dir = "../../migrations"
	sqldb := testdb.PrivateDatabase(t, "regiononce", dir)
	db := &postgres.DB{DB: sqldb}
	ctx := context.Background()
	settings := postgres.NewPlatformSettingRepository(db)
	tenants := postgres.NewTenantRepository(db)
	audit := postgres.NewAuditLogRepository(db)
	admins := postgres.NewAdminRepository(db)
	actor, err := admin.NewAdminUser("region-"+uuid.NewString()[:8]+"@example.com", "Region", admin.AdminRoleSuperAdmin, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := admins.Create(ctx, actor); err != nil {
		t.Fatal(err)
	}
	svc := deploymentregion.NewService(settings, tenants, consolesetting.NewRecorder(audit, nil, "OpenCTEM", nil), "", nil)

	got, err := svc.Get(ctx)
	if err != nil || !got.Settable {
		t.Fatalf("a fresh installation (only the system tenant) can set the region: %+v %v", got, err)
	}
	if _, err := svc.Set(ctx, actor, "eu-central", "EU data residency", "203.0.113.9", "it"); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Set(ctx, actor, "us-east", "again", "", ""); !errors.Is(err, deploymentregion.ErrAlreadySet) {
		t.Fatalf("the region is immutable: %v", err)
	}

	// A replica that has not read the setting yet (no region source at all)
	// still stamps the region: the insert reads the setting itself.
	stale := postgres.NewTenantRepository(db)
	creator := createTestUser(t, sqldb, "region-owner-"+uuid.NewString()[:8]+"@example.com", "Owner")
	org, err := tenant.NewTenant("Region Org", "region-org-"+uuid.NewString()[:8], creator.String())
	if err != nil {
		t.Fatal(err)
	}
	if err := stale.Create(ctx, org); err != nil {
		t.Fatal(err)
	}
	if org.Region() != "eu-central" {
		t.Fatalf("Create: region %q, want eu-central", org.Region())
	}
	owned, err := tenant.NewTenant("Owned Org", "owned-org-"+uuid.NewString()[:8], creator.String())
	if err != nil {
		t.Fatal(err)
	}
	m, err := tenant.NewMembership(creator, owned.ID(), tenant.RoleOwner, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := stale.CreateWithOwner(ctx, owned, m); err != nil {
		t.Fatal(err)
	}
	if again, _ := stale.GetByID(ctx, owned.ID()); again.Region() != "eu-central" {
		t.Fatalf("CreateWithOwner: region %q, want eu-central", again.Region())
	}

	var critical int
	if err := sqldb.QueryRowContext(ctx, `SELECT count(*) FROM admin_audit_logs WHERE action = $1 AND admin_id = $2`,
		deploymentregion.ActionSet, actor.ID().String()).Scan(&critical); err != nil || critical != 1 {
		t.Fatalf("audit rows %d %v, want 1", critical, err)
	}
}

// Once an organization exists the region can no longer be set.
func TestDeploymentRegion_RefusedAfterFirstOrganization(t *testing.T) {
	const dir = "../../migrations"
	sqldb := testdb.PrivateDatabase(t, "regionlate", dir)
	db := &postgres.DB{DB: sqldb}
	ctx := context.Background()
	_ = createTestTenant(t, sqldb, "region-late")
	svc := deploymentregion.NewService(postgres.NewPlatformSettingRepository(db), postgres.NewTenantRepository(db),
		consolesetting.NewRecorder(nil, nil, "", nil), "", nil)
	actor, _ := admin.NewAdminUser("late@example.com", "Late", admin.AdminRoleSuperAdmin, nil)
	if got, _ := svc.Get(ctx); got.Settable {
		t.Fatal("not settable once an organization exists")
	}
	if _, err := svc.Set(ctx, actor, "eu-central", "late", "", ""); !errors.Is(err, deploymentregion.ErrOrganizationsExist) {
		t.Fatalf("err = %v", err)
	}
}
