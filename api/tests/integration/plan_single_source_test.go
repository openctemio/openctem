package integration

// One source for an organization's plan (docs/architecture/plans-and-limits.md):
// the membership list (the sidebar organization card), the organization
// itself, Settings > Plan & usage, the console and limit enforcement all
// read tenant_plans, a missing row being plan.Unassigned. Covers the
// organization bootstrap-admin creates, a self-service Free organization and
// one an administrator moved to Enterprise.
//
// Requires DATABASE_URL pointing at a fully migrated database.

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/openctemio/openctem/api/internal/adminbootstrap"
	authapp "github.com/openctemio/openctem/api/internal/app/auth"
	"github.com/openctemio/openctem/api/internal/app/entitlement"
	tenantapp "github.com/openctemio/openctem/api/internal/app/tenant"
	"github.com/openctemio/openctem/api/internal/config"
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/admin"
	"github.com/openctemio/openctem/api/pkg/domain/plan"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/validator"
)

func TestOrganizationPlanHasOneSource(t *testing.T) {
	db := openConsoleDB(t)
	ctx := context.Background()
	log := logger.NewNop()
	// The built-in defaults apply: Free is capped (5 seats), Enterprise is not.
	if _, err := db.Exec(`DELETE FROM platform_settings WHERE key = $1`, plan.SettingKey); err != nil {
		t.Fatal(err)
	}
	ent := entitlement.NewService(postgres.NewPlanRepository(db), nil, nil, nil, log)
	tenantRepo := postgres.NewTenantRepository(db)
	users := handler.NewUserHandler(nil, tenantapp.NewTenantService(tenantRepo, log), nil, validator.New(), log)
	console := postgres.NewAdminOrganizationRepository(db)

	userID := func(email string) shared.ID {
		t.Helper()
		var id string
		if err := db.QueryRow(`SELECT id FROM users WHERE email = $1`, email).Scan(&id); err != nil {
			t.Fatalf("user %s: %v", email, err)
		}
		return shared.MustIDFromString(id)
	}

	// The organization bootstrap-admin creates on a fresh install.
	o := orgBootOptions(t, db)
	if err := adminbootstrap.Run(ctx, db.DB, o, &bytes.Buffer{}); err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	var bootID string
	if err := db.QueryRow(`SELECT id FROM tenants WHERE slug = $1`, o.OrgSlug).Scan(&bootID); err != nil {
		t.Fatal(err)
	}

	// Self-service organizations start on Free.
	authSvc := orgAuthService(db, config.TenantCreationSelfService)
	selfService := func(name string) (shared.ID, shared.ID) {
		t.Helper()
		email, refresh := orgSelfServiceUser(t, db, authSvc)
		res, err := authSvc.CreateFirstTeam(ctx, authapp.CreateFirstTeamInput{RefreshToken: refresh, TeamName: name, TeamSlug: "plan-" + uuid.NewString()[:8]})
		if err != nil {
			t.Fatalf("create first team: %v", err)
		}
		tid := shared.MustIDFromString(res.Tenant.TenantID)
		t.Cleanup(func() { _, _ = db.Exec(`DELETE FROM tenants WHERE id = $1`, tid.String()) })
		return tid, userID(email)
	}
	freeID, freeOwner := selfService("Free Org")
	entID, entOwner := selfService("Sales Org")

	// An administrator moves the second one to Enterprise (sales).
	actor, err := admin.NewAdminUser("ops-"+entID.String()[:8]+"@example.test", "Ops", admin.AdminRoleOpsAdmin, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := ent.ChangeTenantPlan(ctx, actor, entID, plan.Enterprise, "", ""); err != nil {
		t.Fatalf("change plan: %v", err)
	}

	cases := []struct {
		name    string
		tenant  shared.ID
		owner   shared.ID
		want    plan.Plan
		limited bool // Free's seat cap is enforced
	}{
		{"bootstrap organization", shared.MustIDFromString(bootID), userID(o.OrgOwnerEmail), plan.Unassigned, false},
		{"self-service Free organization", freeID, freeOwner, plan.Free, true},
		{"organization moved to Enterprise", entID, entOwner, plan.Enterprise, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Sidebar: GET /users/me/tenants (and the session bootstrap).
			list, err := users.MyTenantsResponse(ctx, tc.owner)
			if err != nil {
				t.Fatal(err)
			}
			// Each owner sees their own organization only: the plan lookup is
			// keyed by the listed organization, never another tenant's row.
			if len(list) != 1 || list[0].ID != tc.tenant.String() {
				t.Fatalf("membership list of the owner: %+v", list)
			}
			sidebar := list[0].Plan
			// Settings > Plan & usage: GET /organization/plan.
			sum, err := ent.Effective(ctx, tc.tenant)
			if err != nil {
				t.Fatal(err)
			}
			// GET /tenants/{id}.
			org, err := tenantRepo.GetByID(ctx, tc.tenant)
			if err != nil {
				t.Fatal(err)
			}
			// Console > Organizations.
			row, err := console.GetOrganization(ctx, tc.tenant)
			if err != nil {
				t.Fatal(err)
			}
			if sidebar != string(tc.want) || sum.Plan != tc.want || org.Plan() != tc.want || row.Plan != string(tc.want) {
				t.Fatalf("plans disagree: sidebar %q, plan & usage %q, organization %q, console %q; want %q",
					sidebar, sum.Plan, org.Plan(), row.Plan, tc.want)
			}

			// Enforcement reads the same plan: the owner holds one seat, so
			// five more exceed Free's five seats and pass elsewhere.
			err = ent.Check(ctx, tc.tenant, plan.Seats, 5)
			var lim *plan.ErrLimitReached
			if tc.limited {
				if !errors.As(err, &lim) || lim.Key != plan.Seats || lim.Limit != 5 {
					t.Fatalf("Free seat cap not enforced: %v", err)
				}
			} else if err != nil {
				t.Fatalf("%s plan refused seats: %v", tc.want, err)
			}
		})
	}

	// The bootstrap organization has no stored plan (plan.Unassigned); the
	// self-service one has its Free row, written with the organization.
	var n int
	if err := db.QueryRow(`SELECT count(*) FROM tenant_plans WHERE tenant_id = $1`, bootID).Scan(&n); err != nil || n != 0 {
		t.Fatalf("bootstrap organization stored plan rows: %d %v", n, err)
	}
	if err := db.QueryRow(`SELECT count(*) FROM tenant_plans WHERE tenant_id = $1 AND plan = 'free'`, freeID.String()).Scan(&n); err != nil || n != 1 {
		t.Fatalf("self-service organization Free row: %d %v", n, err)
	}
}
