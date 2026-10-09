package routes

// Service accounts against a migrated database: an organization-owned
// identity that starts with no role, can hold custom roles, can never be an
// owner or administrator nor hold full data access (service and schema), never
// gets a password, belongs to one organization only, and takes its API keys
// with it when deleted.

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/accesscontrol"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	roledom "github.com/openctemio/openctem/api/pkg/domain/role"
	"github.com/openctemio/openctem/api/pkg/domain/serviceaccount"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

func TestServiceAccounts(t *testing.T) {
	h := newGRBHarness(t) // tenants, owner, admin, custom roles, team
	ctx := context.Background()
	db := &postgres.DB{DB: h.db}
	repo := postgres.NewServiceAccountRepository(db)
	svc := accesscontrol.NewServiceAccountService(repo, nil, logger.NewNop())
	roleSvc := accesscontrol.NewRoleService(h.roles, postgres.NewPermissionRepository(db), logger.NewNop())
	roleSvc.SetServiceAccountReader(repo)
	h.groups.SetRoleBindings(postgres.NewGroupRoleBindingRepository(db), roleSvc)

	a, err := svc.Create(ctx, accesscontrol.CreateServiceAccountInput{Name: "SIEM export", Description: "ships findings"}, h.actx(h.owner))
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if a.OwnerID == nil || *a.OwnerID != h.owner || a.Status != "active" {
		t.Fatalf("created: %+v", a)
	}
	if p := h.perms(a.ID); len(p) != 0 {
		t.Fatalf("a new service account holds permissions: %v", p)
	}

	// A custom role is fine; owner, admin and full data are not, through the
	// service and through the schema.
	assign := func(roleID string) error {
		return roleSvc.AssignRole(ctx, accesscontrol.AssignRoleInput{TenantID: h.tenant.String(), UserID: a.ID.String(), RoleID: roleID}, h.owner.String(), h.actx(h.owner))
	}
	if err := assign(h.analyst.String()); err != nil {
		t.Fatalf("custom role: %v", err)
	}
	if !slices.Contains(h.perms(a.ID), "findings:verify") {
		t.Fatal("the service account lacks its custom role")
	}
	for _, r := range []string{roledom.OwnerRoleID.String(), roledom.AdminRoleID.String(), h.fullData.String()} {
		if err := assign(r); !errors.Is(err, shared.ErrForbidden) {
			t.Errorf("assign %s to a service account: %v", r, err)
		}
		if _, err := h.db.Exec(`INSERT INTO user_roles (user_id, tenant_id, role_id) VALUES ($1, $2, $3)`, a.ID.String(), h.tenant.String(), r); err == nil {
			t.Errorf("the schema let a service account hold %s", r)
		}
	}
	// Nor full data through a team.
	if err := h.groups.BindRole(ctx, h.team.String(), h.fullData.String(), h.actx(h.owner)); err != nil {
		t.Fatal(err)
	}
	if err := h.addMember(h.owner, a.ID); !errors.Is(err, accesscontrol.ErrExternalRoleCeiling) {
		t.Fatalf("service account joins a full-data team: %v", err)
	}

	// No password, no other organization, no owner or admin label.
	if _, err := h.db.Exec(`UPDATE users SET password_hash = 'x' WHERE id = $1`, a.ID.String()); err == nil {
		t.Error("a service account got a password")
	}
	if _, err := h.db.Exec(`INSERT INTO tenant_members (user_id, tenant_id, role) VALUES ($1, $2, 'viewer')`, a.ID.String(), h.other.String()); err == nil {
		t.Error("a service account joined another organization")
	}
	if _, err := h.db.Exec(`UPDATE tenant_members SET role = 'admin' WHERE user_id = $1 AND tenant_id = $2`, a.ID.String(), h.tenant.String()); err == nil {
		t.Error("a service account became an administrator member")
	}

	// Another organization cannot see or delete it.
	otherActx := h.actx(h.owner)
	otherActx.TenantID = h.other.String()
	if list, err := svc.List(ctx, h.other.String()); err != nil || len(list) != 0 {
		t.Fatalf("listed in another organization: %v %v", list, err)
	}
	if err := svc.Delete(ctx, a.ID.String(), otherActx); !errors.Is(err, serviceaccount.ErrNotFound) {
		t.Fatalf("deleted from another organization: %v", err)
	}

	// Deleting it takes its API keys and roles.
	if _, err := h.db.Exec(`INSERT INTO api_keys (id, tenant_id, user_id, name, key_hash, key_prefix, status) VALUES ($1, $2, $3, 'k', $4, 'oct_test', 'active')`,
		shared.NewID().String(), h.tenant.String(), a.ID.String(), "hash-"+a.ID.String()); err != nil {
		t.Fatalf("seed key: %v", err)
	}
	if list, _ := svc.List(ctx, h.tenant.String()); len(list) != 1 || list[0].APIKeys != 1 {
		t.Fatalf("list: %+v", list)
	}
	if err := svc.Delete(ctx, a.ID.String(), h.actx(h.owner)); err != nil {
		t.Fatal(err)
	}
	var keys int
	_ = h.db.QueryRow(`SELECT COUNT(*) FROM api_keys WHERE user_id = $1`, a.ID.String()).Scan(&keys)
	if keys != 0 || len(h.perms(a.ID)) != 0 {
		t.Fatalf("after delete: %d keys, permissions %v", keys, h.perms(a.ID))
	}
}
