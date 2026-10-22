package routes

// Service-account follow-ups against a migrated database: a role a service
// account holds cannot be turned into a full-data role (service and schema),
// and a member who loses service_accounts:manage through a role change loses
// the keys they minted.

import (
	"context"
	"errors"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/accesscontrol"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

func (h *grbHarness) serviceAccount() shared.ID {
	id := shared.NewID()
	h.exec(`INSERT INTO users (id, email, name, kind, service_tenant_id, service_owner_id)
		VALUES ($1, $2, 'svc', 'service', $3, $4)`,
		id.String(), "svc-"+id.String()+"@service-accounts.invalid", h.tenant.String(), h.owner.String())
	h.exec(`INSERT INTO tenant_members (user_id, tenant_id, role) VALUES ($1, $2, 'member')`, id.String(), h.tenant.String())
	h.exec(`DELETE FROM user_roles WHERE user_id = $1 AND tenant_id = $2`, id.String(), h.tenant.String())
	h.t.Cleanup(func() { _, _ = h.db.Exec(`DELETE FROM users WHERE id = $1`, id.String()) })
	return id
}

func TestServiceAccountRole_FullDataRefusedWhileAServiceAccountHoldsIt(t *testing.T) {
	h := newGRBHarness(t)
	ctx := context.Background()
	db := &postgres.DB{DB: h.db}
	roleSvc := accesscontrol.NewRoleService(h.roles, postgres.NewPermissionRepository(db), logger.NewNop())
	roleSvc.SetServiceAccountReader(postgres.NewServiceAccountRepository(db))
	on := true
	update := func(role shared.ID) error {
		_, err := roleSvc.UpdateRole(ctx, h.tenant.String(), role.String(), accesscontrol.UpdateRoleInput{HasFullDataAccess: &on}, h.actx(h.owner))
		return err
	}

	direct := h.customRole(h.tenant, "sa-direct", false, "findings:read")
	viaTeam := h.customRole(h.tenant, "sa-team", false, "findings:read")
	free := h.customRole(h.tenant, "sa-free", false, "findings:read")
	sa1, sa2 := h.serviceAccount(), h.serviceAccount()
	h.exec(`INSERT INTO user_roles (user_id, tenant_id, role_id) VALUES ($1, $2, $3)`, sa1.String(), h.tenant.String(), direct.String())
	h.exec(`INSERT INTO group_members (group_id, user_id, role) VALUES ($1, $2, 'member')`, h.team.String(), sa2.String())
	h.exec(`INSERT INTO group_role_bindings (tenant_id, group_id, role_id) VALUES ($1, $2, $3)`, h.tenant.String(), h.team.String(), viaTeam.String())

	for name, role := range map[string]shared.ID{"direct": direct, "team": viaTeam} {
		if err := update(role); !errors.Is(err, accesscontrol.ErrServiceAccountRoleCeiling) {
			t.Errorf("%s holder: UpdateRole = %v, want the service-account ceiling", name, err)
		}
		// The schema refuses it too, for any writer.
		if _, err := h.db.Exec(`UPDATE roles SET has_full_data_access = true WHERE id = $1`, role.String()); err == nil {
			t.Errorf("%s holder: the schema let the role get full data access", name)
		}
		var fd bool
		_ = h.db.QueryRow(`SELECT has_full_data_access FROM roles WHERE id = $1`, role.String()).Scan(&fd)
		if fd {
			t.Errorf("%s holder: the role got full data access", name)
		}
	}
	// An inactive team still counts: re-activating it would hand the service
	// account the full-data role.
	h.exec(`UPDATE groups SET is_active = false WHERE id = $1`, h.team.String())
	if err := update(viaTeam); !errors.Is(err, accesscontrol.ErrServiceAccountRoleCeiling) {
		t.Errorf("inactive team holder: UpdateRole = %v, want the service-account ceiling", err)
	}
	if _, err := h.db.Exec(`UPDATE roles SET has_full_data_access = true WHERE id = $1`, viaTeam.String()); err == nil {
		t.Error("inactive team holder: the schema let the role get full data access")
	}
	// Control: a role no service account holds may become full-data.
	if err := update(free); err != nil {
		t.Fatalf("a role without service-account holders: %v", err)
	}
}

func TestServiceAccountKeys_RevokedWhenAMemberLosesManageThroughARole(t *testing.T) {
	h := newGRBHarness(t)
	ctx := context.Background()
	db := &postgres.DB{DB: h.db}
	roleSvc := accesscontrol.NewRoleService(h.roles, postgres.NewPermissionRepository(db), logger.NewNop())
	roleSvc.SetServiceKeyRevoker(postgres.NewMemberLifecycleRepository(db))
	manager := h.customRole(h.tenant, "sa-manager", false, "service_accounts:manage")
	manager2 := h.customRole(h.tenant, "sa-manager-2", false, "service_accounts:manage")
	sa := h.serviceAccount()
	key := func(creator shared.ID) string {
		id := shared.NewID().String()
		h.exec(`INSERT INTO api_keys (id, tenant_id, user_id, name, key_hash, key_prefix, status, created_by)
			VALUES ($1, $2, $3, $4, $5, 'oct_svc', 'active', $6)`, id, h.tenant.String(), sa.String(), "k-"+id, "hash-"+id, creator.String())
		return id
	}
	status := func(id string) string {
		var s string
		_ = h.db.QueryRow(`SELECT status FROM api_keys WHERE id = $1`, id).Scan(&s)
		return s
	}
	grant := func(user shared.ID, roles ...shared.ID) {
		ids := make([]string, len(roles))
		for i, r := range roles {
			ids[i] = r.String()
		}
		if err := roleSvc.SetUserRoles(ctx, accesscontrol.SetUserRolesInput{TenantID: h.tenant.String(), UserID: user.String(), RoleIDs: ids}, h.owner.String(), h.actx(h.owner)); err != nil {
			t.Fatalf("set roles: %v", err)
		}
	}

	// RemoveRole of the only role holding the permission.
	grant(h.member, manager)
	mine, others := key(h.member), key(h.owner)
	if err := roleSvc.RemoveRole(ctx, h.tenant.String(), h.member.String(), manager.String(), h.actx(h.owner)); err != nil {
		t.Fatal(err)
	}
	if got := status(mine); got != "revoked" {
		t.Errorf("the key a member minted after losing manage is %q", got)
	}
	if got := status(others); got != "active" {
		t.Errorf("another person's key is %q", got)
	}

	// Replacing the role set with one that no longer holds it.
	grant(h.member, manager)
	mine2 := key(h.member)
	grant(h.member, h.analyst)
	if got := status(mine2); got != "revoked" {
		t.Errorf("SetUserRoles dropping manage left the key %q", got)
	}

	// Still holding it through another role keeps the key.
	grant(h.member, manager, manager2)
	kept := key(h.member)
	if err := roleSvc.RemoveRole(ctx, h.tenant.String(), h.member.String(), manager.String(), h.actx(h.owner)); err != nil {
		t.Fatal(err)
	}
	if got := status(kept); got != "active" {
		t.Errorf("a member who still holds manage lost a key: %q", got)
	}
}
