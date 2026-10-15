package integration

// Invitations for people outside the organization against a real database
// (RFC-095 §3.2, §4): any role but owner, a privileged role needs the
// inviter's step-up, Security.invitees restricts who may be invited, and an
// invitation is re-authorized as the inviter at acceptance.

import (
	"context"
	"errors"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/accesscontrol"
	"github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/internal/app/tenant"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	tenantdom "github.com/openctemio/openctem/api/pkg/domain/tenant"
	"github.com/openctemio/openctem/api/pkg/logger"
)

const (
	invAdminRole  = "00000000-0000-0000-0000-000000000002"
	invMemberRole = "00000000-0000-0000-0000-000000000003"
)

type invDomainOwners map[string]shared.ID

func (o invDomainOwners) OwnerOfDomain(_ context.Context, d string) (shared.ID, bool, error) {
	id, ok := o[d]
	return id, ok, nil
}

// invStepUp answers like the real gate: only the requester is asked.
type invStepUp struct {
	requester string
	fresh     *bool
}

var errInvStepUp = errors.New("step-up required")

func (g invStepUp) RequireRecentAuth(_ context.Context, actorID string) error {
	if actorID == "" || actorID != g.requester || *g.fresh {
		return nil
	}
	return errInvStepUp
}

func TestInvitationOutsidePolicy(t *testing.T) {
	db := setupTestDB(t)
	t.Cleanup(func() { _ = db.Close() })
	ctx := context.Background()
	pg := &postgres.DB{DB: db}
	repo := postgres.NewTenantRepository(pg)

	host := createTestTenant(t, db, "inv-host")
	other := createTestTenant(t, db, "inv-other")
	owner := createTestUser(t, db, "owner-"+shared.NewID().String()+"@host.example", "Owner")
	admin := createTestUser(t, db, "admin-"+shared.NewID().String()+"@host.example", "Admin")
	createTestMembership(t, db, host, owner, "owner")
	createTestMembership(t, db, host, admin, "admin")
	t.Cleanup(func() {
		for _, tid := range []shared.ID{host, other} {
			_, _ = db.ExecContext(ctx, `DELETE FROM audit_logs WHERE tenant_id = $1`, tid.String())
			_, _ = db.ExecContext(ctx, `DELETE FROM tenant_invitations WHERE tenant_id = $1`, tid.String())
			_, _ = db.ExecContext(ctx, `DELETE FROM user_roles WHERE tenant_id = $1`, tid.String())
			_, _ = db.ExecContext(ctx, `DELETE FROM tenant_members WHERE tenant_id = $1`, tid.String())
			_, _ = db.ExecContext(ctx, `DELETE FROM roles WHERE tenant_id = $1`, tid.String())
		}
		cleanupTestData(db, host, other)
	})

	fresh := false
	gate := invStepUp{requester: admin.String(), fresh: &fresh}
	roles := accesscontrol.NewRoleService(postgres.NewRoleRepository(pg), postgres.NewPermissionRepository(pg), logger.NewNop(),
		accesscontrol.WithRoleMembershipReader(repo))
	roles.SetStepUpGate(gate)
	svc := tenant.NewTenantService(repo, logger.NewNop())
	svc.SetRoleService(roles)
	svc.SetStepUpGate(gate)
	svc.SetAddressClassifier(tenant.NewAddressClassifier(invDomainOwners{"host.example": host},
		func(context.Context, shared.ID) (bool, error) { return true, nil }))
	adminCtx := audit.AuditContext{TenantID: host.String(), ActorID: admin.String()}

	invite := func(email string, roleIDs ...string) (*tenantdom.Invitation, error) {
		return svc.CreateInvitation(ctx, host.String(), tenant.CreateInvitationInput{Email: email, Role: "member", RoleIDs: roleIDs}, admin, adminCtx)
	}
	accept := func(inv *tenantdom.Invitation) (*tenantdom.Membership, shared.ID, error) {
		u := createTestUser(t, db, inv.Email(), "Invitee")
		m, err := svc.AcceptInvitation(ctx, inv.Token(), u, inv.Email(), audit.AuditContext{ActorID: u.String()})
		return m, u, err
	}
	holds := func(u shared.ID, roleID string) bool {
		var n int
		if err := db.QueryRowContext(ctx, `SELECT count(*) FROM user_roles WHERE tenant_id = $1 AND user_id = $2 AND role_id = $3`,
			host.String(), u.String(), roleID).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n == 1
	}

	t.Run("an outside person joins with the invited role and no imposed end", func(t *testing.T) {
		inv, err := invite("m-"+shared.NewID().String()[24:]+"@gmail.com", invMemberRole)
		if err != nil {
			t.Fatalf("invite an outside person as member: %v", err)
		}
		if inv.Access().ExpiresAt != nil {
			t.Fatalf("end of access imposed: %v", inv.Access().ExpiresAt)
		}
		m, u, err := accept(inv)
		if err != nil {
			t.Fatalf("accept: %v", err)
		}
		if !m.IsExternal() || m.Role() != tenantdom.RoleMember || m.ExpiresAt() != nil {
			t.Fatalf("external=%v role=%s expires=%v", m.IsExternal(), m.Role(), m.ExpiresAt())
		}
		if !holds(u, invMemberRole) {
			t.Fatal("the invited member role was not granted")
		}
	})

	t.Run("a privileged role for an outside person needs the inviter's step-up", func(t *testing.T) {
		fullData := shared.NewID().String()
		if _, err := db.ExecContext(ctx, `INSERT INTO roles (id, tenant_id, slug, name, is_system, hierarchy_level, has_full_data_access)
			VALUES ($1, $2, 'inv-reader', 'Reader of all', false, 10, true)`, fullData, host.String()); err != nil {
			t.Fatal(err)
		}
		email := "p-" + shared.NewID().String()[24:] + "@gmail.com"
		if _, err := invite(email, fullData); !errors.Is(err, errInvStepUp) {
			t.Fatalf("without step-up: want step-up, got %v", err)
		}
		fresh = true
		defer func() { fresh = false }()
		inv, err := invite(email, fullData)
		if err != nil {
			t.Fatalf("after step-up: %v", err)
		}
		if _, u, err := accept(inv); err != nil || !holds(u, fullData) {
			t.Fatalf("accept privileged outside invitation: %v", err)
		}
		// An insider needs no step-up for the same role.
		fresh = false
		if _, err := invite("in-"+shared.NewID().String()[24:]+"@host.example", fullData); err != nil {
			t.Fatalf("insider with a full-data role: %v", err)
		}
	})

	t.Run("verified_domains admits only the organization's own domains", func(t *testing.T) {
		if _, err := db.ExecContext(ctx, `UPDATE tenants SET settings = jsonb_set(COALESCE(settings, '{}'::jsonb), '{security}',
			COALESCE(settings->'security', '{}'::jsonb) || '{"invitees":"verified_domains"}'::jsonb) WHERE id = $1`, host.String()); err != nil {
			t.Fatal(err)
		}
		defer func() {
			_, _ = db.ExecContext(ctx, `UPDATE tenants SET settings = settings #- '{security,invitees}' WHERE id = $1`, host.String())
		}()
		if _, err := invite("v-"+shared.NewID().String()[24:]+"@gmail.com", invMemberRole); !errors.Is(err, tenant.ErrInviteeNotOnVerifiedDomain) {
			t.Fatalf("outside address: want ErrInviteeNotOnVerifiedDomain, got %v", err)
		}
		if _, err := invite("v-"+shared.NewID().String()[24:]+"@host.example", invMemberRole); err != nil {
			t.Fatalf("own domain: %v", err)
		}
	})

	t.Run("a demoted inviter's invitation no longer grants anything", func(t *testing.T) {
		inv, err := invite("late-"+shared.NewID().String()[24:]+"@gmail.com", invMemberRole)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := db.ExecContext(ctx, `UPDATE tenant_members SET role = 'member' WHERE tenant_id = $1 AND user_id = $2`, host.String(), admin.String()); err != nil {
			t.Fatal(err)
		}
		if _, err := db.ExecContext(ctx, `DELETE FROM user_roles WHERE tenant_id = $1 AND user_id = $2 AND role_id = $3`, host.String(), admin.String(), invAdminRole); err != nil {
			t.Fatal(err)
		}
		_, u, err := accept(inv)
		if !errors.Is(err, tenant.ErrInvitationNoLongerValid) {
			t.Fatalf("want ErrInvitationNoLongerValid, got %v", err)
		}
		var n int
		_ = db.QueryRowContext(ctx, `SELECT count(*) FROM tenant_members WHERE tenant_id = $1 AND user_id = $2`, host.String(), u.String()).Scan(&n)
		if n != 0 || holds(u, invMemberRole) {
			t.Fatal("the refused acceptance stored a membership or a role")
		}
	})

	t.Run("a role of another organization is refused", func(t *testing.T) {
		foreign := shared.NewID().String()
		if _, err := db.ExecContext(ctx, `INSERT INTO roles (id, tenant_id, slug, name, is_system, hierarchy_level)
			VALUES ($1, $2, 'inv-foreign', 'Foreign', false, 10)`, foreign, other.String()); err != nil {
			t.Fatal(err)
		}
		_, err := svc.CreateInvitation(ctx, host.String(), tenant.CreateInvitationInput{
			Email: "f-" + shared.NewID().String()[24:] + "@gmail.com", Role: "member", RoleIDs: []string{foreign},
		}, owner, audit.AuditContext{TenantID: host.String(), ActorID: owner.String()})
		if err == nil {
			t.Fatal("an invitation with another organization's role was created")
		}
	})
}
