package tenant_test

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	tenantapp "github.com/openctemio/openctem/api/internal/app/tenant"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

type driftStepUp struct{ err error }

func (g driftStepUp) RequireRecentAuth(context.Context, string) error { return g.err }

type driftOrg struct {
	e                       *firstOwnerEnv
	org                     string
	owner, drift, admin, mb string // user ids
	driftMembership         string
}

// newDriftOrg builds an organization with the real owner, an admin, a member
// and a co-owner planted the old way: an owner role row on a member whose
// membership label is admin.
func newDriftOrg(t *testing.T) *driftOrg {
	t.Helper()
	e := newFirstOwnerEnv(t)
	o := &driftOrg{e: e, org: e.org()}
	add := func(role string) (string, string) {
		uid, mid := uuid.NewString(), uuid.NewString()
		if _, err := e.db.Exec(`INSERT INTO users (id, email) VALUES ($1, $2)`, uid, "drift-"+uid[:8]+"@it.test"); err != nil {
			t.Fatal(err)
		}
		if _, err := e.db.Exec(`INSERT INTO tenant_members (id, user_id, tenant_id, role, status, joined_at) VALUES ($1, $2, $3, $4, 'active', now())`, mid, uid, o.org, role); err != nil {
			t.Fatal(err)
		}
		return uid, mid
	}
	o.owner, _ = add("owner")
	o.admin, _ = add("admin")
	o.mb, _ = add("member")
	o.drift, o.driftMembership = add("admin")

	admin := testdb.OpenAdmin(t)
	tx, err := admin.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(`SET LOCAL session_replication_role = replica`); err != nil {
		_ = tx.Rollback()
		t.Skipf("cannot bypass triggers (needs a superuser): %v", err)
	}
	if _, err := tx.Exec(`INSERT INTO user_roles (user_id, tenant_id, role_id) VALUES ($1, $2, '00000000-0000-0000-0000-000000000001') ON CONFLICT DO NOTHING`, o.drift, o.org); err != nil {
		_ = tx.Rollback()
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	var eff string
	if err := e.db.QueryRow(`SELECT role FROM v_user_effective_role WHERE user_id=$1 AND tenant_id=$2`, o.drift, o.org).Scan(&eff); err != nil || eff != "owner" {
		t.Fatalf("planted co-owner effective role = %q (%v), want owner", eff, err)
	}
	return o
}

func (o *driftOrg) svc(gate shared.RecentAuthGate) *tenantapp.TenantService {
	audit := auditapp.NewAuditService(postgres.NewAuditRepository(o.e.pg), o.e.log)
	s := tenantapp.NewTenantService(postgres.NewTenantRepository(o.e.pg), o.e.log, tenantapp.WithTenantAuditService(audit))
	s.SetStepUpGate(gate)
	return s
}

func (o *driftOrg) actx(actor string) auditapp.AuditContext {
	return auditapp.AuditContext{TenantID: o.org, ActorID: actor, ActorEmail: "actor@it.test"}
}

func (o *driftOrg) state() (label, effective string, ownerRows int) {
	_ = o.e.db.QueryRow(`SELECT role FROM tenant_members WHERE user_id=$1 AND tenant_id=$2`, o.drift, o.org).Scan(&label)
	_ = o.e.db.QueryRow(`SELECT role FROM v_user_effective_role WHERE user_id=$1 AND tenant_id=$2`, o.drift, o.org).Scan(&effective)
	_ = o.e.db.QueryRow(`SELECT count(*) FROM user_roles WHERE user_id=$1 AND tenant_id=$2 AND role_id='00000000-0000-0000-0000-000000000001'`, o.drift, o.org).Scan(&ownerRows)
	return
}

func (o *driftOrg) auditCount() int {
	return o.e.count(`SELECT count(*) FROM audit_logs WHERE tenant_id=$1 AND action='owner_role_drift_removed' AND severity='critical'`, o.org)
}

func TestUpdateMemberRole_OwnerRemovesDriftedCoOwner(t *testing.T) {
	o := newDriftOrg(t)
	m, err := o.svc(driftStepUp{}).UpdateMemberRole(context.Background(), o.driftMembership, tenantapp.UpdateMemberRoleInput{Role: "viewer"}, o.actx(o.owner))
	if err != nil {
		t.Fatalf("owner removing drifted co-owner: %v", err)
	}
	if m.Role().String() != "viewer" {
		t.Fatalf("returned role = %s", m.Role())
	}
	label, eff, rows := o.state()
	if label != "viewer" || eff != "viewer" || rows != 0 {
		t.Fatalf("after removal label=%q effective=%q ownerRows=%d, want viewer/viewer/0", label, eff, rows)
	}
	if n := o.auditCount(); n != 1 {
		t.Fatalf("owner_role_drift_removed critical audit entries = %d, want 1", n)
	}
}

func TestUpdateMemberRole_DriftRemovalRefusals(t *testing.T) {
	cases := []struct {
		name  string
		actor func(o *driftOrg) string
		gate  shared.RecentAuthGate
		want  error
	}{
		{"admin", func(o *driftOrg) string { return o.admin }, driftStepUp{}, tenantapp.ErrOwnerRoleDriftRemoval},
		{"member", func(o *driftOrg) string { return o.mb }, driftStepUp{}, tenantapp.ErrOwnerRoleDriftRemoval},
		{"the co-owner itself", func(o *driftOrg) string { return o.drift }, driftStepUp{}, tenantapp.ErrOwnerRoleDriftRemoval},
		{"system path without an actor", func(o *driftOrg) string { return "" }, driftStepUp{}, tenantapp.ErrOwnerRoleDriftRemoval},
		{"owner without step-up", func(o *driftOrg) string { return o.owner }, driftStepUp{err: shared.ErrForbidden}, shared.ErrForbidden},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			o := newDriftOrg(t)
			_, err := o.svc(c.gate).UpdateMemberRole(context.Background(), o.driftMembership, tenantapp.UpdateMemberRoleInput{Role: "viewer"}, o.actx(c.actor(o)))
			if !errors.Is(err, c.want) {
				t.Fatalf("err = %v, want %v", err, c.want)
			}
			label, eff, rows := o.state()
			if label != "admin" || eff != "owner" || rows != 1 {
				t.Fatalf("refused change altered the member: label=%q effective=%q ownerRows=%d", label, eff, rows)
			}
			if n := o.auditCount(); n != 0 {
				t.Fatalf("audit entries = %d, want 0", n)
			}
		})
	}
}

// The real owner (label owner) stays untouchable by a role change.
func TestUpdateMemberRole_RealOwnerStillRefused(t *testing.T) {
	o := newDriftOrg(t)
	var ownerMembership string
	if err := o.e.db.QueryRow(`SELECT id FROM tenant_members WHERE user_id=$1 AND tenant_id=$2`, o.owner, o.org).Scan(&ownerMembership); err != nil {
		t.Fatal(err)
	}
	_, err := o.svc(driftStepUp{}).UpdateMemberRole(context.Background(), ownerMembership, tenantapp.UpdateMemberRoleInput{Role: "viewer"}, o.actx(o.admin))
	if !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("err = %v, want validation refusal", err)
	}
}
