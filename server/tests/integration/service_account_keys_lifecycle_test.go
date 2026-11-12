package integration

// The service-account keys a person minted do not outlive their role: they
// are revoked when the person is offboarded or demoted from administrator,
// reported before the fact in the access report, counted in the result, and
// never touch another person's keys or another organization's accounts.

import (
	"context"
	"database/sql"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/tenant"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// seedServiceAccountKey inserts a service account of tenantID (when account is
// nil, a new one) and an active key minted for it by creator.
func (f *lifecycleFixture) seedServiceAccountKey(t *testing.T, tenantID shared.ID, account *shared.ID, creator shared.ID) (shared.ID, shared.ID) {
	t.Helper()
	acc := shared.NewID()
	if account != nil {
		acc = *account
	} else {
		if _, err := f.db.Exec(`INSERT INTO users (id, email, name, kind, service_tenant_id, service_owner_id)
			VALUES ($1, $2, 'svc', 'service', $3, $4)`,
			acc.String(), "svc-"+acc.String()+"@service-accounts.invalid", tenantID.String(), f.ownerID.String()); err != nil {
			t.Fatalf("seed service account: %v", err)
		}
		t.Cleanup(func() { _, _ = f.db.Exec(`DELETE FROM users WHERE id = $1`, acc.String()) })
	}
	key := shared.NewID()
	if _, err := f.db.Exec(`INSERT INTO api_keys (id, tenant_id, user_id, name, key_hash, key_prefix, status, created_by)
		VALUES ($1, $2, $3, $4, $5, 'oct_svc', 'active', $6)`,
		key.String(), tenantID.String(), acc.String(), "k-"+key.String(), "hash-"+key.String(), creator.String()); err != nil {
		t.Fatalf("seed service account key: %v", err)
	}
	return acc, key
}

func (f *lifecycleFixture) keyStatus(t *testing.T, key shared.ID) string {
	return f.str(t, `SELECT status FROM api_keys WHERE id = $1`, key.String())
}

func TestServiceAccountKeys_OffboardRevokesTheKeysThePersonMinted(t *testing.T) {
	f := newLifecycleFixture(t)
	ctx := context.Background()
	acc, mine := f.seedServiceAccountKey(t, f.tenantID, nil, f.memberID)
	_, owners := f.seedServiceAccountKey(t, f.tenantID, &acc, f.ownerID)  // someone else's key, same account
	_, foreign := f.seedServiceAccountKey(t, f.otherTID, nil, f.memberID) // another organization's account
	pdb := &postgres.DB{DB: f.db}
	lc := postgres.NewMemberLifecycleRepository(pdb)

	// The access report names the keys before anything happens.
	m, err := f.repo.GetMembership(ctx, f.memberID, f.tenantID)
	if err != nil {
		t.Fatal(err)
	}
	rep, err := lc.AccessReport(ctx, m)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.ServiceAccountKeys) != 1 || rep.ServiceAccountKeys[0].ID != mine.String() {
		t.Fatalf("access report service account keys: %+v", rep.ServiceAccountKeys)
	}

	peer := f.peerID.String()
	res, err := f.svc.OffboardMember(ctx, f.mshipID.String(), tenant.OffboardMemberInput{
		SchedulesTo: peer, FindingsTo: peer, AssetsTo: peer,
	}, f.ownerCtx())
	if err != nil {
		t.Fatalf("offboard: %v", err)
	}
	if res.RevokedServiceAccountKeys != 1 {
		t.Errorf("revoked service account keys = %d, want 1", res.RevokedServiceAccountKeys)
	}
	if got := f.keyStatus(t, mine); got != "revoked" {
		t.Errorf("the offboarded person's service-account key is %q", got)
	}
	if got := f.str(t, `SELECT revoked_by::text FROM api_keys WHERE id = $1`, mine.String()); got != f.ownerID.String() {
		t.Errorf("revoked_by = %q, want the acting owner", got)
	}
	if got := f.keyStatus(t, owners); got != "active" {
		t.Errorf("another person's key on the same account is %q", got)
	}
	if got := f.keyStatus(t, foreign); got != "active" {
		t.Errorf("another organization's key is %q", got)
	}
}

func TestServiceAccountKeys_DemotedAdministratorLosesTheKeysTheyMinted(t *testing.T) {
	f := newLifecycleFixture(t)
	ctx := context.Background()
	tid, uid := f.tenantID.String(), f.memberID.String()
	if _, err := f.db.Exec(`UPDATE tenant_members SET role = 'admin' WHERE tenant_id = $1 AND user_id = $2`, tid, uid); err != nil {
		t.Fatal(err)
	}
	_, mine := f.seedServiceAccountKey(t, f.tenantID, nil, f.memberID)
	_, owners := f.seedServiceAccountKey(t, f.tenantID, nil, f.ownerID)
	_, foreign := f.seedServiceAccountKey(t, f.otherTID, nil, f.memberID)

	// A change that does not demote from administrator revokes nothing.
	if _, err := f.svc.UpdateMemberRole(ctx, f.mshipID.String(), tenant.UpdateMemberRoleInput{Role: "admin"}, f.ownerCtx()); err != nil {
		t.Fatalf("keep admin: %v", err)
	}
	if got := f.keyStatus(t, mine); got != "active" {
		t.Fatalf("a no-op role change revoked the key: %q", got)
	}

	if _, err := f.svc.UpdateMemberRole(ctx, f.mshipID.String(), tenant.UpdateMemberRoleInput{Role: "viewer"}, f.ownerCtx()); err != nil {
		t.Fatalf("demote: %v", err)
	}
	if got := f.keyStatus(t, mine); got != "revoked" {
		t.Errorf("a demoted administrator's service-account key is %q", got)
	}
	if got := f.keyStatus(t, owners); got != "active" {
		t.Errorf("another person's key is %q", got)
	}
	if got := f.keyStatus(t, foreign); got != "active" {
		t.Errorf("another organization's key is %q", got)
	}
}

func TestServiceAccountKeys_SuspendRevokesTheKeysThePersonMinted(t *testing.T) {
	f := newLifecycleFixture(t)
	ctx := context.Background()
	_, mine := f.seedServiceAccountKey(t, f.tenantID, nil, f.memberID)
	_, owners := f.seedServiceAccountKey(t, f.tenantID, nil, f.ownerID)
	_, foreign := f.seedServiceAccountKey(t, f.otherTID, nil, f.memberID)

	if err := f.svc.SuspendMember(ctx, f.mshipID.String(), f.ownerCtx()); err != nil {
		t.Fatalf("suspend: %v", err)
	}
	if got := f.keyStatus(t, mine); got != "revoked" {
		t.Errorf("a suspended person's service-account key is %q", got)
	}
	if got := f.keyStatus(t, owners); got != "active" {
		t.Errorf("another person's key is %q", got)
	}
	if got := f.keyStatus(t, foreign); got != "active" {
		t.Errorf("another organization's key is %q", got)
	}
	// Re-enabling does not bring a revoked key back.
	if err := f.svc.ReactivateMember(ctx, f.mshipID.String(), f.ownerCtx()); err != nil {
		t.Fatalf("reactivate: %v", err)
	}
	if got := f.keyStatus(t, mine); got != "revoked" {
		t.Errorf("a reactivated person's service-account key is %q", got)
	}
}

// The revoke is part of the role change: when it cannot be stored, the role
// is not changed either, so the demotion never leaves the keys live.
func TestServiceAccountKeys_DemotionRollsBackWhenTheRevokeFails(t *testing.T) {
	f := newLifecycleFixture(t)
	ctx := context.Background()
	tid, uid := f.tenantID.String(), f.memberID.String()
	if _, err := f.db.Exec(`UPDATE tenant_members SET role = 'admin' WHERE tenant_id = $1 AND user_id = $2`, tid, uid); err != nil {
		t.Fatal(err)
	}
	_, mine := f.seedServiceAccountKey(t, f.tenantID, nil, f.memberID)
	// Creating a trigger is DDL, which the least-privileged app role cannot do:
	// the injection goes through the migrator connection, the code under test
	// stays on the app role. The trigger is scoped to this one key and uniquely
	// named so parallel tests on the shared database are unaffected.
	mdb, err := sql.Open("postgres", testdb.MigratorURL())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = mdb.Close() })
	fn := "test_refuse_revoke_" + strings.ReplaceAll(mine.String(), "-", "")[:12]
	if _, err := mdb.Exec(`CREATE FUNCTION ` + fn + `() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN IF NEW.id = '` + mine.String() + `' AND NEW.status = 'revoked' THEN RAISE EXCEPTION 'revoke refused for the test'; END IF; RETURN NEW; END; $$`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = mdb.Exec(`DROP TRIGGER IF EXISTS ` + fn + ` ON api_keys`)
		_, _ = mdb.Exec(`DROP FUNCTION IF EXISTS ` + fn + `()`)
	})
	if _, err := mdb.Exec(`CREATE TRIGGER ` + fn + ` BEFORE UPDATE ON api_keys FOR EACH ROW EXECUTE FUNCTION ` + fn + `()`); err != nil {
		t.Fatal(err)
	}

	if _, err := f.svc.UpdateMemberRole(ctx, f.mshipID.String(), tenant.UpdateMemberRoleInput{Role: "viewer"}, f.ownerCtx()); err == nil {
		t.Fatal("the demotion succeeded although the key revoke failed")
	}
	if got := f.str(t, `SELECT role FROM tenant_members WHERE tenant_id = $1 AND user_id = $2`, tid, uid); got != "admin" {
		t.Errorf("role after a failed revoke = %q, want admin (rolled back)", got)
	}
	if got := f.keyStatus(t, mine); got != "active" {
		t.Errorf("key = %q", got)
	}
}
