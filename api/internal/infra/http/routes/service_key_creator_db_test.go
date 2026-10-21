package routes

// A service-account key answers to the person who minted it: it stops working
// the moment that person is no longer an active member holding
// service_accounts:manage, whatever the path that took it away. Also the grant
// triggers' role row lock, closing the "enable full data on a role" against
// "grant the role to a service account" race.

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/internal/app/apikey"
	"github.com/openctemio/openctem/api/internal/infra/controller"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/crypto"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

const saKeyPepper = "creator-pepper"

type failingHolder struct{}

func (failingHolder) HeldPermissions(context.Context, shared.ID, shared.ID) (bool, []string, error) {
	return false, nil, errors.New("permission store down")
}

type creatorFixture struct {
	h    *grbHarness
	sa   shared.ID
	keys *apikey.Service
	gate apikey.ServiceKeyGate
}

func newCreatorFixture(t *testing.T, holder func(h *grbHarness) apikey.HolderPermissions) *creatorFixture {
	t.Helper()
	h := newGRBHarness(t)
	db := &postgres.DB{DB: h.db}
	tenants := postgres.NewTenantRepository(db)
	f := &creatorFixture{h: h, sa: h.serviceAccount()}
	var hp apikey.HolderPermissions = apikey.NewHolderPermissions(tenants, harnessPerms{h})
	if holder != nil {
		hp = holder(h)
	}
	f.gate = apikey.NewServiceKeyGate(postgres.NewServiceAccountRepository(db),
		apikey.NewMembershipChecker(tenants, nil, nil), hp)
	f.keys = apikey.NewService(postgres.NewAPIKeyRepository(db), saKeyPepper, logger.NewNop())
	f.keys.SetMembershipChecker(apikey.NewMembershipChecker(tenants, nil, nil))
	f.keys.SetServiceKeyGate(f.gate)
	return f
}

// mint stores a live key of the service account created by creator and returns its raw value.
func (f *creatorFixture) mint(user, creator shared.ID) string {
	raw := "oct_" + shared.NewID().String()
	var by any
	if !creator.IsZero() {
		by = creator.String()
	}
	f.h.exec(`INSERT INTO api_keys (id, tenant_id, user_id, name, key_hash, key_prefix, status, created_by, scopes)
		VALUES ($1, $2, $3, $4, $5, 'oct_svc', 'active', $6, ARRAY['findings:read'])`,
		shared.NewID().String(), f.h.tenant.String(), user.String(), "k-"+raw, crypto.HashTokenPeppered(raw, saKeyPepper), by)
	return raw
}

func (f *creatorFixture) works(raw string) bool {
	_, err := f.keys.Authenticate(context.Background(), raw, "127.0.0.1")
	return err == nil
}

// manager is a member holding service_accounts:manage through a direct role.
func (f *creatorFixture) manager() (user, role shared.ID) {
	user = f.h.user(f.h.tenant, "internal", "")
	role = f.h.customRole(f.h.tenant, "sakeys-"+shared.NewID().String(), false, "service_accounts:manage")
	f.h.exec(`INSERT INTO user_roles (user_id, tenant_id, role_id) VALUES ($1, $2, $3)`, user.String(), f.h.tenant.String(), role.String())
	return user, role
}

// teamManager holds service_accounts:manage only through a team's role binding.
func (f *creatorFixture) teamManager() (user, team, role shared.ID) {
	user = f.h.user(f.h.tenant, "internal", "")
	team = f.h.newTeam(f.h.tenant)
	role = f.h.customRole(f.h.tenant, "sateam-"+shared.NewID().String(), false, "service_accounts:manage")
	f.h.exec(`INSERT INTO group_members (group_id, user_id, role) VALUES ($1, $2, 'member')`, team.String(), user.String())
	f.h.exec(`INSERT INTO group_role_bindings (tenant_id, group_id, role_id) VALUES ($1, $2, $3)`, f.h.tenant.String(), team.String(), role.String())
	return user, team, role
}

func TestServiceKeyCreator_StopsWorkingWhenManageIsLost(t *testing.T) {
	f := newCreatorFixture(t, nil)
	h := f.h
	tid := h.tenant.String()

	cases := []struct {
		name   string
		setup  func() (creator shared.ID, lose func())
		reason string
	}{
		{"role removed", func() (shared.ID, func()) {
			u, r := f.manager()
			return u, func() { h.exec(`DELETE FROM user_roles WHERE user_id = $1 AND role_id = $2`, u.String(), r.String()) }
		}, apikey.ReasonCreatorLostManage},
		{"role permissions edited", func() (shared.ID, func()) {
			u, r := f.manager()
			return u, func() {
				h.exec(`DELETE FROM role_permissions WHERE role_id = $1 AND permission_id = 'service_accounts:manage'`, r.String())
			}
		}, apikey.ReasonCreatorLostManage},
		{"removed from the team", func() (shared.ID, func()) {
			u, team, _ := f.teamManager()
			return u, func() {
				h.exec(`DELETE FROM group_members WHERE group_id = $1 AND user_id = $2`, team.String(), u.String())
			}
		}, apikey.ReasonCreatorLostManage},
		{"role unbound from the team", func() (shared.ID, func()) {
			u, team, r := f.teamManager()
			return u, func() {
				h.exec(`DELETE FROM group_role_bindings WHERE group_id = $1 AND role_id = $2`, team.String(), r.String())
			}
		}, apikey.ReasonCreatorLostManage},
		{"team switched off", func() (shared.ID, func()) {
			u, team, _ := f.teamManager()
			return u, func() { h.exec(`UPDATE groups SET is_active = false WHERE id = $1`, team.String()) }
		}, apikey.ReasonCreatorLostManage},
		{"team membership expired", func() (shared.ID, func()) {
			u, team, _ := f.teamManager()
			return u, func() {
				h.exec(`UPDATE group_members SET expires_at = now() - interval '1 minute' WHERE group_id = $1 AND user_id = $2`, team.String(), u.String())
			}
		}, apikey.ReasonCreatorLostManage},
		{"administrator demoted", func() (shared.ID, func()) {
			u := h.user(h.tenant, "internal", "")
			h.exec(`UPDATE tenant_members SET role = 'admin' WHERE user_id = $1 AND tenant_id = $2`, u.String(), tid)
			return u, func() {
				h.exec(`UPDATE tenant_members SET role = 'member' WHERE user_id = $1 AND tenant_id = $2`, u.String(), tid)
			}
		}, apikey.ReasonCreatorLostManage},
		{"suspended", func() (shared.ID, func()) {
			u, _ := f.manager()
			return u, func() {
				h.exec(`UPDATE tenant_members SET status = 'suspended', suspended_at = now() WHERE user_id = $1 AND tenant_id = $2`, u.String(), tid)
			}
		}, apikey.ReasonCreatorInactive},
		{"offboarded", func() (shared.ID, func()) {
			u, _ := f.manager()
			return u, func() {
				h.exec(`UPDATE tenant_members SET status = 'offboarded', offboarded_at = now() WHERE user_id = $1 AND tenant_id = $2`, u.String(), tid)
			}
		}, apikey.ReasonCreatorInactive},
		{"removed from the organization", func() (shared.ID, func()) {
			u, _ := f.manager()
			return u, func() { h.exec(`DELETE FROM tenant_members WHERE user_id = $1 AND tenant_id = $2`, u.String(), tid) }
		}, apikey.ReasonCreatorLookup},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			creator, lose := c.setup()
			raw := f.mint(f.sa, creator)
			if !f.works(raw) {
				t.Fatal("control: a key whose creator holds service_accounts:manage must work")
			}
			lose()
			if f.works(raw) {
				t.Fatal("the key still works after its creator lost service_accounts:manage")
			}
			reason, err := f.gate.Refusal(context.Background(), h.tenant, f.sa, &creator)
			if c.reason == apikey.ReasonCreatorLookup {
				// A missing membership is a lookup failure: refused, fail closed.
				if err == nil {
					t.Errorf("reason %q, err nil", reason)
				}
				return
			}
			if err != nil || reason != c.reason {
				t.Errorf("reason = %q (err %v), want %q", reason, err, c.reason)
			}
		})
	}
}

func TestServiceKeyCreator_OwnersAndPersonKeysAndMissingCreator(t *testing.T) {
	f := newCreatorFixture(t, nil)
	h := f.h
	// An owner holds every permission.
	if !f.works(f.mint(f.sa, h.owner)) {
		t.Error("a key minted by an owner must work")
	}
	// A key with no recorded creator is refused.
	if f.works(f.mint(f.sa, shared.ID{})) {
		t.Error("a service-account key without a creator must be refused")
	}
	// A person's own key is not tied to service_accounts:manage.
	if !f.works(f.mint(h.member, h.member)) {
		t.Error("a person's key must not need service_accounts:manage")
	}
	// Another organization's manager does not qualify for this tenant's key.
	otherUser := h.user(h.other, "internal", "")
	otherRole := h.customRole(h.other, "other-manager", false, "service_accounts:manage")
	h.exec(`INSERT INTO user_roles (user_id, tenant_id, role_id) VALUES ($1, $2, $3)`, otherUser.String(), h.other.String(), otherRole.String())
	if f.works(f.mint(f.sa, otherUser)) {
		t.Error("a manager of another organization must not keep this organization's key alive")
	}
}

func TestServiceKeyCreator_FailsClosedOnLookupError(t *testing.T) {
	f := newCreatorFixture(t, func(*grbHarness) apikey.HolderPermissions { return failingHolder{} })
	creator, _ := f.manager()
	raw := f.mint(f.sa, creator)
	if f.works(raw) {
		t.Fatal("a permission lookup error must refuse the key")
	}
	reason, err := f.gate.Refusal(context.Background(), f.h.tenant, f.sa, &creator)
	if err == nil || reason != apikey.ReasonCreatorLookup {
		t.Errorf("reason = %q, err = %v, want a lookup failure", reason, err)
	}
	// A person's key does not reach the permission lookup at all.
	if !f.works(f.mint(f.h.member, f.h.member)) {
		t.Error("a person's key must not depend on the creator lookup")
	}
}

func TestServiceKeyCreator_SweepRevokesKeys(t *testing.T) {
	f := newCreatorFixture(t, nil)
	h := f.h
	db := &postgres.DB{DB: h.db}
	lost, role := f.manager()
	kept, _ := f.manager()
	lostKey, keptKey, orphanKey := f.mint(f.sa, lost), f.mint(f.sa, kept), f.mint(f.sa, shared.ID{})
	h.exec(`DELETE FROM user_roles WHERE user_id = $1 AND role_id = $2`, lost.String(), role.String())

	repo := postgres.NewServiceAccountRepository(db)
	c := controller.NewServiceKeyCreatorController(repo, f.gate, postgres.NewMemberLifecycleRepository(db), time.Minute, logger.NewNop())
	n, err := c.Reconcile(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if n < 2 {
		t.Errorf("revoked %d keys, want at least the lost creator's and the orphan", n)
	}
	status := func(raw string) string {
		var s string
		_ = h.db.QueryRow(`SELECT status FROM api_keys WHERE key_hash = $1`, crypto.HashTokenPeppered(raw, saKeyPepper)).Scan(&s)
		return s
	}
	if got := status(lostKey); got != "revoked" {
		t.Errorf("the key of a creator who lost manage is %q", got)
	}
	if got := status(orphanKey); got != "revoked" {
		t.Errorf("the key with no creator is %q", got)
	}
	if got := status(keptKey); got != "active" {
		t.Errorf("a qualifying creator's key is %q", got)
	}

	// A lookup error skips the creator: nothing is revoked on a guess.
	failing := apikey.NewServiceKeyGate(repo, apikey.NewMembershipChecker(postgres.NewTenantRepository(db), nil, nil), failingHolder{})
	c2 := controller.NewServiceKeyCreatorController(repo, failing, postgres.NewMemberLifecycleRepository(db), time.Minute, logger.NewNop())
	if _, err := c2.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := status(keptKey); got != "active" {
		t.Errorf("a lookup error revoked a key: %q", got)
	}
}

// The grant trigger locks the role row, so enabling full data on a role while
// a service account is being granted it cannot slip past both checks.
func TestServiceAccountGrantTriggers_LockTheRoleRow(t *testing.T) {
	h := newGRBHarness(t)
	sa := h.serviceAccount()
	role := h.customRole(h.tenant, "race-"+shared.NewID().String(), false, "findings:read")

	tx, err := h.db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()
	// Turn full data on: no service account holds the role yet, so this passes,
	// uncommitted.
	if _, err := tx.Exec(`UPDATE roles SET has_full_data_access = true WHERE id = $1`, role.String()); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := h.db.Exec(`INSERT INTO user_roles (user_id, tenant_id, role_id) VALUES ($1, $2, $3)`,
			sa.String(), h.tenant.String(), role.String())
		done <- err
	}()
	select {
	case err := <-done:
		t.Fatalf("the grant did not wait for the role update in flight (err %v)", err)
	case <-time.After(500 * time.Millisecond):
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err == nil {
		t.Fatal("a service account was granted a role that became full-data meanwhile")
	}
}

// Up, down, up of the trigger-lock migration against the live schema.
func TestServiceAccountGrantTriggersMigration_UpDownUp(t *testing.T) {
	h := newGRBHarness(t)
	read := func(suffix string) string {
		matches, _ := filepath.Glob("../../../../migrations/*_service_account_grant_triggers_lock_role." + suffix + ".sql")
		if len(matches) != 1 {
			t.Fatalf("migration %s not found: %v", suffix, matches)
		}
		b, err := os.ReadFile(matches[0])
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	locked := func() []bool {
		var out []bool
		for _, fn := range []string{"refuse_service_account_privileged_role", "refuse_full_data_binding_with_service_account", "refuse_service_account_in_full_data_team"} {
			var def string
			if err := h.db.QueryRow(`SELECT pg_get_functiondef(p.oid) FROM pg_proc p WHERE p.proname = $1`, fn).Scan(&def); err != nil {
				t.Fatalf("function %s: %v", fn, err)
			}
			out = append(out, strings.Contains(def, "FOR SHARE"))
		}
		return out
	}
	allEq := func(v []bool, want bool) bool {
		for _, b := range v {
			if b != want {
				return false
			}
		}
		return true
	}
	apply := func(sqlText string) {
		if _, err := h.db.Exec(sqlText); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() { apply(read("up")) })
	if !allEq(locked(), true) {
		t.Fatalf("migrated schema lacks the role lock: %v", locked())
	}
	apply(read("down"))
	if !allEq(locked(), false) {
		t.Fatalf("down left a role lock: %v", locked())
	}
	apply(read("up"))
	if !allEq(locked(), true) {
		t.Fatalf("up again lacks the role lock: %v", locked())
	}
}
