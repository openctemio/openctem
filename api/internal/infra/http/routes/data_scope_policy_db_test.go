package routes

// The per-organization policy "members without an access group see:
// everything | nothing" (tenants.members_without_group_see, migration 000247).
// Owner decision 2026-10-02: organizations that existed keep "everything",
// new organizations start with "nothing", owners/admins always see all.

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/internal/app"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/tenant"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// The data a member without an access group can reach, as status codes.
func (h *dsHarness) memberFreeView(t *testing.T) (findingStatus int, listsB bool) {
	t.Helper()
	findingStatus, _ = h.do(h.memberFree, false, http.MethodGet, "/api/v1/findings/"+h.findingB.String(), nil)
	_, body := h.do(h.memberFree, false, http.MethodGet, "/api/v1/exposures", nil)
	return findingStatus, strings.Contains(body, dsMarkerExpB)
}

func TestDataScopePolicy_BothModes(t *testing.T) {
	h := newDSHarness(t)

	// everything (organizations that existed before the new default).
	if st, listed := h.memberFreeView(t); st != http.StatusOK || !listed {
		t.Errorf("everything: member without group got finding=%d listedB=%v, want 200/true", st, listed)
	}

	// nothing.
	h.setPolicy(tenant.MembersWithoutGroupSeeNothing)
	if st, listed := h.memberFreeView(t); st != http.StatusNotFound || listed {
		t.Errorf("nothing: member without group got finding=%d listedB=%v, want 404/false", st, listed)
	}
	// Owners/admins are never affected; a member in a group keeps their group.
	if st, _ := h.do(h.owner, true, http.MethodGet, "/api/v1/findings/"+h.findingB.String(), nil); st != http.StatusOK {
		t.Errorf("nothing: owner got %d on FB, want 200", st)
	}
	if st, _ := h.do(h.memberA, false, http.MethodGet, "/api/v1/findings/"+h.findingA.String(), nil); st != http.StatusOK {
		t.Errorf("nothing: grouped member got %d on in-scope FA, want 200", st)
	}
	if st, _ := h.do(h.memberA, false, http.MethodGet, "/api/v1/findings/"+h.findingB.String(), nil); st != http.StatusNotFound {
		t.Errorf("nothing: grouped member got %d on out-of-scope FB, want 404", st)
	}
}

func TestDataScopePolicy_NewOrganizationDefaultsToNothing(t *testing.T) {
	h := newDSHarness(t)
	// A row inserted without naming the column, as tenant creation does.
	id := shared.NewID()
	h.exec(`INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $2)`, id.String(), "ds-new-"+id.String())
	t.Cleanup(func() {
		_, _ = h.db.ExecContext(context.Background(), `DELETE FROM tenants WHERE id = $1`, id.String())
	})

	repo := postgres.NewTenantRepository(&postgres.DB{DB: h.db})
	v, err := repo.GetMembersWithoutGroupSee(context.Background(), id)
	if err != nil || v != tenant.MembersWithoutGroupSeeNothing {
		t.Fatalf("new organization policy = %q (err %v), want nothing", v, err)
	}

	// And through the real create path.
	svc := app.NewTenantService(repo, logger.NewNop())
	out, err := svc.CreateTenant(context.Background(), app.CreateTenantInput{Name: "ds new org", Slug: "ds-new-org-" + id.String()[:8]}, h.owner, app.AuditContext{})
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	t.Cleanup(func() {
		_, _ = h.db.ExecContext(context.Background(), `DELETE FROM tenants WHERE id = $1`, out.ID().String())
	})
	if v, _ := repo.GetMembersWithoutGroupSee(context.Background(), out.ID()); v != tenant.MembersWithoutGroupSeeNothing {
		t.Errorf("organization created by TenantService: policy = %q, want nothing", v)
	}
}

func TestDataScopePolicy_UpdateIsValidatedAndAudited(t *testing.T) {
	h := newDSHarness(t)
	ctx := context.Background()
	db := &postgres.DB{DB: h.db}
	repo := postgres.NewTenantRepository(db)
	svc := app.NewTenantService(repo, logger.NewNop(),
		app.WithTenantAuditService(app.NewAuditService(postgres.NewAuditRepository(db), logger.NewNop())))
	svc.SetDataScopePolicyStore(repo)
	actx := app.AuditContext{ActorID: h.owner.String(), ActorEmail: "owner@ds.test"}

	if _, err := svc.UpdateDataScopePolicy(ctx, h.tenant.String(), "some", actx); !errors.Is(err, shared.ErrValidation) {
		t.Errorf("invalid value: err = %v, want validation error", err)
	}

	got, err := svc.UpdateDataScopePolicy(ctx, h.tenant.String(), tenant.MembersWithoutGroupSeeNothing, actx)
	if err != nil || got != tenant.MembersWithoutGroupSeeNothing {
		t.Fatalf("update = %q, %v", got, err)
	}
	if st, _ := h.memberFreeView(t); st != http.StatusNotFound {
		t.Errorf("after switching to nothing, member without group got %d, want 404", st)
	}
	// A repeated value is a no-op and is not audited again.
	if _, err := svc.UpdateDataScopePolicy(ctx, h.tenant.String(), tenant.MembersWithoutGroupSeeNothing, actx); err != nil {
		t.Fatal(err)
	}

	var n int
	var changes []byte
	if err := h.db.QueryRowContext(ctx,
		`SELECT COUNT(*) OVER (), COALESCE(changes::text, '') FROM audit_logs
		 WHERE tenant_id = $1 AND action = 'tenant.settings_updated' AND metadata->>'setting' = 'members_without_group_see'
		 LIMIT 1`, h.tenant.String()).Scan(&n, &changes); err != nil {
		t.Fatalf("audit row: %v", err)
	}
	if n != 1 {
		t.Errorf("audit rows = %d, want exactly 1 (no-op not audited)", n)
	}
	var c struct {
		Before map[string]string `json:"before"`
		After  map[string]string `json:"after"`
	}
	_ = json.Unmarshal(changes, &c)
	if c.Before["members_without_group_see"] != "everything" || c.After["members_without_group_see"] != "nothing" {
		t.Errorf("audit changes = %s, want everything -> nothing", changes)
	}
}

// Migration 000247 against organizations as they were before it: run inside a
// transaction that first removes the column, then rolled back.
func TestDataScopePolicyMigration_ExistingOrganizationsKeepEverything(t *testing.T) {
	h := newDSHarness(t)
	ctx := context.Background()
	up, err := os.ReadFile("../../../../migrations/000247_data_scope_no_group_policy.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	tx, err := h.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()

	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := tx.ExecContext(ctx, q, args...); err != nil {
			t.Fatalf("%.80s: %v", q, err)
		}
	}
	// Other packages use tenants concurrently; lock it before the DDL so the
	// ALTER cannot deadlock with them.
	testdb.LockForDDL(t, ctx, tx, "tenants")
	exec(`ALTER TABLE tenants DROP CONSTRAINT IF EXISTS chk_tenants_members_without_group_see`)
	exec(`ALTER TABLE tenants DROP COLUMN members_without_group_see`)
	plain, flagged := shared.NewID(), shared.NewID()
	exec(`INSERT INTO tenants (id, name, slug, settings) VALUES ($1, 'm1', $2, '{}')`, plain.String(), "mig-plain-"+plain.String())
	exec(`INSERT INTO tenants (id, name, slug, settings) VALUES ($1, 'm2', $2, '{"security":{"restricted_data_scope":true}}')`,
		flagged.String(), "mig-flag-"+flagged.String())

	exec(string(up))
	// Applying it twice is harmless.
	exec(string(up))

	policy := func(id shared.ID) string {
		var v string
		if err := tx.QueryRowContext(ctx, `SELECT members_without_group_see FROM tenants WHERE id = $1`, id.String()).Scan(&v); err != nil {
			t.Fatal(err)
		}
		return v
	}
	if v := policy(plain); v != tenant.MembersWithoutGroupSeeEverything {
		t.Errorf("existing organization: %q, want everything", v)
	}
	if v := policy(h.tenant); v != tenant.MembersWithoutGroupSeeEverything {
		t.Errorf("existing harness organization: %q, want everything", v)
	}
	if v := policy(flagged); v != tenant.MembersWithoutGroupSeeNothing {
		t.Errorf("organization that had turned on restricted data scope: %q, want nothing", v)
	}
	newID := shared.NewID()
	exec(`INSERT INTO tenants (id, name, slug) VALUES ($1, 'm3', $2)`, newID.String(), "mig-new-"+newID.String())
	if v := policy(newID); v != tenant.MembersWithoutGroupSeeNothing {
		t.Errorf("organization created after the migration: %q, want nothing", v)
	}
}

// Retiring "everything" (owner decision D2, research doc 15 L-04): the impact
// report names exactly the members who would see nothing after the switch,
// the switch goes one way only, and is never made for an organization that
// did not choose it.
func TestDataScopePolicy_RetireEverything(t *testing.T) {
	h := newDSHarness(t)
	ctx := context.Background()
	db := &postgres.DB{DB: h.db}
	repo := postgres.NewTenantRepository(db)
	svc := app.NewTenantService(repo, logger.NewNop())
	svc.SetDataScopePolicyStore(repo)
	actx := app.AuditContext{ActorID: h.owner.String()}

	// A member holding a full-data role is not affected either.
	reader := shared.NewID()
	role := shared.NewID()
	h.exec(`INSERT INTO users (id, email, name) VALUES ($1, $2, 'reader')`, reader.String(), reader.String()+"@ds.test")
	t.Cleanup(func() {
		_, _ = h.db.ExecContext(context.Background(), `DELETE FROM users WHERE id = $1`, reader.String())
	})
	h.exec(`INSERT INTO tenant_members (user_id, tenant_id, role) VALUES ($1, $2, 'member')`, reader.String(), h.tenant.String())
	h.exec(`INSERT INTO roles (id, tenant_id, slug, name, hierarchy_level, has_full_data_access) VALUES ($1, $2, $3, 'Reader', 30, TRUE)`,
		role.String(), h.tenant.String(), "ds-reader-"+role.String()[:8])
	h.exec(`INSERT INTO user_roles (user_id, tenant_id, role_id) VALUES ($1, $2, $3)`, reader.String(), h.tenant.String(), role.String())

	impact, err := svc.GetDataScopeImpact(ctx, h.tenant.String())
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, m := range impact.Members {
		got[m.UserID] = true
	}
	want := map[string]bool{h.memberFree.String(): true, h.memberStrict.String(): true}
	if impact.Policy != tenant.MembersWithoutGroupSeeEverything || impact.TotalCount != len(want) || len(got) != len(want) {
		t.Fatalf("impact = %+v, want policy everything and exactly memberFree and memberStrict", impact)
	}
	for id := range want {
		if !got[id] {
			t.Errorf("impact misses %s", id)
		}
	}
	for _, id := range []shared.ID{h.owner, h.memberA, reader} {
		if got[id.String()] {
			t.Errorf("impact lists %s, who keeps access", id)
		}
	}

	// The switch goes one way: to nothing, never back to everything.
	if _, err := svc.UpdateDataScopePolicy(ctx, h.tenant.String(), tenant.MembersWithoutGroupSeeNothing, actx); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.UpdateDataScopePolicy(ctx, h.tenant.String(), tenant.MembersWithoutGroupSeeEverything, actx); !errors.Is(err, tenant.ErrSeeEverythingRetired) {
		t.Errorf("switching back to everything: err = %v, want ErrSeeEverythingRetired", err)
	}
	var stored string
	_ = h.db.QueryRow(`SELECT members_without_group_see FROM tenants WHERE id = $1`, h.tenant.String()).Scan(&stored)
	if stored != tenant.MembersWithoutGroupSeeNothing {
		t.Errorf("stored policy = %s, want nothing", stored)
	}
}
