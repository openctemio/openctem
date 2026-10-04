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
	tx, err := testdb.OpenMigrator(t).BeginTx(ctx, nil) // the migration is DDL: schema owner
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
