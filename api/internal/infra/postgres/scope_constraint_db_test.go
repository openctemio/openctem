package postgres

// Port-limited scope entries (RFC-065 §16.8) against a migrated database:
// the limit is stored and read back, two entries may name one host with
// different ports, the database refuses a malformed limit, and the
// migration goes down and up again.

import (
	"context"
	"errors"
	"testing"

	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/domain/scope"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func TestScopeEntryConstraints_DB(t *testing.T) {
	db := openScopeApproversDB(t)
	ctx := context.Background()
	tenant := newApproverSeed(t, db).tenant
	other := newApproverSeed(t, db).tenant
	repo := NewScopeTargetRepository(&DB{DB: db})

	limited := func(tid shared.ID, ports string) *scope.Target {
		tg, err := scope.NewTarget(tid, scope.TargetTypeDomain, "api.limits.example", "", "")
		if err != nil {
			t.Fatal(err)
		}
		if ports != "" {
			if err := tg.SetConstraint(scope.Constraint{Ports: ports, Protocol: "tcp"}); err != nil {
				t.Fatal(err)
			}
		}
		return tg
	}
	a, b, whole := limited(tenant, "8443"), limited(tenant, "9443"), limited(tenant, "")
	for _, tg := range []*scope.Target{a, b, whole} {
		if err := repo.Create(ctx, tg); err != nil {
			t.Fatalf("create %s: %v", tg.Constraint().Ports, err)
		}
	}
	if err := repo.Create(ctx, limited(tenant, "8443")); !errors.Is(err, scope.ErrTargetAlreadyExists) {
		t.Fatalf("duplicate limited entry: %v", err)
	}
	got, err := repo.GetByID(ctx, tenant, a.ID())
	if err != nil {
		t.Fatal(err)
	}
	if got.Constraint() != (scope.Constraint{Ports: "8443", Protocol: "tcp"}) || got.Matches("api.limits.example") || !got.Matches("api.limits.example:8443") {
		t.Fatalf("read back: %+v", got.Constraint())
	}
	// The manual "already exists" check is about the unlimited entry only.
	if ok, err := repo.ExistsByPattern(ctx, other, scope.TargetTypeDomain, "api.limits.example"); err != nil || ok {
		t.Fatalf("another tenant sees the entry: %v %v", ok, err)
	}
	if ok, _ := repo.ExistsByPattern(ctx, tenant, scope.TargetTypeDomain, "api.limits.example"); !ok {
		t.Fatal("unlimited entry not found")
	}
	if _, err := repo.GetByID(ctx, other, a.ID()); !errors.Is(err, scope.ErrTargetNotFound) {
		t.Fatalf("cross-tenant read: %v", err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE scope_targets SET ports = 'top-100' WHERE tenant_id = $1 AND id = $2`,
		tenant.String(), a.ID().String()); err == nil {
		t.Fatal("the database accepted a malformed port list")
	}
}

func TestScopeEntryConstraintsMigration_DB(t *testing.T) {
	dir := "../../../migrations"
	db := testdb.PrivateDatabase(t, "scope_constraints", dir)
	v := testdb.MigrationVersion(t, dir, "scope_entry_constraints")
	tenant := shared.NewID()
	if _, err := db.Exec(`INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $2)`, tenant.String(), "mig-"+tenant.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO scope_targets (tenant_id, target_type, pattern, ports, protocol) VALUES
		($1, 'domain', 'svc.example', '', ''), ($1, 'domain', 'svc.example', '8443', 'tcp')`, tenant.String()); err != nil {
		t.Fatal(err)
	}
	testdb.Migrate(t, db, dir, v, v, true)
	var n int
	if err := db.QueryRow(`SELECT count(*) FROM scope_targets WHERE tenant_id = $1`, tenant.String()).Scan(&n); err != nil || n != 1 {
		t.Fatalf("after down: %d entries (%v); the limited one must go, never widen", n, err)
	}
	testdb.Migrate(t, db, dir, v, v, false)
	if _, err := db.Exec(`INSERT INTO scope_targets (tenant_id, target_type, pattern, ports) VALUES ($1, 'domain', 'svc.example', '22')`, tenant.String()); err != nil {
		t.Fatalf("after up again: %v", err)
	}
}
