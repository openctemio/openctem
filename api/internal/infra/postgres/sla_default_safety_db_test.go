package postgres

import (
	"context"
	"database/sql"
	"sync"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/sla"
)

func newSLAPolicyRow(t *testing.T, tenant shared.ID, name string, isDefault bool) *sla.Policy {
	t.Helper()
	p, err := sla.NewPolicy(tenant, name)
	if err != nil {
		t.Fatal(err)
	}
	p.SetDefault(isDefault)
	return p
}

func countSLADefaults(ctx context.Context, t *testing.T, db *sql.DB, tenant shared.ID) int {
	t.Helper()
	var n int
	if err := db.QueryRowContext(ctx,
		`SELECT count(*) FROM sla_policies WHERE tenant_id = $1 AND asset_id IS NULL AND is_default`,
		tenant.String()).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// Two concurrent make-default calls end with exactly one default, and neither
// fails.
func TestSLAPolicy_ConcurrentMakeDefault_OneDefault_DB(t *testing.T) {
	ctx := context.Background()
	db := openGroupsDB(t)
	repo := NewSLAPolicyRepository(&DB{DB: db})

	for round := 0; round < 15; round++ {
		tenant := seedTestTenant(ctx, t, db)
		old := newSLAPolicyRow(t, tenant, "old", true)
		a := newSLAPolicyRow(t, tenant, "a", false)
		b := newSLAPolicyRow(t, tenant, "b", false)
		for _, p := range []*sla.Policy{old, a, b} {
			if err := repo.Create(ctx, p); err != nil {
				t.Fatalf("create: %v", err)
			}
		}
		a.SetDefault(true)
		b.SetDefault(true)

		var wg sync.WaitGroup
		errs := make([]error, 2)
		for i, p := range []*sla.Policy{a, b} {
			wg.Add(1)
			go func() {
				defer wg.Done()
				errs[i] = repo.UpdateMakingDefault(ctx, p)
			}()
		}
		wg.Wait()
		for i, err := range errs {
			if err != nil {
				t.Fatalf("round %d: call %d failed: %v", round, i, err)
			}
		}
		if n := countSLADefaults(ctx, t, db, tenant); n != 1 {
			t.Fatalf("round %d: %d defaults, want exactly 1", round, n)
		}
	}
}

// Making a default in tenant A never touches tenant B's default.
func TestSLAPolicy_MakeDefault_TenantIsolation_DB(t *testing.T) {
	ctx := context.Background()
	db := openGroupsDB(t)
	repo := NewSLAPolicyRepository(&DB{DB: db})
	tenantA := seedTestTenant(ctx, t, db)
	tenantB := seedTestTenant(ctx, t, db)

	oldA := newSLAPolicyRow(t, tenantA, "old-a", true)
	newA := newSLAPolicyRow(t, tenantA, "new-a", false)
	defB := newSLAPolicyRow(t, tenantB, "def-b", true)
	for _, p := range []*sla.Policy{oldA, newA, defB} {
		if err := repo.Create(ctx, p); err != nil {
			t.Fatal(err)
		}
	}
	newA.SetDefault(true)
	if err := repo.UpdateMakingDefault(ctx, newA); err != nil {
		t.Fatalf("make default: %v", err)
	}

	gotA, err := repo.GetTenantDefault(ctx, tenantA)
	if err != nil || gotA.ID() != newA.ID() {
		t.Fatalf("tenant A default = %v (%v), want the new policy", gotA, err)
	}
	gotB, err := repo.GetTenantDefault(ctx, tenantB)
	if err != nil || gotB.ID() != defB.ID() {
		t.Fatalf("tenant B default changed: %v (%v)", gotB, err)
	}

	// Tenant B swapping its own default leaves tenant A alone.
	foreign := newSLAPolicyRow(t, tenantB, "foreign", false)
	if err := repo.Create(ctx, foreign); err != nil {
		t.Fatal(err)
	}
	foreign.SetDefault(true)
	if err := repo.UpdateMakingDefault(ctx, foreign); err != nil {
		t.Fatalf("tenant B own make default: %v", err)
	}
	if n := countSLADefaults(ctx, t, db, tenantA); n != 1 {
		t.Fatalf("tenant A has %d defaults after tenant B's change", n)
	}
}

// The database refuses a second default, an inactive default and a window
// outside 1..365 even when the application is bypassed.
func TestSLAPolicy_DefaultSafetyConstraints_DB(t *testing.T) {
	ctx := context.Background()
	db := openGroupsDB(t)
	repo := NewSLAPolicyRepository(&DB{DB: db})
	tenant := seedTestTenant(ctx, t, db)

	if err := repo.Create(ctx, newSLAPolicyRow(t, tenant, "d1", true)); err != nil {
		t.Fatal(err)
	}
	if err := repo.Create(ctx, newSLAPolicyRow(t, tenant, "d2", true)); err == nil {
		t.Error("a second tenant default was accepted")
	}
	if _, err := db.ExecContext(ctx, `UPDATE sla_policies SET is_active = false WHERE tenant_id = $1 AND is_default`, tenant.String()); err == nil {
		t.Error("an inactive default was accepted")
	}
	if _, err := db.ExecContext(ctx, `UPDATE sla_policies SET low_days = 4000 WHERE tenant_id = $1`, tenant.String()); err == nil {
		t.Error("a 4000-day window was accepted")
	}
	if _, err := db.ExecContext(ctx, `UPDATE sla_policies SET critical_days = 0 WHERE tenant_id = $1`, tenant.String()); err == nil {
		t.Error("a 0-day critical window was accepted")
	}
	// An inactive non-default and an asset-specific policy are fine.
	if err := repo.Create(ctx, newSLAPolicyRow(t, tenant, "plain", false)); err != nil {
		t.Errorf("plain policy: %v", err)
	}
}

// The migration keeps the oldest active default per tenant, unsets the rest
// (including an inactive default), leaves other tenants and every window
// untouched, and then the constraints hold.
func TestSLAPolicy_MigrationDedupesDefaults_DB(t *testing.T) {
	const dir = "../../../migrations"
	db := testdb.PrivateDatabase(t, "sla_default", dir)
	ctx := context.Background()
	v := testdb.MigrationVersion(t, dir, "sla_policies_default_safety")
	testdb.Migrate(t, db, dir, v, v, true) // back to the state before the migration

	tenantA, tenantB, tenantC := seedTestTenant(ctx, t, db), seedTestTenant(ctx, t, db), seedTestTenant(ctx, t, db)
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	ins := func(tenant shared.ID, name string, active bool, age int, low int) string {
		id := shared.NewID().String()
		if _, err := db.ExecContext(ctx, `INSERT INTO sla_policies
			(id, tenant_id, name, is_default, is_active, low_days, created_at, updated_at)
			VALUES ($1, $2, $3, true, $4, $5, $6, $6)`,
			id, tenant.String(), name, active, low, t0.Add(time.Duration(age)*time.Hour)); err != nil {
			t.Fatal(err)
		}
		return id
	}
	// Tenant A: oldest is inactive, then two active ones; the older active wins.
	aInactive := ins(tenantA, "inactive-oldest", false, 0, 90)
	aKeep := ins(tenantA, "keep", true, 1, 77)
	aDrop := ins(tenantA, "drop", true, 2, 90)
	// Tenant B: a single active default is untouched.
	bOnly := ins(tenantB, "only", true, 0, 90)
	// Tenant C: only an inactive default; it is unset.
	cInactive := ins(tenantC, "inactive", false, 0, 90)
	// Tenant B also has a non-default policy written before the API bounds:
	// its windows are clamped so the CHECK can be validated.
	bWide := shared.NewID().String()
	if _, err := db.ExecContext(ctx, `INSERT INTO sla_policies
		(id, tenant_id, name, is_default, is_active, critical_days, low_days, info_days)
		VALUES ($1, $2, 'wide', false, true, 0, 500, 400)`, bWide, tenantB.String()); err != nil {
		t.Fatal(err)
	}

	testdb.Migrate(t, db, dir, v, v, false)

	isDefault := func(id string) bool {
		var d bool
		if err := db.QueryRowContext(ctx, `SELECT is_default FROM sla_policies WHERE id = $1`, id).Scan(&d); err != nil {
			t.Fatal(err)
		}
		return d
	}
	if isDefault(aInactive) || isDefault(aDrop) || !isDefault(aKeep) {
		t.Errorf("tenant A: inactive=%v drop=%v keep=%v, want false/false/true", isDefault(aInactive), isDefault(aDrop), isDefault(aKeep))
	}
	if !isDefault(bOnly) {
		t.Error("tenant B's only default was unset")
	}
	if isDefault(cInactive) {
		t.Error("tenant C's inactive default stayed default")
	}
	var low int
	if err := db.QueryRowContext(ctx, `SELECT low_days FROM sla_policies WHERE id = $1`, aKeep).Scan(&low); err != nil || low != 77 {
		t.Errorf("windows were rewritten: low_days=%d err=%v", low, err)
	}

	var crit, wideLow, info int
	if err := db.QueryRowContext(ctx, `SELECT critical_days, low_days, info_days FROM sla_policies WHERE id = $1`, bWide).
		Scan(&crit, &wideLow, &info); err != nil || crit != 1 || wideLow != 365 || info != 365 {
		t.Errorf("out-of-range windows = %d/%d/%d err=%v, want clamped to 1/365/365", crit, wideLow, info, err)
	}

	// down then up again works on the migrated data.
	testdb.Migrate(t, db, dir, v, v, true)
	testdb.Migrate(t, db, dir, v, v, false)
}
