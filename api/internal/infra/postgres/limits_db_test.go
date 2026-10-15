package postgres

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/limits"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func limitsTestTenant(t *testing.T, db *sql.DB, slug string) shared.ID {
	t.Helper()
	id := shared.NewID()
	if _, err := db.ExecContext(context.Background(),
		`INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $3)`, id.String(), slug, slug); err != nil {
		t.Fatalf("insert tenant: %v", err)
	}
	t.Cleanup(func() { _, _ = db.ExecContext(context.Background(), `DELETE FROM tenants WHERE id = $1`, id.String()) })
	return id
}

// Limits, feature denies, the self-service defaults and usage as the
// application role: every read and write stays inside its organization and
// its origin. Requires DATABASE_URL.
func TestLimitsRepository(t *testing.T) {
	sqlDB := openSensorDB(t)
	ctx := context.Background()
	r := NewLimitsRepository(&DB{DB: sqlDB})
	suffix := shared.NewID().String()[28:]
	a := limitsTestTenant(t, sqlDB, "lim-a-"+suffix)
	b := limitsTestTenant(t, sqlDB, "lim-b-"+suffix)
	owner := limitsTestUser(t, sqlDB, "lim-owner-"+suffix+"@example.test")
	member := limitsTestUser(t, sqlDB, "lim-member-"+suffix+"@example.test")
	now := time.Now().UTC()

	// Self-service defaults: absent, then saved, then a stale save refused.
	_, _ = sqlDB.ExecContext(ctx, `DELETE FROM platform_settings WHERE key = $1`, limits.SelfServiceDefaultsKey)
	t.Cleanup(func() {
		_, _ = sqlDB.ExecContext(context.Background(), `DELETE FROM platform_settings WHERE key = $1`, limits.SelfServiceDefaultsKey)
	})
	if _, _, err := r.GetSelfServiceDefaults(ctx); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("empty defaults: %v", err)
	}
	d := limits.Limits{limits.Seats: 5}
	v, err := r.SaveSelfServiceDefaults(ctx, d, 0, owner, now)
	if err != nil || v != 1 {
		t.Fatalf("first save v=%d err=%v", v, err)
	}
	if _, err := r.SaveSelfServiceDefaults(ctx, d, 0, owner, now); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("second insert must conflict: %v", err)
	}
	d[limits.OrgsPerUser] = 1
	if v, err = r.SaveSelfServiceDefaults(ctx, d, 1, owner, now); err != nil || v != 2 {
		t.Fatalf("update v=%d err=%v", v, err)
	}
	if _, err := r.SaveSelfServiceDefaults(ctx, d, 1, owner, now); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("stale version must conflict: %v", err)
	}
	got, gv, err := r.GetSelfServiceDefaults(ctx)
	if err != nil || gv != 2 || got.Get(limits.OrgsPerUser) != 1 || got.Get(limits.Assets) != limits.Unlimited {
		t.Fatalf("read back: %v v=%d err=%v", got, gv, err)
	}

	// Limits are per organization and per origin.
	exp := now.Add(24 * time.Hour)
	op, cp := limits.OriginOperator, limits.OriginControlPlane
	if err := r.SetLimit(ctx, limits.Limit{TenantID: a, Key: limits.Seats, Value: 10, Origin: op, Reason: "pilot", ExpiresAt: &exp, SetBy: &owner, SetAt: now}); err != nil {
		t.Fatal(err)
	}
	if err := r.SetLimit(ctx, limits.Limit{TenantID: a, Key: limits.Seats, Value: 12, Origin: op, Reason: "pilot+", SetAt: now}); err != nil {
		t.Fatal(err)
	}
	if err := r.SetLimit(ctx, limits.Limit{TenantID: a, Key: limits.Seats, Value: 5, Origin: cp, Reason: "service", SetAt: now}); err != nil {
		t.Fatal(err)
	}
	la, _ := r.ListLimits(ctx, a, op)
	if len(la) != 1 || la[0].Value != 12 || la[0].ExpiresAt != nil || la[0].Reason != "pilot+" || la[0].Origin != op {
		t.Fatalf("operator limits a: %+v", la)
	}
	if lc, _ := r.ListLimits(ctx, a, cp); len(lc) != 1 || lc[0].Value != 5 {
		t.Fatalf("control-plane limits a: %+v", lc)
	}
	if lb, _ := r.ListLimits(ctx, b, op); len(lb) != 0 {
		t.Fatalf("limits b must be empty: %+v", lb)
	}
	if err := r.DeleteLimit(ctx, b, limits.Seats, op); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("deleting b's (absent) limit must not touch a's: %v", err)
	}
	if err := r.DeleteLimit(ctx, a, limits.Seats, op); err != nil {
		t.Fatal(err)
	}
	if lc, _ := r.ListLimits(ctx, a, cp); len(lc) != 1 {
		t.Fatal("deleting the operator's limit keeps the control plane's")
	}
	if err := r.SetLimit(ctx, limits.Limit{TenantID: a, Key: limits.Seats, Value: 1, Origin: op, Reason: "", SetAt: now}); err == nil {
		t.Fatal("an empty reason must be refused by the check constraint")
	}
	if err := r.SetLimit(ctx, limits.Limit{TenantID: a, Key: limits.Seats, Value: 1, Origin: "billing", Reason: "x", SetAt: now}); err == nil {
		t.Fatal("an unknown origin must be refused by the check constraint")
	}

	// Feature denies.
	if err := r.SetDeny(ctx, limits.FeatureDeny{TenantID: a, Feature: "pentest", Origin: op, Reason: "contract", SetAt: now}); err != nil {
		t.Fatal(err)
	}
	if da, _ := r.ListDenies(ctx, a, op); len(da) != 1 || da[0].Feature != "pentest" {
		t.Fatalf("denies a: %+v", da)
	}
	if db, _ := r.ListDenies(ctx, b, op); len(db) != 0 {
		t.Fatalf("denies b: %+v", db)
	}
	if err := r.SetDeny(ctx, limits.FeatureDeny{TenantID: a, Feature: "Bad Feature", Origin: op, Reason: "x", SetAt: now}); err == nil {
		t.Fatal("a malformed feature must be refused by the check constraint")
	}

	// ReplaceOrigin swaps one origin's rows atomically and leaves the rest.
	if err := r.ReplaceOrigin(ctx, a, cp,
		[]limits.Limit{{TenantID: a, Key: limits.Assets, Value: 500, Origin: cp, Reason: "service", SetAt: now}},
		[]limits.FeatureDeny{{TenantID: a, Feature: "reports", Origin: cp, Reason: "service", SetAt: now}}); err != nil {
		t.Fatal(err)
	}
	if lc, _ := r.ListLimits(ctx, a, cp); len(lc) != 1 || lc[0].Key != limits.Assets {
		t.Fatalf("replaced control-plane limits: %+v", lc)
	}
	if da, _ := r.ListDenies(ctx, a, op); len(da) != 1 {
		t.Fatal("ReplaceOrigin must not touch the operator's denies")
	}
	if err := r.ReplaceOrigin(ctx, a, cp, []limits.Limit{{TenantID: b, Key: limits.Assets, Value: 1, Origin: cp, Reason: "x", SetAt: now}}, nil); err == nil {
		t.Fatal("a row for another organization must be refused")
	}
	if lc, _ := r.ListLimits(ctx, a, cp); len(lc) != 1 {
		t.Fatal("a refused replace is rolled back")
	}
	if lb, _ := r.ListLimits(ctx, b, cp); len(lb) != 0 {
		t.Fatal("nothing written for b")
	}

	// Grace.
	until := now.Add(time.Hour)
	if err := r.StartGrace(ctx, a, []string{"pentest", "not-a-module"}, until); err != nil {
		t.Fatal(err)
	}
	if ga, _ := r.ListGrace(ctx, a); len(ga) != 1 {
		t.Fatalf("grace a (modules only): %v", ga)
	}
	if gb, _ := r.ListGrace(ctx, b); len(gb) != 0 {
		t.Fatalf("grace b: %v", gb)
	}
	if err := r.EndGrace(ctx, a, []string{"pentest"}); err != nil {
		t.Fatal(err)
	}

	// Usage counts only the organization's own rows.
	for _, m := range []struct {
		tenant shared.ID
		user   shared.ID
		role   string
	}{{a, owner, "owner"}, {a, member, "member"}, {b, member, "owner"}} {
		if _, err := sqlDB.ExecContext(ctx, `INSERT INTO tenant_members (tenant_id, user_id, role, status) VALUES ($1, $2, $3, 'active')`,
			m.tenant.String(), m.user.String(), m.role); err != nil {
			t.Fatalf("insert member: %v", err)
		}
	}
	// A suspended member still holds a seat; an offboarded one does not.
	third := limitsTestUser(t, sqlDB, "lim-third-"+suffix+"@example.test")
	gone := limitsTestUser(t, sqlDB, "lim-gone-"+suffix+"@example.test")
	for u, status := range map[shared.ID]string{third: "suspended", gone: "offboarded"} {
		if _, err := sqlDB.ExecContext(ctx, `INSERT INTO tenant_members (tenant_id, user_id, role, status) VALUES ($1, $2, 'viewer', $3)`,
			a.String(), u.String(), status); err != nil {
			t.Fatalf("insert %s member: %v", status, err)
		}
	}
	ua, err := r.Usage(ctx, a, false)
	if err != nil {
		t.Fatal(err)
	}
	if ua[limits.Seats] != 3 || ua[limits.Assets] != 0 || ua[limits.APIKeys] != 0 {
		t.Fatalf("usage a: %v", ua)
	}
	if ub, _ := r.Usage(ctx, b, false); ub[limits.Seats] != 1 {
		t.Fatalf("usage b: %v", ub)
	}

	// Organizations a person owns.
	if n, _ := r.CountOwnedTenants(ctx, member); n != 1 {
		t.Fatalf("member owns b: %d", n)
	}
	if n, _ := r.CountOwnedTenants(ctx, owner); n != 1 {
		t.Fatalf("owner owns a: %d", n)
	}
}

func limitsTestUser(t *testing.T, db *sql.DB, email string) shared.ID {
	t.Helper()
	id := shared.NewID()
	if _, err := db.ExecContext(context.Background(),
		`INSERT INTO users (id, email, name, status) VALUES ($1, $2, 'Limits Test', 'active')`, id.String(), email); err != nil {
		t.Fatalf("insert user: %v", err)
	}
	t.Cleanup(func() { _, _ = db.ExecContext(context.Background(), `DELETE FROM users WHERE id = $1`, id.String()) })
	return id
}
