package postgres

import (
	"context"
	"database/sql"
	"testing"

	_ "github.com/lib/pq"

	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Only an active control that passed its test and whose review date has not
// passed reduces anything (backend audit B7-R2): an untested, partially
// tested, failed, expired or review-date-less control counts as none. A
// control of another tenant never counts.
func TestCompensatingControlLookup_OnlyVerifiedControlsCount(t *testing.T) {
	dbURL := testdb.URL()
	if dbURL == "" {
		t.Skip("DATABASE_URL not set; skipping DB-backed test")
	}
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer func() { _ = db.Close() }()
	if err := db.Ping(); err != nil {
		t.Skipf("cannot reach test DB: %v", err)
	}
	ctx := context.Background()

	newTenant := func() shared.ID {
		id := shared.NewID()
		mustExec(t, db, `INSERT INTO tenants (id, name, slug) VALUES ($1,$2,$3)`, id.String(), "cc-lookup", "cc-"+id.String()[24:])
		t.Cleanup(func() { _, _ = db.ExecContext(ctx, `DELETE FROM tenants WHERE id=$1`, id.String()) })
		return id
	}
	tenant, other := newTenant(), newTenant()

	cases := []struct {
		name, status, test, tested, expires string
		want                                float64
	}{
		{"untested", "active", "NULL", "NULL", "now() + interval '30 days'", 0},
		{"partial", "active", "'partial'", "now()", "now() + interval '30 days'", 0},
		{"no review date", "active", "'pass'", "now()", "NULL", 0},
		{"review date passed", "active", "'pass'", "now()", "now() - interval '1 day'", 0},
		{"inactive", "inactive", "'pass'", "now()", "now() + interval '30 days'", 0},
		{"verified", "active", "'pass'", "now()", "now() + interval '30 days'", 0.5},
	}
	repo := NewCompensatingControlLookupRepo(db)
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var asset string
			if err := db.QueryRowContext(ctx, `INSERT INTO assets (tenant_id, name, asset_type) VALUES ($1,$2,'domain') RETURNING id`,
				tenant.String(), shared.NewID().String()+".example.com").Scan(&asset); err != nil {
				t.Fatal(err)
			}
			var control string
			if err := db.QueryRowContext(ctx, `INSERT INTO compensating_controls
				(tenant_id, name, control_type, status, reduction_factor, test_result, last_tested_at, expires_at)
				VALUES ($1, 'waf', 'runtime', $2, 0.5, `+c.test+`, `+c.tested+`, `+c.expires+`) RETURNING id`,
				tenant.String(), c.status).Scan(&control); err != nil {
				t.Fatal(err)
			}
			mustExec(t, db, `INSERT INTO compensating_control_assets (control_id, asset_id) VALUES ($1,$2)`, control, asset)
			aid, _ := shared.IDFromString(asset)

			got, err := repo.GetEffectiveForAssets(ctx, tenant, []shared.ID{aid})
			if err != nil {
				t.Fatal(err)
			}
			if got[aid] != c.want {
				t.Fatalf("reduction = %v, want %v", got[aid], c.want)
			}
			// Asked as another tenant, the asset has no control at all.
			cross, err := repo.GetEffectiveForAssets(ctx, other, []shared.ID{aid})
			if err != nil {
				t.Fatal(err)
			}
			if len(cross) != 0 {
				t.Fatalf("another tenant sees reduction %v", cross)
			}
		})
	}
}
