package postgres

import (
	"context"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// GetStats under a user's scope counts only that user's assets, and a user
// with no scope row counts nothing (there is no "no scope row means
// everything" any more, owner decision D2). A report rendered under a
// restricted creator's scope (D6) relies on it; CountWindow honors the same
// scope.
func TestGetStats_ScopeAlwaysStrictAndCountWindowScope(t *testing.T) {
	db := openStatsTestDB(t)
	ctx := context.Background()

	tenantID := seedTestTenant(ctx, t, db)
	visible := seedTestAsset(ctx, t, db, tenantID)
	hidden := seedTestAsset(ctx, t, db, tenantID)
	seedStatsFinding(ctx, t, db, tenantID, visible, statsProbe{source: "sca", severity: "high", status: "new"})
	seedStatsFinding(ctx, t, db, tenantID, hidden, statsProbe{source: "sca", severity: "critical", status: "new"})

	scoped, empty := shared.NewID(), shared.NewID()
	for _, u := range []shared.ID{scoped, empty} {
		if _, err := db.ExecContext(ctx, `INSERT INTO users (id, email, name) VALUES ($1, $2, 'strict')`,
			u.String(), u.String()+"@stats-strict.test"); err != nil {
			t.Fatal(err)
		}
		uid := u
		t.Cleanup(func() { _, _ = db.ExecContext(context.Background(), `DELETE FROM users WHERE id = $1`, uid.String()) })
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO user_accessible_assets (user_id, tenant_id, asset_id) VALUES ($1, $2, $3)`,
		scoped.String(), tenantID.String(), visible.String()); err != nil {
		t.Fatal(err)
	}
	repo := NewFindingRepository(&DB{DB: db})
	none := vulnerability.FindingStatsFilter{}

	if st, err := repo.GetStats(ctx, tenantID, &scoped, none); err != nil || st.Total != 1 {
		t.Errorf("scope with a row: total %v (err %v), want 1", st.Total, err)
	}
	if st, err := repo.GetStats(ctx, tenantID, &empty, none); err != nil || st.Total != 0 {
		t.Errorf("scope without rows: total %v (err %v), want 0 (never the whole tenant)", st.Total, err)
	}
	if st, err := repo.GetStats(ctx, tenantID, nil, none); err != nil || st.Total != 2 {
		t.Errorf("unscoped (admin): total %v (err %v), want 2", st.Total, err)
	}

	n, _, err := repo.CountWindow(ctx, tenantID, &shared.DataScope{TenantID: tenantID, UserID: scoped}, 7)
	if err != nil || n != 1 {
		t.Errorf("scoped window: new %d (err %v), want 1", n, err)
	}
	if n, _, err := repo.CountWindow(ctx, tenantID, nil, 7); err != nil || n != 2 {
		t.Errorf("unscoped window: new %d (err %v), want 2", n, err)
	}
}
