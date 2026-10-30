package postgres

// The repository extension and asset group reads count findings for the rows
// they return only. Both used to join a derived table grouping the findings
// of every tenant (GROUP BY asset_id / asset_group_id), which the outer
// tenant filter cannot reach: each call scanned the whole findings index,
// and the asset list paid it once per page.

import (
	"context"
	"database/sql"
	"strings"
	"testing"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func explainLines(ctx context.Context, t *testing.T, db *sql.DB, query string, args ...any) string {
	t.Helper()
	rows, err := db.QueryContext(ctx, "EXPLAIN "+query, args...)
	if err != nil {
		t.Fatalf("explain: %v", err)
	}
	defer rows.Close()
	var b strings.Builder
	for rows.Next() {
		var line string
		if err := rows.Scan(&line); err != nil {
			t.Fatal(err)
		}
		b.WriteString(line + "\n")
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return b.String()
}

func TestFindingCountsArePerReturnedRow(t *testing.T) {
	sqlDB := openSensorDB(t)
	ctx := context.Background()
	db := &DB{DB: sqlDB}
	mine, other := seedTestTenant(ctx, t, sqlDB), seedTestTenant(ctx, t, sqlDB)

	repoAsset := func(tenant shared.ID, name string, findings int) shared.ID {
		id := shared.NewID()
		exec := func(q string, args ...any) {
			if _, err := sqlDB.ExecContext(ctx, q, args...); err != nil {
				t.Fatalf("%s: %v", q, err)
			}
		}
		exec(`INSERT INTO assets (id, tenant_id, name, asset_type) VALUES ($1, $2, $3, 'repository')`, id.String(), tenant.String(), name)
		exec(`INSERT INTO asset_repositories (asset_id, full_name) VALUES ($1, $2)`, id.String(), name)
		exec(`INSERT INTO findings (id, tenant_id, asset_id, source, tool_name, message, severity, fingerprint, status)
			SELECT gen_random_uuid(), $1, $2::uuid, 'sca', 'count-test', 'm', 'high', $2::text || '-' || g, 'new' FROM generate_series(1, $3::int) g`,
			tenant.String(), id.String(), findings)
		return id
	}
	a := repoAsset(mine, "example/count-a-"+mine.String()[:8], 3)
	_ = repoAsset(other, "example/count-b-"+other.String()[:8], 5)

	got, err := NewRepositoryExtensionRepository(db).GetByAssetIDs(ctx, []shared.ID{a})
	if err != nil {
		t.Fatal(err)
	}
	if r := got[a]; r == nil || r.FindingCount() != 3 {
		t.Fatalf("finding count of the repository = %v, want 3", r)
	}

	plan := explainLines(ctx, t, sqlDB, NewRepositoryExtensionRepository(db).selectQuery()+" WHERE ar.asset_id = ANY($1)", pq.Array([]string{a.String()}))
	if strings.Contains(plan, "Group Key") {
		t.Errorf("repository extension read aggregates findings beyond its rows:\n%s", plan)
	}
	plan = explainLines(ctx, t, sqlDB, assetGroupSelectQuery+" WHERE ag.tenant_id = $1", mine.String())
	if strings.Contains(plan, "Group Key") {
		t.Errorf("asset group read aggregates findings beyond its rows:\n%s", plan)
	}
}
