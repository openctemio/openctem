package postgres

import (
	"context"
	"database/sql"
	"testing"

	_ "github.com/lib/pq"

	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Re-seeing a finding on a rescan sets severity and status to the values they
// already have. The branch counter trigger used to run its five COUNT(*) and an
// UPDATE of repository_branches for every such write; it must fire only when
// the branch, severity or status actually changed.
func TestBranchCounterTrigger_FiresOnlyOnRealChange(t *testing.T) {
	dbURL := testdb.URL()
	if dbURL == "" {
		t.Skip("DATABASE_URL not set; skipping DB execution check")
	}
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		t.Skipf("open db: %v", err)
	}
	defer func() { _ = db.Close() }()
	ctx := context.Background()
	if err := db.PingContext(ctx); err != nil {
		t.Skipf("cannot reach DATABASE_URL: %v", err)
	}

	tenant := seedTestTenant(ctx, t, db)
	repoID := shared.NewID()
	branchID := shared.NewID()
	findingID := shared.NewID()
	mustExec := func(q string, args ...any) {
		t.Helper()
		if _, err := db.ExecContext(ctx, q, args...); err != nil {
			t.Fatalf("%v\n%s", err, q)
		}
	}
	mustExec(`INSERT INTO assets (id, tenant_id, name, asset_type) VALUES ($1,$2,'repo','repository')`, repoID.String(), tenant.String())
	mustExec(`INSERT INTO asset_repositories (asset_id) VALUES ($1)`, repoID.String())
	mustExec(`INSERT INTO repository_branches (id, repository_id, name) VALUES ($1,$2,'main')`, branchID.String(), repoID.String())
	mustExec(`INSERT INTO findings (id, tenant_id, asset_id, branch_id, source, tool_name, message, severity, fingerprint, status)
		VALUES ($1,$2,$3,$4,'sast','semgrep','m','high',$5,'new')`,
		findingID.String(), tenant.String(), repoID.String(), branchID.String(), findingID.String())

	branch := func() (xmin string, high int) {
		t.Helper()
		if err := db.QueryRowContext(ctx,
			`SELECT xmin::text, findings_high FROM repository_branches WHERE id = $1`, branchID.String()).Scan(&xmin, &high); err != nil {
			t.Fatal(err)
		}
		return
	}
	xmin0, high0 := branch()
	if high0 != 1 {
		t.Fatalf("insert did not count the finding: findings_high=%d", high0)
	}

	// A re-sighting: same severity and status named in SET, plus freshness.
	mustExec(`UPDATE findings SET severity = 'high', status = 'new', last_seen_at = now(), updated_at = now() WHERE id = $1`, findingID.String())
	if xmin1, _ := branch(); xmin1 != xmin0 {
		t.Fatalf("an unchanged re-sighting rewrote repository_branches (xmin %s -> %s)", xmin0, xmin1)
	}

	// A real severity change still moves the counters.
	mustExec(`UPDATE findings SET severity = 'low' WHERE id = $1`, findingID.String())
	var high, low int
	if err := db.QueryRowContext(ctx,
		`SELECT findings_high, findings_low FROM repository_branches WHERE id = $1`, branchID.String()).Scan(&high, &low); err != nil {
		t.Fatal(err)
	}
	if high != 0 || low != 1 {
		t.Fatalf("severity change not counted: high=%d low=%d", high, low)
	}

	// Closing it (status leaves the open set) still moves them.
	mustExec(`UPDATE findings SET status = 'resolved' WHERE id = $1`, findingID.String())
	if err := db.QueryRowContext(ctx,
		`SELECT findings_total FROM repository_branches WHERE id = $1`, branchID.String()).Scan(&high); err != nil {
		t.Fatal(err)
	}
	if high != 0 {
		t.Fatalf("status change not counted: findings_total=%d", high)
	}
}
