package postgres

import (
	"context"
	"database/sql"
	"os"
	"testing"

	_ "github.com/lib/pq"

	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/vulnerability"
	"github.com/openctemio/api/pkg/pagination"
)

// The finding-groups endpoint gained an "assigned to me" filter
// (FindingFilter.RelatedToUserID). "Mine" mirrors canMarkFixApplied's 3-way
// definition of relatedness: (1) direct assignee, (2) member of a group the
// finding is assigned to, (3) owner of the finding's asset. This test proves the
// predicate is applied before GROUP BY on more than one dimension: without the
// filter every group is returned; with it, only groups containing a finding
// related to the user survive — and each of the three relatedness paths counts.

func openGroupsDB(t *testing.T) *sql.DB {
	t.Helper()
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		t.Skip("DATABASE_URL not set; skipping finding-groups assigned-to-me DB test")
	}
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		t.Skipf("open db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.PingContext(context.Background()); err != nil {
		t.Skipf("cannot reach DATABASE_URL: %v", err)
	}
	return db
}

func seedGroupsUser(ctx context.Context, t *testing.T, db *sql.DB, email string) shared.ID {
	t.Helper()
	id := shared.NewID()
	if _, err := db.ExecContext(ctx,
		`INSERT INTO users (id, email, name) VALUES ($1, $2, $3)`,
		id.String(), id.String()+"@"+email, "u-"+id.String()); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	t.Cleanup(func() {
		_, _ = db.ExecContext(context.Background(), `DELETE FROM users WHERE id = $1`, id.String())
	})
	return id
}

func seedOwnedAsset(ctx context.Context, t *testing.T, db *sql.DB, tenantID shared.ID, ownerID *shared.ID) shared.ID {
	t.Helper()
	id := shared.NewID()
	var owner any
	if ownerID != nil {
		owner = ownerID.String()
	}
	if _, err := db.ExecContext(ctx,
		`INSERT INTO assets (id, tenant_id, name, asset_type, owner_id) VALUES ($1, $2, $3, 'host', $4)`,
		id.String(), tenantID.String(), "asset-"+id.String(), owner); err != nil {
		t.Fatalf("seed owned asset: %v", err)
	}
	return id
}

func seedGroupFinding(
	ctx context.Context, t *testing.T, db *sql.DB,
	tenantID, assetID shared.ID, cve, severity string, assignedTo *shared.ID,
) shared.ID {
	t.Helper()
	id := shared.NewID()
	var assignee any
	if assignedTo != nil {
		assignee = assignedTo.String()
	}
	if _, err := db.ExecContext(ctx, `
		INSERT INTO findings (id, tenant_id, asset_id, source, tool_name, message, severity, fingerprint, status, cve_id, assigned_to)
		VALUES ($1, $2, $3, 'va', 'test', 'msg', $4, $5, 'new', $6, $7)`,
		id.String(), tenantID.String(), assetID.String(), severity, id.String(), cve, assignee); err != nil {
		t.Fatalf("seed group finding: %v", err)
	}
	return id
}

// groupKeys collects the group_key values from a ListFindingGroups result.
func groupKeys(t *testing.T, res pagination.Result[*vulnerability.FindingGroup]) map[string]bool {
	t.Helper()
	keys := make(map[string]bool, len(res.Data))
	for _, g := range res.Data {
		keys[g.GroupKey] = true
	}
	return keys
}

func TestListFindingGroups_AssignedToMeFilter(t *testing.T) {
	ctx := context.Background()
	db := openGroupsDB(t)
	repo := NewFindingRepository(&DB{DB: db})

	tenantID := seedTestTenant(ctx, t, db)
	me := seedGroupsUser(ctx, t, db, "mine.test")
	other := seedGroupsUser(ctx, t, db, "other.test")

	assetOwnedByMe := seedOwnedAsset(ctx, t, db, tenantID, &me)
	assetOwnedByOther := seedOwnedAsset(ctx, t, db, tenantID, &other)

	// A group "me" belongs to; used to prove the group-membership path.
	groupID := shared.NewID()
	if _, err := db.ExecContext(ctx,
		`INSERT INTO groups (id, tenant_id, name, slug, is_active) VALUES ($1, $2, $3, $4, true)`,
		groupID.String(), tenantID.String(), "grp-"+groupID.String(), "grp-"+groupID.String()); err != nil {
		t.Fatalf("seed group: %v", err)
	}
	if _, err := db.ExecContext(ctx,
		`INSERT INTO group_members (group_id, user_id) VALUES ($1, $2)`,
		groupID.String(), me.String()); err != nil {
		t.Fatalf("seed group member: %v", err)
	}

	const (
		cveAssignee = "CVE-2099-0001" // mine via direct assignee
		cveOwner    = "CVE-2099-0002" // mine via asset owner
		cveGroup    = "CVE-2099-0003" // mine via assigned-group membership
		cveOther    = "CVE-2099-0004" // NOT mine
	)

	// (1) direct assignee — asset owned by someone else, high severity.
	seedGroupFinding(ctx, t, db, tenantID, assetOwnedByOther, cveAssignee, "high", &me)
	// (2) asset owner — no assignee, high severity.
	seedGroupFinding(ctx, t, db, tenantID, assetOwnedByMe, cveOwner, "high", nil)
	// (3) group membership — asset owned by other, assigned to a group "me" is in.
	fGroup := seedGroupFinding(ctx, t, db, tenantID, assetOwnedByOther, cveGroup, "high", nil)
	if _, err := db.ExecContext(ctx,
		`INSERT INTO finding_group_assignments (tenant_id, finding_id, group_id) VALUES ($1, $2, $3)`,
		tenantID.String(), fGroup.String(), groupID.String()); err != nil {
		t.Fatalf("seed finding_group_assignment: %v", err)
	}
	// (4) unrelated — owned by other, assigned to other, LOW severity so it also
	// shows up as its own severity group.
	seedGroupFinding(ctx, t, db, tenantID, assetOwnedByOther, cveOther, "low", &other)

	page := pagination.New(1, 100)

	// --- group_by cve_id ---
	all, err := repo.ListFindingGroups(ctx, tenantID, "cve_id", vulnerability.FindingFilter{}, page)
	if err != nil {
		t.Fatalf("cve groups (no filter): %v", err)
	}
	allKeys := groupKeys(t, all)
	for _, want := range []string{cveAssignee, cveOwner, cveGroup, cveOther} {
		if !allKeys[want] {
			t.Fatalf("without filter, expected cve group %q present; got %v", want, allKeys)
		}
	}

	mineFilter := vulnerability.FindingFilter{RelatedToUserID: &me}
	mine, err := repo.ListFindingGroups(ctx, tenantID, "cve_id", mineFilter, page)
	if err != nil {
		t.Fatalf("cve groups (assigned_to_me): %v", err)
	}
	mineKeys := groupKeys(t, mine)
	for _, want := range []string{cveAssignee, cveOwner, cveGroup} {
		if !mineKeys[want] {
			t.Errorf("with assigned_to_me, expected mine cve group %q present (relatedness path missing); got %v", want, mineKeys)
		}
	}
	if mineKeys[cveOther] {
		t.Errorf("with assigned_to_me, unrelated cve group %q must be excluded; got %v", cveOther, mineKeys)
	}

	// --- group_by severity: proves the predicate applies to another dimension ---
	// Only the unrelated finding is 'low'. With the filter, 'low' must vanish.
	allSev, err := repo.ListFindingGroups(ctx, tenantID, "severity", vulnerability.FindingFilter{}, page)
	if err != nil {
		t.Fatalf("severity groups (no filter): %v", err)
	}
	allSevKeys := groupKeys(t, allSev)
	if !allSevKeys["high"] || !allSevKeys["low"] {
		t.Fatalf("without filter, expected both high and low severity groups; got %v", allSevKeys)
	}

	mineSev, err := repo.ListFindingGroups(ctx, tenantID, "severity", mineFilter, page)
	if err != nil {
		t.Fatalf("severity groups (assigned_to_me): %v", err)
	}
	mineSevKeys := groupKeys(t, mineSev)
	if !mineSevKeys["high"] {
		t.Errorf("with assigned_to_me, 'high' severity group (mine findings) must remain; got %v", mineSevKeys)
	}
	if mineSevKeys["low"] {
		t.Errorf("with assigned_to_me, 'low' severity group (only unrelated finding) must be excluded; got %v", mineSevKeys)
	}
}
