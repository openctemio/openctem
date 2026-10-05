package postgres

import (
	"context"
	"database/sql"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/api/pkg/pagination"
)

// The findings list page query is a deferred join (filter/sort/paginate over
// ids, then load the wide rows for the page only). These tests pin that the
// rewrite is purely a performance change: tenant isolation, data scope
// (fail-open and strict), pagination/total and the default CTEM ordering are
// exactly what the single-query form produced.

func TestBuildFindingPageQuery_FilterSortAndPageLiveInSubquery(t *testing.T) {
	q := buildFindingPageQuery("SELECT id, title FROM findings", "tenant_id = $1", "created_at DESC", 20, 40)

	want := "SELECT id, title FROM findings WHERE findings.id IN (" +
		"SELECT id FROM findings WHERE tenant_id = $1 ORDER BY created_at DESC LIMIT 20 OFFSET 40" +
		") ORDER BY created_at DESC"
	if q != want {
		t.Fatalf("unexpected page query:\n got: %s\nwant: %s", q, want)
	}

	// No filter: still paginated inside the subquery.
	q = buildFindingPageQuery("SELECT id FROM findings", "", "created_at DESC", 10, 0)
	if !strings.Contains(q, "(SELECT id FROM findings ORDER BY created_at DESC LIMIT 10 OFFSET 0)") {
		t.Fatalf("unfiltered page query must paginate in the subquery: %s", q)
	}
}

func seedListFinding(ctx context.Context, t *testing.T, db *sql.DB, tenantID, assetID shared.ID, severity, priority string) shared.ID {
	t.Helper()
	id := shared.NewID()
	var prio any
	if priority != "" {
		prio = priority
	}
	if _, err := db.ExecContext(ctx, `
		INSERT INTO findings (id, tenant_id, asset_id, source, tool_name, message, severity, fingerprint, status, priority_class)
		VALUES ($1, $2, $3, 'sca', 'test', 'msg', $4, $5, 'new', $6)`,
		id.String(), tenantID.String(), assetID.String(), severity, id.String(), prio); err != nil {
		t.Fatalf("seed finding: %v", err)
	}
	return id
}

func listIDs(res pagination.Result[*vulnerability.Finding]) []string {
	out := make([]string, 0, len(res.Data))
	for _, f := range res.Data {
		out = append(out, f.ID().String())
	}
	return out
}

func TestFindingList_DeferredJoinKeepsIsolationScopeAndOrder(t *testing.T) {
	ctx := context.Background()
	db := openGroupsDB(t)
	repo := NewFindingRepository(&DB{DB: db})

	tenantA := seedTestTenant(ctx, t, db)
	tenantB := seedTestTenant(ctx, t, db)
	assetA1 := seedOwnedAsset(ctx, t, db, tenantA, nil)
	assetA2 := seedOwnedAsset(ctx, t, db, tenantA, nil)
	assetB := seedOwnedAsset(ctx, t, db, tenantB, nil)

	// Tenant A: 5 findings with a known default (CTEM) order:
	// P0 critical, P0 low, P1 high, P2 medium, (no priority) critical.
	p0crit := seedListFinding(ctx, t, db, tenantA, assetA1, "critical", "P0")
	p0low := seedListFinding(ctx, t, db, tenantA, assetA2, "low", "P0")
	p1high := seedListFinding(ctx, t, db, tenantA, assetA1, "high", "P1")
	p2med := seedListFinding(ctx, t, db, tenantA, assetA2, "medium", "P2")
	noPrio := seedListFinding(ctx, t, db, tenantA, assetA1, "critical", "")
	// Tenant B: must never leak into tenant A's list.
	leak := seedListFinding(ctx, t, db, tenantB, assetB, "critical", "P0")

	filterA := vulnerability.NewFindingFilter().WithTenantID(tenantA)

	// --- default order + tenant isolation ---
	all, err := repo.List(ctx, filterA, vulnerability.FindingListOptions{}, pagination.New(1, 100))
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	want := []string{p0crit.String(), p0low.String(), p1high.String(), p2med.String(), noPrio.String()}
	got := listIDs(all)
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("default CTEM order changed:\n got %v\nwant %v", got, want)
	}
	if all.Total != 5 {
		t.Fatalf("total: want 5, got %d", all.Total)
	}
	for _, id := range got {
		if id == leak.String() {
			t.Fatal("tenant B finding leaked into tenant A list")
		}
	}

	// --- pagination: pages are the ordered slices, total is the full count ---
	p1, err := repo.List(ctx, filterA, vulnerability.FindingListOptions{}, pagination.New(1, 2))
	if err != nil {
		t.Fatalf("page 1: %v", err)
	}
	p2, err := repo.List(ctx, filterA, vulnerability.FindingListOptions{}, pagination.New(2, 2))
	if err != nil {
		t.Fatalf("page 2: %v", err)
	}
	p3, err := repo.List(ctx, filterA, vulnerability.FindingListOptions{}, pagination.New(3, 2))
	if err != nil {
		t.Fatalf("page 3: %v", err)
	}
	paged := append(append(listIDs(p1), listIDs(p2)...), listIDs(p3)...)
	if strings.Join(paged, ",") != strings.Join(want, ",") {
		t.Fatalf("paged order mismatch:\n got %v\nwant %v", paged, want)
	}
	if p1.Total != 5 || p2.Total != 5 || p3.Total != 5 {
		t.Fatalf("total must be the full match count on every page: %d %d %d", p1.Total, p2.Total, p3.Total)
	}

	// --- data scope: a user scoped to assetA2 sees only assetA2's findings ---
	scoped := seedGroupsUser(ctx, t, db, "scope.test")
	if _, err := db.ExecContext(ctx,
		`INSERT INTO user_accessible_assets (user_id, tenant_id, asset_id) VALUES ($1, $2, $3)`,
		scoped.String(), tenantA.String(), assetA2.String()); err != nil {
		t.Fatalf("seed accessible asset: %v", err)
	}
	scopedFilter := filterA
	scopedFilter.DataScopeUserID = &scoped
	res, err := repo.List(ctx, scopedFilter, vulnerability.FindingListOptions{}, pagination.New(1, 100))
	if err != nil {
		t.Fatalf("scoped list: %v", err)
	}
	if strings.Join(listIDs(res), ",") != p0low.String()+","+p2med.String() || res.Total != 2 {
		t.Fatalf("data scope not applied: got %v total=%d", listIDs(res), res.Total)
	}

	// --- a user with no scope row sees nothing (always fail closed) ---
	unassigned := seedGroupsUser(ctx, t, db, "noscope.test")
	noScopeFilter := filterA
	noScopeFilter.DataScopeUserID = &unassigned
	res, err = repo.List(ctx, noScopeFilter, vulnerability.FindingListOptions{}, pagination.New(1, 100))
	if err != nil {
		t.Fatalf("no-scope list: %v", err)
	}
	if res.Total != 0 || len(res.Data) != 0 {
		t.Fatalf("unassigned user must see nothing, got %d/%d", len(res.Data), res.Total)
	}
}
