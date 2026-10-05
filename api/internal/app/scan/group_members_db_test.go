package scan_test

// A group scan resolves its members as assets, by id, against the real
// database and the real scope service: an archived member is not scanned, a
// member whose address is in an excluded network is excluded although its
// name is not, and a membership row pointing at another tenant's asset never
// reaches a scanner.

import (
	"context"
	"database/sql"
	"slices"
	"strings"
	"testing"

	_ "github.com/lib/pq"

	scanapp "github.com/openctemio/openctem/api/internal/app/scan"
	"github.com/openctemio/openctem/api/internal/app/scope"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/domain/assetgroup"
	"github.com/openctemio/openctem/api/pkg/domain/scan"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/tool"
	"github.com/openctemio/openctem/api/pkg/logger"
)

func openGroupMembersDB(t *testing.T) *postgres.DB {
	t.Helper()
	dbURL := testdb.URL()
	if dbURL == "" {
		t.Skip("DATABASE_URL not set; skipping group scan member DB test")
	}
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		t.Skipf("open db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.PingContext(context.Background()); err != nil {
		t.Skipf("cannot reach DATABASE_URL: %v", err)
	}
	return &postgres.DB{DB: db}
}

func TestResolveScanTargets_GroupMembersByAsset_DB(t *testing.T) {
	ctx := context.Background()
	db := openGroupMembersDB(t)

	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := db.ExecContext(ctx, q, args...); err != nil {
			t.Fatalf("%s: %v", strings.Fields(q)[0]+" "+strings.Fields(q)[2], err)
		}
	}
	newTenant := func() shared.ID {
		id := shared.NewID()
		exec(`INSERT INTO tenants (id, name, slug) VALUES ($1, 'group scan members', $2)`, id.String(), "gsm-"+id.String())
		t.Cleanup(func() { _, _ = db.ExecContext(context.Background(), `DELETE FROM tenants WHERE id = $1`, id.String()) })
		return id
	}
	tenant, other := newTenant(), newTenant()

	groupID := shared.NewID()
	exec(`INSERT INTO asset_groups (id, tenant_id, name) VALUES ($1, $2, 'web')`, groupID.String(), tenant.String())
	member := func(tenantID shared.ID, name, status, props string) {
		t.Helper()
		id := shared.NewID()
		exec(`INSERT INTO assets (id, tenant_id, name, asset_type, status, properties) VALUES ($1, $2, $3, 'domain', $4, $5::jsonb)`,
			id.String(), tenantID.String(), name, status, props)
		exec(`INSERT INTO asset_group_members (asset_group_id, asset_id) VALUES ($1, $2)`, groupID.String(), id.String())
	}
	member(tenant, "app.example.com", "active", `{}`)
	member(tenant, "stale.example.com", "stale", `{}`)
	member(tenant, "old.example.com", "archived", `{}`)
	member(tenant, "db.example.com", "active", `{"ip_addresses": ["10.9.9.20"]}`)
	member(tenant, "legacy.example.com", "active", `{"ip": "10.9.9.21"}`)
	member(other, "foreign.example.org", "active", `{}`)

	// An approved exclusion of the network db and legacy resolve to.
	exec(`INSERT INTO scope_exclusions (tenant_id, exclusion_type, pattern, reason, status, approved_by, approved_at)
		VALUES ($1, 'cidr', '10.9.9.0/24', 'payment network', 'active', 'approver', NOW())`, tenant.String())

	svc := scanapp.NewGroupResolverForTest(
		postgres.NewAssetGroupRepository(db),
		scope.NewService(nil, postgres.NewScopeExclusionRepository(db), nil, logger.NewNop()))
	sc := &scan.Scan{ID: shared.NewID(), TenantID: tenant, Name: "web", ScannerName: "nuclei"}
	sc.SetAssetGroupIDs([]shared.ID{groupID})

	got, err := svc.ResolveScanTargetsForTest(ctx, sc)
	if err != nil {
		t.Fatal(err)
	}
	slices.Sort(got.Targets)
	want := []string{"app.example.com", "stale.example.com"}
	if !slices.Equal(got.Targets, want) {
		t.Fatalf("dispatched %v, want %v (archived, address-excluded and other-tenant members must not be scanned)", got.Targets, want)
	}
	slices.Sort(got.ExcludedNames)
	if !slices.Equal(got.ExcludedNames, []string{"db.example.com", "legacy.example.com"}) {
		t.Fatalf("excluded %v, want the two members whose address is in the excluded network", got.ExcludedNames)
	}
	if got.Archived != 1 {
		t.Fatalf("archived = %d, want 1", got.Archived)
	}
	if got.RunContext["archived_target_count"] != 1 {
		t.Fatalf("run context archived_target_count = %v, want 1", got.RunContext["archived_target_count"])
	}

	// Another tenant's scan naming this group reads nothing from it.
	foreign := &scan.Scan{ID: shared.NewID(), TenantID: other, Name: "x", ScannerName: "nuclei"}
	foreign.SetAssetGroupIDs([]shared.ID{groupID})
	got, err = svc.ResolveScanTargetsForTest(ctx, foreign)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Targets) != 0 {
		t.Fatalf("another tenant's scan resolved %v from this tenant's group", got.Targets)
	}

	// Keyset paging returns every member exactly once.
	repo := postgres.NewAssetGroupRepository(db)
	q := assetgroup.ScanMemberQuery{TenantID: tenant, GroupID: groupID, Limit: 1}
	var names []string
	for {
		page, err := repo.ListScanMembers(ctx, q)
		if err != nil {
			t.Fatal(err)
		}
		if len(page.Members) == 0 {
			break
		}
		for _, m := range page.Members {
			names = append(names, m.Name)
		}
		last := page.Members[len(page.Members)-1]
		q.AfterName, q.AfterID = last.Name, last.ID
	}
	wantNames := []string{"app.example.com", "db.example.com", "legacy.example.com", "stale.example.com"}
	if !slices.Equal(names, wantNames) {
		t.Fatalf("paged members %v, want %v", names, wantNames)
	}
}

// RFC-042 §6.3.8 O6 against the real database: a group member is dispatched
// to a single scanner only when the registry says the scanner can scan its
// stored (type, sub_type); the run records what was left out, and a member
// of another tenant is never read.
func TestResolveScanTargets_ScannerTypeGate_DB(t *testing.T) {
	ctx := context.Background()
	db := openGroupMembersDB(t)
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := db.ExecContext(ctx, q, args...); err != nil {
			t.Fatalf("%s: %v", strings.Fields(q)[0]+" "+strings.Fields(q)[2], err)
		}
	}
	newTenant := func() shared.ID {
		id := shared.NewID()
		exec(`INSERT INTO tenants (id, name, slug) VALUES ($1, 'scanner type gate', $2)`, id.String(), "stg-"+id.String())
		t.Cleanup(func() { _, _ = db.ExecContext(context.Background(), `DELETE FROM tenants WHERE id = $1`, id.String()) })
		return id
	}
	tenant, other := newTenant(), newTenant()

	tools := postgres.NewToolRepository(db)
	id := shared.NewID().String()
	urlTool, err := tool.NewTool("o6-url-"+id[len(id)-12:], "URL scanner", nil, tool.InstallGo)
	if err != nil {
		t.Fatal(err)
	}
	urlTool.SupportedTargets = []string{"url"}
	if err := tools.Create(ctx, urlTool); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = db.ExecContext(context.Background(), `DELETE FROM tools WHERE id = $1`, urlTool.ID.String())
	})

	groupID := shared.NewID()
	exec(`INSERT INTO asset_groups (id, tenant_id, name) VALUES ($1, $2, 'mixed')`, groupID.String(), tenant.String())
	member := func(tenantID shared.ID, name, typ, sub string) {
		t.Helper()
		id := shared.NewID()
		exec(`INSERT INTO assets (id, tenant_id, name, asset_type, sub_type) VALUES ($1, $2, $3, $4, NULLIF($5, ''))`,
			id.String(), tenantID.String(), name, typ, sub)
		exec(`INSERT INTO asset_group_members (asset_group_id, asset_id) VALUES ($1, $2)`, groupID.String(), id.String())
	}
	member(tenant, "https://app.example.com", "application", "website")
	member(tenant, "https://m.example.com", "application", "mobile_app")
	member(tenant, "github.com/acme/app", "repository", "")
	member(other, "https://foreign.example.org", "application", "website")

	svc := scanapp.NewGroupResolverForTest(postgres.NewAssetGroupRepository(db), nil).WithToolRepoForTest(tools)
	sc := &scan.Scan{ID: shared.NewID(), TenantID: tenant, Name: "mixed", ScannerName: urlTool.Name}
	sc.SetAssetGroupIDs([]shared.ID{groupID})

	got, err := svc.ResolveScanTargetsForTest(ctx, sc)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(got.Targets, []string{"https://app.example.com"}) {
		t.Fatalf("dispatched %v, want only the web application", got.Targets)
	}
	if got.RunContext["incompatible_target_count"] != 2 {
		t.Fatalf("incompatible_target_count = %v, want 2", got.RunContext["incompatible_target_count"])
	}
	types, _ := got.RunContext[scanapp.RunContextKeyTargetTypes].(map[string]string)
	if types["https://app.example.com"] != "application/website" || len(types) != 1 {
		t.Fatalf("target types = %v", types)
	}

	// Only incompatible members: the run is refused with a clear error.
	onlyRepo := shared.NewID()
	exec(`INSERT INTO asset_groups (id, tenant_id, name) VALUES ($1, $2, 'code')`, onlyRepo.String(), tenant.String())
	exec(`INSERT INTO asset_group_members (asset_group_id, asset_id)
		SELECT $1, id FROM assets WHERE tenant_id = $2 AND asset_type = 'repository'`, onlyRepo.String(), tenant.String())
	sc2 := &scan.Scan{ID: shared.NewID(), TenantID: tenant, Name: "code", ScannerName: urlTool.Name}
	sc2.SetAssetGroupIDs([]shared.ID{onlyRepo})
	r, err := svc.ResolveScanTargetsForTest(ctx, sc2)
	if err == nil {
		t.Fatalf("expected NO_COMPATIBLE_TARGETS, got %v", r)
	}
	if !strings.Contains(err.Error(), "cannot scan 1 repository") {
		t.Fatalf("err = %v", err)
	}
}
