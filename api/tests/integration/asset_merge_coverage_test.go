package integration

import (
	"context"
	"database/sql"
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// assetReferenceColumns lists every "table.column" that refers to assets.id in
// the migrated schema: foreign keys, plus *asset_id / *asset_ids columns that
// carry asset ids without one.
func assetReferenceColumns(t *testing.T, db *sql.DB) map[string]string {
	t.Helper()
	rows, err := db.Query(`
		SELECT c.conrelid::regclass::text || '.' || a.attname,
		       CASE c.confdeltype WHEN 'c' THEN 'fk cascade' WHEN 'n' THEN 'fk set null' ELSE 'fk' END
		FROM pg_constraint c
		-- The referencing column paired with assets.id: the only column of a
		-- single-column key, the asset column of a composite (tenant_id, asset)
		-- key (migration 000921).
		JOIN pg_attribute a ON a.attrelid = c.conrelid
		 AND a.attnum = c.conkey[array_position(c.confkey, (SELECT attnum FROM pg_attribute WHERE attrelid = 'assets'::regclass AND attname = 'id'))]
		WHERE c.contype = 'f' AND c.confrelid = 'assets'::regclass
		UNION
		SELECT col.table_name || '.' || col.column_name, 'no fk'
		FROM information_schema.columns col
		JOIN information_schema.tables tb ON tb.table_schema = col.table_schema AND tb.table_name = col.table_name
		WHERE col.table_schema = 'public' AND tb.table_type = 'BASE TABLE'
		  AND (col.column_name LIKE '%asset_id' OR col.column_name LIKE '%asset_ids')
		  AND col.udt_name IN ('uuid', '_uuid')
		  AND NOT EXISTS (
			SELECT 1 FROM pg_constraint k
			JOIN pg_attribute ka ON ka.attrelid = k.conrelid AND ka.attnum = ANY(k.conkey)
			WHERE k.contype = 'f' AND k.conrelid::regclass::text = col.table_name AND ka.attname = col.column_name)`)
	if err != nil {
		t.Fatalf("list asset references: %v", err)
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var ref, kind string
		if err := rows.Scan(&ref, &kind); err != nil {
			t.Fatal(err)
		}
		out[ref] = kind
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

// Every column that refers to an asset must be handled by the merge, and every
// table the merge names must exist. A new table that references assets fails
// here until asset_merge_plan.go says what a merge does with it; before this,
// rows in tables the merge forgot were deleted by ON DELETE CASCADE, and two
// tables it named had been dropped (the error was swallowed).
func TestAssetMergeCoversEveryAssetReference(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	schema := assetReferenceColumns(t, db)
	handled := postgres.AssetMergeReferenceHandling()
	// Columns named *asset_id that do not hold ids of rows in assets.
	notAssetIDs := map[string]bool{}

	var missing, stale []string
	for ref, kind := range schema {
		if _, ok := handled[ref]; !ok && !notAssetIDs[ref] {
			missing = append(missing, ref+" ("+kind+")")
		}
	}
	for ref := range handled {
		if _, ok := schema[ref]; !ok {
			stale = append(stale, ref)
		}
	}
	sort.Strings(missing)
	sort.Strings(stale)
	if len(missing) > 0 {
		t.Errorf("asset merge does not handle these references; add them to asset_merge_plan.go:\n  %v", missing)
	}
	if len(stale) > 0 {
		t.Errorf("asset merge names references that are not in the schema:\n  %v", stale)
	}
}

// A merge loses nothing: one row in every table that references the merged
// asset ends up on the kept asset, except rows whose unique key the kept asset
// already has.
func TestApproveAndMerge_MovesEveryReference(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()
	ctx := context.Background()

	tenant := createTestTenant(t, db, "mergeall")
	keep := createTestAsset(t, db, tenant, "keep-mergeall")
	merge := createTestAsset(t, db, tenant, "merge-mergeall")
	other := createTestAsset(t, db, tenant, "other-mergeall")
	child := createTestAsset(t, db, tenant, "child-mergeall")
	user := shared.NewID()

	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := db.Exec(q, args...); err != nil {
			t.Fatalf("seed: %v\n%s", err, q)
		}
	}
	T, M, K, O, U := tenant.String(), merge.String(), keep.String(), other.String(), user.String()
	exec(`INSERT INTO users (id, email, name) VALUES ($1, $2, 'merge test')`, U, "merge-"+U+"@example.test")

	// Parents of the referencing rows.
	ids := map[string]string{}
	newID := func(k string) string { ids[k] = shared.NewID().String(); return ids[k] }
	exec(`INSERT INTO groups (id, tenant_id, name, slug) VALUES ($1,$2,'g',md5(random()::text))`, newID("group"), T)
	exec(`INSERT INTO business_units (id, tenant_id, name) VALUES ($1,$2,'bu')`, newID("bu"), T)
	exec(`INSERT INTO business_services (id, tenant_id, name) VALUES ($1,$2,'svc')`, newID("svc"), T)
	exec(`INSERT INTO asset_groups (id, tenant_id, name) VALUES ($1,$2,'ag')`, newID("ag"), T)
	exec(`INSERT INTO compensating_controls (id, tenant_id, name, control_type) VALUES ($1,$2,'cc','other')`, newID("cc"), T)
	exec(`INSERT INTO attack_paths (id, tenant_id, name) VALUES ($1,$2,'ap')`, newID("ap"), T)
	exec(`INSERT INTO threat_models (id, tenant_id, scope_type, name) VALUES ($1,$2,'tenant','tm')`, newID("tm"), T)
	exec(`INSERT INTO scan_workflows (id, tenant_id, name) VALUES ($1,$2,'pt')`, newID("pt"), T)
	exec(`INSERT INTO components (id, purl, name, ecosystem) VALUES ($1,'pkg:npm/m-'||md5(random()::text),'m','npm')`, newID("comp"))

	// One row per reference for the merged asset ($2); where noted, the kept
	// asset ($3) already holds the same unique key, so the merged row is
	// dropped instead of moved.
	seeds := []string{
		`INSERT INTO findings (tenant_id, asset_id, source, tool_name, message, severity, fingerprint) VALUES ($1,$2,'sast','t','m','low',md5(random()::text))`,
		`INSERT INTO exposures (tenant_id, asset_id, title, category, severity) VALUES ($1,$2,'e','c','low')`,
		`INSERT INTO suppression_rules (tenant_id, name, requested_by, asset_id) VALUES ($1,'s',$4,$2)`,
		`INSERT INTO sla_policies (tenant_id, name, asset_id) VALUES ($1,md5(random()::text),$2)`,
		`INSERT INTO exposure_events (tenant_id, event_type, title, fingerprint, source, asset_id) VALUES ($1,'port_open','t',md5(random()::text),'s',$2)`,
		`INSERT INTO runtime_telemetry_events (tenant_id, event_type, observed_at, endpoint_asset_id) VALUES ($1,'process_start',NOW(),$2)`,
		`INSERT INTO asset_owners (asset_id, user_id, ownership_type) VALUES ($2,$4,'primary')`,
		`INSERT INTO asset_owners (asset_id, user_id, ownership_type) VALUES ($3,$4,'primary')`, // conflict
		`INSERT INTO user_accessible_assets (user_id, tenant_id, asset_id) VALUES ($4,$1,$2)`,
		`INSERT INTO scan_coverage_state (asset_id, tenant_id, last_dispatched_at) VALUES ($2,$1,NOW())`,
		`INSERT INTO scan_coverage_state (asset_id, tenant_id, last_dispatched_at) VALUES ($3,$1,NOW())`, // conflict
		`INSERT INTO asset_services (tenant_id, asset_id, port, protocol) VALUES ($1,$2,8080,'tcp')`,
		`INSERT INTO relationship_suggestions (tenant_id, source_asset_id, target_asset_id, relationship_type, reason) VALUES ($1,$2,$5,'depends_on','r')`,
		`INSERT INTO relationship_suggestions (tenant_id, source_asset_id, target_asset_id, relationship_type, reason) VALUES ($1,$2,$3,'depends_on','r')`, // loop
		`INSERT INTO asset_relationships (tenant_id, source_asset_id, target_asset_id, relationship_type) VALUES ($1,$5,$2,'depends_on')`,
		`UPDATE assets SET parent_id = $2 WHERE id = $6`,
	}
	// The seeds share one set of ids; they are inlined as literals because
	// each statement uses a different subset.
	lit := strings.NewReplacer("$1", "'"+T+"'", "$2", "'"+M+"'", "$3", "'"+K+"'",
		"$4", "'"+U+"'", "$5", "'"+O+"'", "$6", "'"+child.String()+"'")
	for _, q := range seeds {
		exec(lit.Replace(q))
	}
	exec(`INSERT INTO asset_owners (asset_id, group_id, ownership_type) VALUES ($1,$2,'secondary')`, M, ids["group"])
	exec(`INSERT INTO business_unit_assets (id, tenant_id, business_unit_id, asset_id) VALUES ($1,$2,$3,$4)`, shared.NewID().String(), T, ids["bu"], M)
	exec(`INSERT INTO business_service_assets (tenant_id, service_id, asset_id) VALUES ($1,$2,$3)`, T, ids["svc"], M)
	exec(`INSERT INTO asset_group_members (asset_group_id, asset_id) VALUES ($1,$2)`, ids["ag"], M)
	exec(`INSERT INTO compensating_control_assets (control_id, asset_id) VALUES ($1,$2)`, ids["cc"], M)
	exec(`INSERT INTO attack_path_nodes (attack_path_id, asset_id, node_order, node_type) VALUES ($1,$2,1,'entry')`, ids["ap"], M)
	exec(`INSERT INTO threat_model_threats (tenant_id, threat_model_id, entry_point_asset_id, hop_asset_id, target_asset_id) VALUES ($1,$2,$3,$3,$3)`, T, ids["tm"], M)
	exec(`INSERT INTO scan_runs (tenant_id, scan_workflow_id, trigger_type, asset_id) VALUES ($1,$2,'manual',$3)`, T, ids["pt"], M)
	exec(`INSERT INTO asset_components (tenant_id, asset_id, component_id, path, name, ecosystem) VALUES ($1,$2,$3,'/m','m','npm')`, T, M, ids["comp"])
	exec(`INSERT INTO pentest_campaigns (tenant_id, name, asset_ids) VALUES ($1,'pc',$2)`, T, pq.Array([]string{M, O}))

	// Repository data: the merged repo has branches main (the kept repo has
	// one too) and feature; a finding sits on its main.
	exec(`INSERT INTO asset_repositories (asset_id, full_name) VALUES ($1,'github.com/acme/merged')`, M)
	exec(`INSERT INTO asset_repositories (asset_id, full_name) VALUES ($1,'github.com/acme/kept')`, K)
	exec(`INSERT INTO repository_branches (id, repository_id, name) VALUES ($1,$2,'main')`, newID("kmain"), K)
	exec(`INSERT INTO repository_branches (id, repository_id, name) VALUES ($1,$2,'main')`, newID("mmain"), M)
	exec(`INSERT INTO repository_branches (id, repository_id, name) VALUES ($1,$2,'feature')`, newID("mfeat"), M)
	exec(`UPDATE findings SET branch_id = $1 WHERE asset_id = $2`, ids["mmain"], M)

	// A stale pending review about the merged asset.
	exec(`INSERT INTO asset_dedup_review (tenant_id, normalized_name, asset_type, keep_asset_id, keep_asset_name, merge_asset_ids, merge_asset_names, status)
		VALUES ($1,'x','host',$2,'x',$3,$4,'pending')`, T, O, pq.Array([]string{M}), pq.Array([]string{"merge-mergeall"}))

	reviewID := shared.NewID().String()
	exec(`INSERT INTO asset_dedup_review (id, tenant_id, normalized_name, asset_type, keep_asset_id, keep_asset_name, merge_asset_ids, merge_asset_names, status)
		VALUES ($1,$2,'keep','repository',$3,'keep',$4,$5,'pending')`, reviewID, T, K, pq.Array([]string{M}), pq.Array([]string{"merge-mergeall"}))

	repo := postgres.NewAssetDedupRepository(&postgres.DB{DB: db})
	if err := repo.ApproveAndMerge(ctx, T, reviewID, U, nil); err != nil {
		t.Fatalf("ApproveAndMerge: %v", err)
	}

	count := func(q string, args ...any) int {
		t.Helper()
		var n int
		if err := db.QueryRow(q, args...).Scan(&n); err != nil {
			t.Fatalf("count: %v\n%s", err, q)
		}
		return n
	}

	// Nothing references the merged asset any more.
	for ref := range assetReferenceColumns(t, db) {
		table, col, _ := strings.Cut(ref, ".")
		if table == "asset_merge_log" || table == "asset_dedup_review" {
			continue
		}
		var q string
		if strings.HasSuffix(col, "_ids") {
			q = fmt.Sprintf(`SELECT count(*) FROM %s WHERE $1::uuid = ANY(%s)`, table, col) //nolint:gosec // test-only, names from the catalog
		} else {
			q = fmt.Sprintf(`SELECT count(*) FROM %s WHERE %s = $1::uuid`, table, col) //nolint:gosec // test-only, names from the catalog
		}
		if n := count(q, M); n != 0 {
			t.Errorf("%s still references the merged asset (%d rows)", ref, n)
		}
	}

	// And it all landed on the kept asset.
	want := map[string]int{
		`SELECT count(*) FROM findings WHERE asset_id = $1`:                                                                        1,
		`SELECT count(*) FROM exposures WHERE asset_id = $1`:                                                                       1,
		`SELECT count(*) FROM suppression_rules WHERE asset_id = $1`:                                                               1,
		`SELECT count(*) FROM sla_policies WHERE asset_id = $1`:                                                                    1,
		`SELECT count(*) FROM exposure_events WHERE asset_id = $1`:                                                                 1,
		`SELECT count(*) FROM runtime_telemetry_events WHERE endpoint_asset_id = $1`:                                               1,
		`SELECT count(*) FROM scan_runs WHERE asset_id = $1`:                                                                       1,
		`SELECT count(*) FROM attack_path_nodes WHERE asset_id = $1`:                                                               1,
		`SELECT count(*) FROM threat_model_threats WHERE entry_point_asset_id = $1 AND hop_asset_id = $1 AND target_asset_id = $1`: 1,
		`SELECT count(*) FROM asset_owners WHERE asset_id = $1`:                                                                    2, // user (kept's own) + group
		`SELECT count(*) FROM user_accessible_assets WHERE asset_id = $1`:                                                          1,
		`SELECT count(*) FROM scan_coverage_state WHERE asset_id = $1`:                                                             1,
		`SELECT count(*) FROM asset_services WHERE asset_id = $1`:                                                                  1,
		`SELECT count(*) FROM business_unit_assets WHERE asset_id = $1`:                                                            1,
		`SELECT count(*) FROM business_service_assets WHERE asset_id = $1`:                                                         1,
		`SELECT count(*) FROM asset_group_members WHERE asset_id = $1`:                                                             1,
		`SELECT count(*) FROM compensating_control_assets WHERE asset_id = $1`:                                                     1,
		`SELECT count(*) FROM asset_components WHERE asset_id = $1`:                                                                1,
		`SELECT count(*) FROM relationship_suggestions WHERE source_asset_id = $1`:                                                 1, // loop dropped
		`SELECT count(*) FROM asset_relationships WHERE target_asset_id = $1`:                                                      1,
		`SELECT count(*) FROM assets WHERE parent_id = $1`:                                                                         1,
		`SELECT count(*) FROM pentest_campaigns WHERE $1::uuid = ANY(asset_ids)`:                                                   1,
		`SELECT count(*) FROM repository_branches WHERE repository_id = $1`:                                                        2, // main + feature
	}
	for q, n := range want {
		if got := count(q, K); got != n {
			t.Errorf("%s = %d, want %d", q, got, n)
		}
	}
	if got := count(`SELECT count(*) FROM findings WHERE asset_id = $1 AND branch_id = $2`, K, ids["kmain"]); got != 1 {
		t.Errorf("finding on the merged repo's main branch should move to the kept repo's main, got %d", got)
	}
	if got := count(`SELECT count(*) FROM asset_dedup_review WHERE tenant_id = $1 AND status = 'pending'`, T); got != 0 {
		t.Errorf("stale pending review about the merged asset was kept (%d pending)", got)
	}
	if got := count(`SELECT count(*) FROM assets WHERE id = $1`, M); got != 0 {
		t.Errorf("merged asset still exists")
	}

	_, _ = db.Exec(`DELETE FROM tenants WHERE id = $1`, T)
	_, _ = db.Exec(`DELETE FROM components WHERE id = $1`, ids["comp"])
	_, _ = db.Exec(`DELETE FROM users WHERE id = $1`, U)
}
