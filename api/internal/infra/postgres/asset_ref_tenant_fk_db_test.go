package postgres

// Composite tenant foreign keys on asset references (migrations 000920-000922,
// research doc 21b P1-1): the database refuses a row of one tenant that points
// at another tenant's asset, whatever code writes it, and keeps each table's
// ON DELETE action.

import (
	"context"
	"database/sql"
	"os"
	"strings"
	"testing"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// assetRefTables are every table the migrations constrain, plus assets.
var assetRefTables = []string{
	"assets", "asset_access_grants", "asset_attributions", "asset_components", "asset_identifiers",
	"asset_relationships", "asset_services", "asset_state_history", "asset_type_reclassifications",
	"business_service_assets", "business_unit_assets", "easm_dns_check_state", "easm_evidence",
	"exposure_events", "exposures", "finding_retests", "findings", "pipeline_runs",
	"relationship_suggestions", "runtime_telemetry_events", "scan_coverage_state", "scan_sessions",
	"sla_policies", "suppression_rules", "user_accessible_assets",
}

// compositeFromCreation are tables that later migrations created with their
// composite (tenant_id, asset) keys; 000921's down does not drop them.
var compositeFromCreation = []string{"scan_step_outputs", "scan_run_targets", "ci_runs", "ci_gate_overrides"}

func seedRefAsset(ctx context.Context, t *testing.T, db interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
}, tenant shared.ID) shared.ID {
	t.Helper()
	id := shared.NewID()
	if _, err := db.ExecContext(ctx, `INSERT INTO assets (id, tenant_id, name, asset_type) VALUES ($1, $2, $3, 'domain')`,
		id.String(), tenant.String(), "fk-"+id.String()+".example.com"); err != nil {
		t.Fatalf("seed asset: %v", err)
	}
	return id
}

func TestAssetRefTenantFKs_Schema(t *testing.T) {
	db := openGroupsDB(t)
	var n int
	var allValid sql.NullBool
	if err := db.QueryRowContext(context.Background(), `
		SELECT COUNT(*), bool_and(convalidated) FROM pg_constraint
		 WHERE contype = 'f' AND confrelid = 'assets'::regclass AND array_length(conkey, 1) = 2`).Scan(&n, &allValid); err != nil {
		t.Fatal(err)
	}
	// 27 from 000921, 3 from the scan chaining tables (001049), 2 from the CI
	// run tables (001053, RFC-051).
	if n != 32 || !allValid.Bool {
		t.Fatalf("composite asset foreign keys: %d (all validated: %v), want 32 validated", n, allValid.Bool)
	}
	// Every single-column reference to assets(id) from a table that has a
	// tenant_id is covered by a composite key: a new table referencing
	// assets must add its own (tenant_id, asset) key.
	rows, err := db.QueryContext(context.Background(), `
		SELECT c.conrelid::regclass::text, a.attname
		  FROM pg_constraint c
		  JOIN pg_attribute a ON a.attrelid = c.conrelid AND a.attnum = c.conkey[1]
		 WHERE c.contype = 'f' AND c.confrelid = 'assets'::regclass AND array_length(c.conkey, 1) = 1
		   AND EXISTS (SELECT 1 FROM pg_attribute ta WHERE ta.attrelid = c.conrelid AND ta.attname = 'tenant_id' AND NOT ta.attisdropped)
		   AND NOT EXISTS (
		       SELECT 1 FROM pg_constraint cc
		        WHERE cc.contype = 'f' AND cc.conrelid = c.conrelid AND cc.confrelid = 'assets'::regclass
		          AND array_length(cc.conkey, 1) = 2 AND cc.conkey[2] = c.conkey[1])`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var uncovered []string
	for rows.Next() {
		var tbl, col string
		if err := rows.Scan(&tbl, &col); err != nil {
			t.Fatal(err)
		}
		uncovered = append(uncovered, tbl+"."+col)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if len(uncovered) > 0 {
		t.Errorf("asset references with a tenant_id but no composite (tenant_id, asset) foreign key: %v", uncovered)
	}
}

func TestAssetRefTenantFKs_RefuseCrossTenantAndKeepOnDelete(t *testing.T) {
	ctx := context.Background()
	db := openGroupsDB(t)
	tenantA, tenantB := seedTestTenant(ctx, t, db), seedTestTenant(ctx, t, db)
	own, foreign := seedRefAsset(ctx, t, db, tenantA), seedRefAsset(ctx, t, db, tenantB)

	insertFinding := func(asset shared.ID) error {
		_, err := db.ExecContext(ctx, `INSERT INTO findings (tenant_id, asset_id, source, tool_name, severity, message, fingerprint)
			VALUES ($1, $2, 'manual', 'fk', 'high', 'm', $3)`, tenantA.String(), asset.String(), "fk-"+shared.NewID().String())
		return err
	}
	if err := insertFinding(foreign); err == nil || !strings.Contains(err.Error(), "fk_findings_tenant_asset") {
		t.Errorf("cross-tenant finding: err = %v, want the composite foreign key to refuse it", err)
	}
	if err := insertFinding(own); err != nil {
		t.Errorf("own-tenant finding: %v", err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO exposure_events (tenant_id, asset_id, event_type, title, fingerprint, source)
		VALUES ($1, $2, 'port_open', 't', $3, 's')`, tenantA.String(), foreign.String(), "fk-"+shared.NewID().String()); err == nil {
		t.Error("cross-tenant exposure event stored")
	}
	if _, err := db.ExecContext(ctx, `UPDATE assets SET parent_id = $1 WHERE id = $2`, foreign.String(), own.String()); err == nil {
		t.Error("an asset was given another tenant's asset as parent")
	}

	// ON DELETE SET NULL clears only the asset column (tenant_id stays).
	victim := seedRefAsset(ctx, t, db, tenantA)
	evID := shared.NewID()
	if _, err := db.ExecContext(ctx, `INSERT INTO exposure_events (id, tenant_id, asset_id, event_type, title, fingerprint, source)
		VALUES ($1, $2, $3, 'port_open', 't', $4, 's')`, evID.String(), tenantA.String(), victim.String(), "fk-"+evID.String()); err != nil {
		t.Fatal(err)
	}
	// ON DELETE CASCADE still removes dependent rows.
	if _, err := db.ExecContext(ctx, `INSERT INTO asset_identifiers (tenant_id, asset_id, kind, value, strong)
		VALUES ($1, $2, 'fqdn', $3, false)`, tenantA.String(), victim.String(), "fk-"+victim.String()+".example.com"); err != nil {
		t.Fatalf("seed identifier: %v", err)
	}
	if _, err := db.ExecContext(ctx, `DELETE FROM assets WHERE id = $1`, victim.String()); err != nil {
		t.Fatalf("hard delete asset: %v", err)
	}
	var tenant sql.NullString
	var asset sql.NullString
	if err := db.QueryRowContext(ctx, `SELECT tenant_id::text, asset_id::text FROM exposure_events WHERE id = $1`, evID.String()).Scan(&tenant, &asset); err != nil {
		t.Fatal(err)
	}
	if asset.Valid || tenant.String != tenantA.String() {
		t.Errorf("after asset delete: exposure event tenant=%v asset=%v, want tenant kept and asset NULL", tenant, asset)
	}
	var ids int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM asset_identifiers WHERE asset_id = $1`, victim.String()).Scan(&ids); err != nil {
		t.Fatal(err)
	}
	if ids != 0 {
		t.Errorf("%d identifier(s) left after their asset was deleted, want cascade", ids)
	}
	// findings stays NO ACTION: an asset with a finding cannot be hard-deleted.
	if _, err := db.ExecContext(ctx, `DELETE FROM assets WHERE id = $1`, own.String()); err == nil {
		t.Error("an asset with a finding was hard-deleted")
	}
	t.Cleanup(func() {
		_, _ = db.ExecContext(context.Background(), `DELETE FROM findings WHERE tenant_id = $1`, tenantA.String())
	})
}

// Replays 000921 down → up → 000922 in a rolled-back transaction over
// populated tables, and proves the pre-flight refuses existing cross-tenant
// rows without changing anything.
func TestAssetRefTenantFKs_MigrationReplay(t *testing.T) {
	ctx := context.Background()
	read := func(name string) string {
		b, err := os.ReadFile("../../../migrations/" + name)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	up921, down921, up922 := read("000921_asset_ref_tenant_fks.up.sql"), read("000921_asset_ref_tenant_fks.down.sql"),
		read("000922_asset_ref_tenant_fks_validate.up.sql")

	db := openGroupsDB(t)
	tenantA, tenantB := seedTestTenant(ctx, t, db), seedTestTenant(ctx, t, db)
	own, foreign := seedRefAsset(ctx, t, db, tenantA), seedRefAsset(ctx, t, db, tenantB)
	if _, err := db.ExecContext(ctx, `INSERT INTO findings (tenant_id, asset_id, source, tool_name, severity, message, fingerprint)
		VALUES ($1, $2, 'manual', 'fk', 'high', 'm', $3)`, tenantA.String(), own.String(), "fk-"+shared.NewID().String()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = db.ExecContext(context.Background(), `DELETE FROM findings WHERE tenant_id = $1`, tenantA.String())
	})

	run := func(name string, f func(tx *sql.Tx)) {
		t.Run(name, func(t *testing.T) {
			tx, err := testdb.OpenMigrator(t).BeginTx(ctx, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = tx.Rollback() }()
			testdb.LockForDDL(t, ctx, tx, assetRefTables...)
			f(tx)
		})
	}
	exec := func(tx *sql.Tx, what, q string, args ...any) {
		t.Helper()
		if _, err := tx.ExecContext(ctx, q, args...); err != nil {
			t.Fatalf("%s: %v", what, err)
		}
	}

	run("down then up on populated data", func(tx *sql.Tx) {
		exec(tx, "down", down921)
		exec(tx, "up", up921)
		exec(tx, "validate", up922)
		exec(tx, "down again", down921)
		exec(tx, "up again", up921)
		exec(tx, "validate again", up922)
	})

	run("pre-flight refuses existing cross-tenant rows", func(tx *sql.Tx) {
		exec(tx, "down", down921)
		exec(tx, "seed cross-tenant finding", `INSERT INTO findings (tenant_id, asset_id, source, tool_name, severity, message, fingerprint)
			VALUES ($1, $2, 'manual', 'fk', 'high', 'm', $3)`, tenantA.String(), foreign.String(), "fk-"+shared.NewID().String())
		exec(tx, "seed cross-tenant scope row", `INSERT INTO user_accessible_assets (user_id, tenant_id, asset_id, ownership_type)
			SELECT id, $1, $2, 'secondary' FROM users LIMIT 1`, tenantA.String(), foreign.String())
		exec(tx, "savepoint", `SAVEPOINT before_up`)
		_, err := tx.ExecContext(ctx, up921)
		if err == nil {
			t.Fatal("000921 applied over cross-tenant rows")
		}
		if !strings.Contains(err.Error(), "cross-tenant asset references found") || !strings.Contains(err.Error(), "findings.asset_id: 1") {
			t.Errorf("pre-flight error = %v, want the per-column count", err)
		}
		exec(tx, "rollback to savepoint", `ROLLBACK TO SAVEPOINT before_up`)
		var n int
		// Tables created later with their keys are not part of 000921.
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM pg_constraint WHERE contype = 'f' AND confrelid = 'assets'::regclass AND array_length(conkey, 1) = 2
			AND NOT (conrelid::regclass::text = ANY($1))`, pq.Array(compositeFromCreation)).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n != 0 {
			t.Errorf("%d composite key(s) left after a refused pre-flight, want 0", n)
		}
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM findings WHERE tenant_id = $1 AND asset_id = $2`, tenantA.String(), foreign.String()).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n != 1 {
			t.Errorf("the pre-flight changed data: %d cross-tenant finding(s), want the seeded 1", n)
		}
	})
}
