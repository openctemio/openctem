package postgres

// Composite tenant foreign keys on asset references (research doc 21b P1-1,
// in the migration baseline): the database refuses a row of one tenant that points
// at another tenant's asset, whatever code writes it, and keeps each table's
// ON DELETE action.

import (
	"context"
	"database/sql"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

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
		 WHERE contype = 'f' AND confrelid = 'assets'::regclass AND array_length(conkey, 1) = 2
		   AND conparentid = 0`).Scan(&n, &allValid); err != nil {
		t.Fatal(err)
	}
	// 27 from 000921 (scan_sessions dropped by 001148, the type
	// normalisation ledger by 001481), 3 from the scan
	// chaining tables (001049), 2 from the CI run tables (001077, RFC-051), 1
	// from CI pipelines (001084), 1 from CI coverage expectations (001099), 1
	// from CI gate policies (001144), 1 from web endpoints (001270) and 1 from
	// API descriptions (001299, RFC-056), 1 from software links (001616,
	// RFC-066), 1 from attribute sources (001652, RFC-069), 1 from the asset
	// change timeline (RFC-069; its monthly partitions inherit it and are
	// not counted), 1 from per-source set elements (RFC-069), 1 from program
	// asset links (001792, RFC-065), 1 from program target assets
	// (program_target_assets, RFC-065 16.8) and 1 from VEX statements
	// (RFC-070).
	if n != 42 || !allValid.Bool {
		t.Fatalf("composite asset foreign keys: %d (all validated: %v), want 42 validated", n, allValid.Bool)
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
