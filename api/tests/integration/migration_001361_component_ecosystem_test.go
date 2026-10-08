package integration

// Migration 001361: components stored with ecosystem 'other' although their
// package URL names an ecosystem (trivy fs reports carry only a PURL) get
// the ecosystem the PURL type names, on the shared component and on each
// asset's copy. Types outside our ecosystems stay 'other'; a component
// labelled already keeps its label. Runs as the schema owner in a
// rolled-back transaction.

import (
	"context"
	"database/sql"
	"os"
	"testing"

	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func TestMigration001361ClassifiesComponentsFromPURL(t *testing.T) {
	appDB := openLifecycleDB(t)
	ctx := context.Background()
	tenant := seedLifecycleTenant(ctx, t, appDB)

	up, err := os.ReadFile("../../migrations/001361_component_ecosystem_from_purl.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("postgres", testdb.MigratorURL())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()

	assetID := shared.NewID().String()
	if _, err := tx.ExecContext(ctx, `INSERT INTO assets (id, tenant_id, name, asset_type) VALUES ($1, $2, $3, 'repository')`,
		assetID, tenant.String(), "repo-"+assetID); err != nil {
		t.Fatal(err)
	}
	suffix := shared.NewID().String()[:8]
	component := func(purl, ecosystem string) string {
		t.Helper()
		id := shared.NewID().String()
		if _, err := tx.ExecContext(ctx, `INSERT INTO components (id, purl, name, version, ecosystem) VALUES ($1, $2, $4, '1', $3)`,
			id, purl, ecosystem, "c-"+id); err != nil {
			t.Fatalf("seed component %s: %v", purl, err)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO asset_components (tenant_id, asset_id, component_id, name, version, ecosystem, purl, path)
			VALUES ($1, $2, $3, $7, '1', $4, $5, $6)`, tenant.String(), assetID, id, ecosystem, purl, "/"+id, "c-"+id); err != nil {
			t.Fatalf("seed asset component %s: %v", purl, err)
		}
		return id
	}
	npm := component("pkg:npm/left-pad-"+suffix+"@1.3.0", "other")
	golang := component("pkg:golang/github.com/example/m-"+suffix+"@v1.0.0", "other")
	deb := component("pkg:deb/debian/openssl-"+suffix+"@3.0.11", "other")
	labelled := component("pkg:npm/already-"+suffix+"@1.0.0", "pypi")

	if _, err := tx.ExecContext(ctx, string(up)); err != nil {
		t.Fatalf("up: %v", err)
	}
	// Idempotent.
	if _, err := tx.ExecContext(ctx, string(up)); err != nil {
		t.Fatalf("up again: %v", err)
	}

	for id, want := range map[string]string{npm: "npm", golang: "go", deb: "other", labelled: "pypi"} {
		var got, gotAsset string
		if err := tx.QueryRowContext(ctx, `SELECT c.ecosystem, ac.ecosystem FROM components c
			JOIN asset_components ac ON ac.component_id = c.id WHERE c.id = $1`, id).Scan(&got, &gotAsset); err != nil {
			t.Fatal(err)
		}
		if got != want || gotAsset != want {
			t.Errorf("component %s: ecosystem %q, asset copy %q, want %q", id, got, gotAsset, want)
		}
	}

	down, err := os.ReadFile("../../migrations/001361_component_ecosystem_from_purl.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.ExecContext(ctx, string(down)); err != nil {
		t.Fatalf("down: %v", err)
	}
}
