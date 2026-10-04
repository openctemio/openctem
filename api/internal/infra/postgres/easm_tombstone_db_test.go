package postgres

import (
	"context"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/attribution"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Rejection tombstones against the real schema (migration 000620): a
// rejection (single or bulk) records the name with its rules, a changed
// decision removes it, a deleted asset keeps it, expired rows are ignored and
// purged, and no tenant sees or changes another tenant's tombstones.
// Requires DATABASE_URL.
func TestEASMTombstones(t *testing.T) {
	db := openSensorDB(t)
	ctx := context.Background()
	repo := NewAttributionRepository(&DB{DB: db})
	tenant := seedTestTenant(ctx, t, db)
	other := seedTestTenant(ctx, t, db)

	sub := func(tid shared.ID, name string) string {
		t.Helper()
		id := shared.NewID().String()
		if _, err := db.ExecContext(ctx, `INSERT INTO assets (id, tenant_id, name, asset_type) VALUES ($1, $2, $3, 'subdomain')`,
			id, tid.String(), name); err != nil {
			t.Fatal(err)
		}
		return id
	}
	a := sub(tenant, "Old.Acme.com")
	b := sub(tenant, "b.acme.com")
	theirs := sub(other, "old.acme.com")
	if err := repo.UpsertEvidence(ctx, tenant, []attribution.Evidence{{AssetID: a, Rule: attribution.RuleAssertedRoot,
		Technique: "cert_transparency", Source: "crt.sh", Weight: 0.85}}); err != nil {
		t.Fatal(err)
	}

	if _, err := repo.SaveDecision(ctx, tenant, a, attribution.StateRejected, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.SaveDecisions(ctx, tenant, []string{b, theirs}, attribution.StateRejected, ""); err != nil {
		t.Fatal(err)
	}
	dead, err := repo.Tombstoned(ctx, tenant, []string{"old.acme.com", "b.acme.com"})
	if err != nil {
		t.Fatal(err)
	}
	if len(dead["old.acme.com"]) != 1 || dead["old.acme.com"][0] != attribution.RuleAssertedRoot {
		t.Fatalf("tombstone rules = %v", dead)
	}
	if _, ok := dead["b.acme.com"]; !ok {
		t.Fatal("bulk rejection wrote no tombstone")
	}
	// The other tenant's asset id in a bulk decision wrote nothing for it.
	if d, _ := repo.Tombstoned(ctx, other, []string{"old.acme.com"}); len(d) != 0 {
		t.Fatal("a decision by one tenant tombstoned another tenant's name")
	}

	// The tombstone outlives the asset.
	if _, err := db.ExecContext(ctx, `DELETE FROM assets WHERE id = $1`, a); err != nil {
		t.Fatal(err)
	}
	if d, _ := repo.Tombstoned(ctx, tenant, []string{"old.acme.com"}); len(d) != 1 {
		t.Fatal("tombstone lost with the asset")
	}

	// Changing the decision removes the tombstone.
	if _, err := repo.SaveDecision(ctx, tenant, b, attribution.StateConfirmed, ""); err != nil {
		t.Fatal(err)
	}
	if d, _ := repo.Tombstoned(ctx, tenant, []string{"b.acme.com"}); len(d) != 0 {
		t.Fatal("tombstone kept after the rejection was reversed")
	}

	// Expired: ignored, then purged for this tenant only.
	if _, err := db.ExecContext(ctx, `UPDATE easm_tombstones SET expires_at = now() - interval '1 day' WHERE tenant_id = $1`, tenant.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO easm_tombstones (tenant_id, name, expires_at) VALUES ($1, 'x.other.com', now() - interval '1 day')`, other.String()); err != nil {
		t.Fatal(err)
	}
	if d, _ := repo.Tombstoned(ctx, tenant, []string{"old.acme.com"}); len(d) != 0 {
		t.Fatal("expired tombstone still applies")
	}
	if n, err := repo.PurgeExpiredTombstones(ctx, tenant); err != nil || n != 1 {
		t.Fatalf("purged %d %v, want 1", n, err)
	}
	var left int
	_ = db.QueryRowContext(ctx, `SELECT count(*) FROM easm_tombstones WHERE tenant_id = $1`, other.String()).Scan(&left)
	if left != 1 {
		t.Fatal("purging one tenant removed another tenant's tombstones")
	}
}
