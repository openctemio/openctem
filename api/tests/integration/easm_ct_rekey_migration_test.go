package integration

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/domain/exposure"
)

// Migration 001018 (research/22 P0-9, 22c B2) re-keys CT exposures to the
// asset-independent identity the CT monitor now writes, resolves the
// duplicates it collapses, and leaves other sources and other tenants'
// rows alone. Its SQL fingerprint must equal exposure.Fingerprint. The down
// migration restores every touched row. Replayed down -> up -> down -> up
// inside a rolled-back transaction as the migrator.
func TestMigration001018_RekeysCTExposures(t *testing.T) {
	ctx := context.Background()
	up, err := os.ReadFile("../../migrations/001018_easm_ct_exposure_rekey.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	down, err := os.ReadFile("../../migrations/001018_easm_ct_exposure_rekey.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	tx, err := testdb.OpenMigrator(t).BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := tx.ExecContext(ctx, q, args...); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	exec(string(down))

	tenant, other, asset := uuid.NewString(), uuid.NewString(), uuid.NewString()
	for _, id := range []string{tenant, other} {
		exec(`INSERT INTO tenants (id, name, slug) VALUES ($1, 'ct rekey IT', $2)`, id, "ctrekey-"+strings.ReplaceAll(id[:13], "-", ""))
	}
	exec(`INSERT INTO assets (id, tenant_id, name, asset_type, status) VALUES ($1, $2, 'example.com', 'domain', 'active')`, asset, tenant)

	const host = "old.example.com"
	title := "TLS certificate expiring soon: " + host
	details := map[string]any{"domain": host}
	newFP := exposure.Fingerprint(tenant, "certificate_expiring", title, "cert_transparency", "", details)
	linkedFP := exposure.Fingerprint(tenant, "certificate_expiring", title, "cert_transparency", asset, details)
	insert := func(tn, assetID, fp, source, state string) string {
		id := uuid.NewString()
		var a any
		if assetID != "" {
			a = assetID
		}
		exec(`INSERT INTO exposure_events (id, tenant_id, asset_id, event_type, severity, state, title, details, fingerprint, source,
			first_seen_at, last_seen_at, created_at, updated_at)
			VALUES ($1, $2, $3, 'certificate_expiring', 'high', $4, $5, jsonb_build_object('domain', $6::text), $7, $8,
			now(), now(), now(), now())`, id, tn, a, state, title, host, fp, source)
		return id
	}
	unlinked := insert(tenant, "", newFP, "cert_transparency", "active") // seed-only period
	linked := insert(tenant, asset, linkedFP, "cert_transparency", "active")
	dns := insert(tenant, asset, uuid.NewString()[:32]+"dnsdnsdnsdnsdnsdnsdnsdnsdnsdnsdn", "easm_dns", "active")
	foreign := insert(other, "", exposure.Fingerprint(other, "certificate_expiring", title, "cert_transparency", "", details), "cert_transparency", "active")

	row := func(id string) (fp, state string) {
		t.Helper()
		if err := tx.QueryRowContext(ctx, `SELECT fingerprint, state FROM exposure_events WHERE id = $1`, id).Scan(&fp, &state); err != nil {
			t.Fatal(err)
		}
		return
	}
	check := func() {
		t.Helper()
		if fp, st := row(linked); fp != newFP || st != "active" {
			t.Fatalf("kept row: %s %s, want the Go fingerprint %s, active", fp, st, newFP)
		}
		if fp, st := row(unlinked); fp == newFP || st != "resolved" {
			t.Fatalf("duplicate: %s %s, want resolved with a placeholder", fp, st)
		}
		if _, st := row(dns); st != "active" {
			t.Fatal("a DNS-check exposure was touched")
		}
		if fp, st := row(foreign); st != "active" || fp != exposure.Fingerprint(other, "certificate_expiring", title, "cert_transparency", "", details) {
			t.Fatal("another tenant's exposure was changed")
		}
	}
	exec(string(up))
	check()

	exec(string(down))
	if fp, st := row(linked); fp != linkedFP || st != "active" {
		t.Fatalf("down: kept row %s %s", fp, st)
	}
	if fp, st := row(unlinked); fp != newFP || st != "active" {
		t.Fatalf("down: duplicate %s %s", fp, st)
	}
	exec(string(up))
	check()
}
