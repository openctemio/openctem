package postgres

import (
	"context"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/attribution"
)

// Attribution against the real schema (migration 000275): evidence upsert is
// idempotent per (asset, rule, source), a foreign tenant's asset id writes
// nothing, automation never overwrites a human decision, and the scan gate
// blocks only non-confirmed records. Requires DATABASE_URL.
func TestAttributionRepository(t *testing.T) {
	sqlDB := openSensorDB(t)
	ctx := context.Background()
	repo := NewAttributionRepository(&DB{DB: sqlDB})
	tenant := seedTestTenant(ctx, t, sqlDB)
	other := seedTestTenant(ctx, t, sqlDB)

	review := seedTestAsset(ctx, t, sqlDB, tenant).String()
	confirmed := seedTestAsset(ctx, t, sqlDB, tenant).String()
	legacy := seedTestAsset(ctx, t, sqlDB, tenant).String()
	foreign := seedTestAsset(ctx, t, sqlDB, other).String()

	ev := attribution.Evidence{AssetID: review, Rule: attribution.RuleAssertedRoot, Technique: "cert_transparency",
		Source: "crt.sh", Weight: 0.85, Observed: map[string]any{"root": "listed.com"}}
	for i := 0; i < 2; i++ { // a re-sighting is not new evidence
		if err := repo.UpsertEvidence(ctx, tenant, []attribution.Evidence{ev}); err != nil {
			t.Fatal(err)
		}
	}
	// Writing evidence for another tenant's asset under this tenant is a no-op.
	bad := ev
	bad.AssetID = foreign
	if err := repo.UpsertEvidence(ctx, tenant, []attribution.Evidence{bad}); err != nil {
		t.Fatal(err)
	}
	var n int
	_ = sqlDB.QueryRowContext(ctx, `SELECT count(*) FROM easm_evidence WHERE asset_id = $1`, foreign).Scan(&n)
	if n != 0 {
		t.Fatalf("evidence written for a foreign tenant's asset")
	}

	fired, err := repo.FiredRules(ctx, tenant, []string{review, legacy})
	if err != nil {
		t.Fatal(err)
	}
	if len(fired[review]) != 1 || fired[review][0] != attribution.RuleAssertedRoot || len(fired[legacy]) != 0 {
		t.Fatalf("fired = %v", fired)
	}

	if err := repo.SaveAutomatic(ctx, tenant, review, attribution.Decision{State: attribution.StateNeedsReview, Confidence: 85, Reason: attribution.RuleAssertedRoot}); err != nil {
		t.Fatal(err)
	}
	if err := repo.SaveAutomatic(ctx, tenant, confirmed, attribution.Decision{State: attribution.StateConfirmed, Confidence: 99, Reason: attribution.RuleVerifiedRoot}); err != nil {
		t.Fatal(err)
	}
	// SaveAutomatic for a foreign asset writes nothing.
	if err := repo.SaveAutomatic(ctx, tenant, foreign, attribution.Decision{State: attribution.StateConfirmed, Confidence: 99}); err != nil {
		t.Fatal(err)
	}
	if recs, _ := repo.Records(ctx, other, []string{foreign}); len(recs) != 0 {
		t.Fatalf("foreign asset got a record: %v", recs)
	}

	blocked, err := repo.ActiveCheckBlocked(ctx, tenant, []string{review, confirmed, legacy})
	if err != nil {
		t.Fatal(err)
	}
	if len(blocked) != 1 || blocked[review] != attribution.StateNeedsReview {
		t.Fatalf("blocked = %v, want only the needs_review asset", blocked)
	}
	// Another tenant cannot read this tenant's records through the gate.
	if b, _ := repo.ActiveCheckBlocked(ctx, other, []string{review}); len(b) != 0 {
		t.Fatalf("cross-tenant gate read: %v", b)
	}

	// A human decision is never overwritten by automation.
	if _, err := sqlDB.ExecContext(ctx, `UPDATE asset_attributions SET state = 'rejected', decided_at = now() WHERE asset_id = $1`, review); err != nil {
		t.Fatal(err)
	}
	if err := repo.SaveAutomatic(ctx, tenant, review, attribution.Decision{State: attribution.StateConfirmed, Confidence: 99}); err != nil {
		t.Fatal(err)
	}
	view, found, err := repo.Get(ctx, tenant, review)
	if err != nil || !found {
		t.Fatalf("get: found=%v err=%v", found, err)
	}
	if view.Record.State != attribution.StateRejected || !view.Record.HumanDecided {
		t.Fatalf("human decision overwritten: %+v", view.Record)
	}
	if len(view.Evidence) != 1 || view.Evidence[0].Observed["root"] != "listed.com" {
		t.Fatalf("evidence = %+v", view.Evidence)
	}

	// A person's decision on a legacy asset creates the record; on another
	// tenant's asset it is not found and writes nothing.
	if ok, err := repo.SaveDecision(ctx, tenant, confirmed, attribution.StateDependency, ""); err != nil || !ok {
		t.Fatalf("decision: ok=%v err=%v", ok, err)
	}
	if v, _, _ := repo.Get(ctx, tenant, confirmed); v.Record.State != attribution.StateDependency || !v.Record.HumanDecided || v.Record.Confidence != 99 {
		t.Fatalf("after decision: %+v (confidence must be kept)", v.Record)
	}
	if ok, err := repo.SaveDecision(ctx, tenant, foreign, attribution.StateConfirmed, ""); err != nil || ok {
		t.Fatalf("decision on a foreign asset: ok=%v err=%v", ok, err)
	}

	// Legacy asset: no record, found=false.
	if _, found, err := repo.Get(ctx, tenant, legacy); err != nil || found {
		t.Fatalf("legacy: found=%v err=%v", found, err)
	}
	// The state check constraint holds.
	if err := repo.SaveAutomatic(ctx, tenant, legacy, attribution.Decision{State: "owned", Confidence: 10}); err == nil {
		t.Fatal("invalid state accepted")
	}
}
