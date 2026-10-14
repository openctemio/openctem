package integration

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/internal/app/scancoverage"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// License-aware coverage batches on the coverage ledger (research/143):
// dispatch leaves the batch's rows queued (not covered), the batch's
// per-target outcomes settle them, and the cycle progress counts what the
// connector assessed. Another tenant's rows for the same address never move.
func TestTenableSCRotation_LedgerSettlement(t *testing.T) {
	sqldb := setupTestDB(t)
	t.Cleanup(func() { _ = sqldb.Close() })
	db := &postgres.DB{DB: sqldb}
	ctx := context.Background()
	repo := postgres.NewScanCoverageRepository(db)

	tenant, other := seedTenant(t, sqldb), seedTenant(t, sqldb)
	ids := map[string]shared.ID{}
	for _, name := range []string{"10.60.0.1", "10.60.0.2", "10.60.0.3"} {
		ids[name] = seedIPAsset(t, sqldb, tenant, name)
	}
	otherID := seedIPAsset(t, sqldb, other, "10.60.0.1")

	start := time.Now().UTC().Add(-time.Minute)
	claim := func(tid shared.ID, batch []scancoverage.Candidate) {
		t.Helper()
		got, err := repo.ClaimBatch(ctx, tid, batch, time.Now().UTC().Truncate(time.Microsecond))
		if err != nil || len(got) != len(batch) {
			t.Fatalf("claim: %v %v", got, err)
		}
		assetIDs := make([]string, 0, len(batch))
		for _, c := range batch {
			assetIDs = append(assetIDs, c.AssetID)
		}
		if err := repo.MarkDispatched(ctx, scancoverage.DispatchRecord{TenantID: tid, AssetIDs: assetIDs}); err != nil {
			t.Fatal(err)
		}
	}
	var batch []scancoverage.Candidate
	for name, id := range ids {
		batch = append(batch, scancoverage.Candidate{AssetID: id.String(), Target: name})
	}
	claim(tenant, batch)
	claim(other, []scancoverage.Candidate{{AssetID: otherID.String(), Target: "10.60.0.1"}})

	for name, id := range ids {
		if st := ledgerState(t, sqldb, tenant, id); st != "queued" {
			t.Fatalf("%s after dispatch: %s, want queued (dispatched is not covered)", name, st)
		}
	}

	if err := repo.SettleConnectorBatch(ctx, tenant, scancoverage.BatchSettlement{
		Done: []string{"10.60.0.1"}, Unreachable: []string{"10.60.0.2"}, Unfinished: []string{"10.60.0.3"},
	}); err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"10.60.0.1": "covered", "10.60.0.2": "failed", "10.60.0.3": "due"}
	for name, id := range ids {
		if st := ledgerState(t, sqldb, tenant, id); st != want[name] {
			t.Fatalf("%s: %s, want %s", name, st, want[name])
		}
	}
	if st := ledgerState(t, sqldb, other, otherID); st != "queued" {
		t.Fatalf("another tenant's row moved: %s", st)
	}

	eligible, assessed, err := repo.ConnectorCycleProgress(ctx, tenant, start)
	if err != nil || eligible != 3 || assessed != 1 {
		t.Fatalf("cycle progress %d/%d %v", assessed, eligible, err)
	}
	if e, a, err := repo.ConnectorCycleProgress(ctx, other, start); err != nil || e != 1 || a != 0 {
		t.Fatalf("other tenant's progress %d/%d %v", a, e, err)
	}

	// A failed batch fails its rows with the reason.
	if err := repo.SettleConnectorBatch(ctx, tenant, scancoverage.BatchSettlement{
		Failed: []string{"10.60.0.3"}, Error: "credentials rejected",
	}); err != nil {
		t.Fatal(err)
	}
	var state, lastErr string
	if err := sqldb.QueryRow(`SELECT state, last_error FROM asset_coverage WHERE tenant_id = $1 AND asset_id = $2 AND capability = 'network_va.connector'`,
		tenant.String(), ids["10.60.0.3"].String()).Scan(&state, &lastErr); err != nil || state != "failed" || lastErr != "credentials rejected" {
		t.Fatalf("failed row: %s %q %v", state, lastErr, err)
	}
}

func seedIPAsset(t *testing.T, db *sql.DB, tenant shared.ID, name string) shared.ID {
	t.Helper()
	id := shared.NewID()
	if _, err := db.Exec(`INSERT INTO assets (id, tenant_id, name, asset_type, status) VALUES ($1, $2, $3, 'ip_address', 'active')`,
		id.String(), tenant.String(), name); err != nil {
		t.Fatalf("seed asset: %v", err)
	}
	return id
}

func ledgerState(t *testing.T, db *sql.DB, tenant, asset shared.ID) string {
	t.Helper()
	var st string
	if err := db.QueryRow(`SELECT state FROM asset_coverage WHERE tenant_id = $1 AND asset_id = $2 AND capability = 'network_va.connector' AND vantage = ''`,
		tenant.String(), asset.String()).Scan(&st); err != nil {
		t.Fatalf("ledger row: %v", err)
	}
	return st
}
