package postgres

import (
	"context"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Coverage candidates that were never dispatched come most critical first by
// rank (critical, high, medium, low), not by the text of the level, before
// the LIMIT applies; another tenant's assets are never listed.
func TestScanCoverage_CandidatesOrderedByCriticalityRank_DB(t *testing.T) {
	db := openScanDB(t)
	ctx := context.Background()
	tenant := seedScanTriggerTenant(ctx, t, db)
	other := seedScanTriggerTenant(ctx, t, db)
	for _, a := range []struct {
		tid        shared.ID
		name, crit string
	}{
		{tenant, "10.0.0.1", "medium"}, {tenant, "10.0.0.2", "low"},
		{tenant, "10.0.0.3", "critical"}, {tenant, "10.0.0.4", "high"},
		{other, "10.0.0.5", "critical"},
	} {
		if _, err := db.ExecContext(ctx, `INSERT INTO assets (id, tenant_id, name, asset_type, criticality, status)
			VALUES ($1, $2, $3, 'host', $4, 'active')`, shared.NewID().String(), a.tid.String(), a.name, a.crit); err != nil {
			t.Fatal(err)
		}
	}
	got, err := NewScanCoverageRepository(&DB{DB: db}).ListCandidates(ctx, tenant, 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Target != "10.0.0.3" || got[1].Target != "10.0.0.4" {
		t.Fatalf("first two candidates = %+v, want the critical then the high asset", got)
	}
}
