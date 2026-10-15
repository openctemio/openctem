package postgres

import (
	"context"
	"math"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// MTTR counts remediations only: a finding resolved because its asset, source
// or rule went away (an obsolete closure) is not a fix and stays out of every
// MTTR figure, whatever its age; a closure of unknown reason (made before
// reasons existed) still counts. Another tenant's fix never enters the mean.
func TestMTTR_ExcludesObsoleteClosures_DB(t *testing.T) {
	ctx := context.Background()
	db := openGroupsDB(t)
	repo := NewDashboardRepository(db)
	tenant := seedTestTenant(ctx, t, db)
	other := seedTestTenant(ctx, t, db)
	asset := seedOwnedAsset(ctx, t, db, tenant, nil)
	otherAsset := seedOwnedAsset(ctx, t, db, other, nil)

	seed := func(tid, aid shared.ID, hours int, reason, verification string) {
		t.Helper()
		id := shared.NewID()
		if _, err := db.ExecContext(ctx, `
			INSERT INTO findings (id, tenant_id, asset_id, source, tool_name, message, severity, fingerprint, status,
				first_detected_at, resolved_at, closure_reason, verification)
			VALUES ($1::uuid, $2, $3, 'sca', 'test', 'msg', 'critical', $1::text, 'resolved',
				NOW() - make_interval(hours => $4::int + 1), NOW() - interval '1 hour', $5, $6)`,
			id.String(), tid.String(), aid.String(), hours, reason, verification); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}
	seed(tenant, asset, 10, "fixed", "covered_scan")
	seed(tenant, asset, 30, "unknown", "unknown")
	seed(tenant, asset, 5000, "obsolete_source", "none")
	seed(tenant, asset, 5000, "obsolete_asset", "none")
	seed(other, otherAsset, 900, "fixed", "retest")

	m, err := repo.GetMTTRMetrics(ctx, tenant, nil, 90)
	if err != nil {
		t.Fatal(err)
	}
	if got := m["critical"]; math.Abs(got-20) > 0.1 {
		t.Fatalf("MTTR critical = %.2fh, want 20h (the fixed and the unknown closure, not the obsolete ones)", got)
	}
	a, err := repo.GetMTTRAnalytics(ctx, tenant, nil, 90)
	if err != nil {
		t.Fatal(err)
	}
	if a.SampleSize != 2 {
		t.Fatalf("MTTR analytics sample = %d, want 2", a.SampleSize)
	}
	s, err := repo.GetExecutiveSummary(ctx, tenant, 90)
	if err != nil {
		t.Fatal(err)
	}
	if math.Abs(s.MTTRCriticalHrs-20) > 0.1 {
		t.Fatalf("executive MTTR critical = %.2fh, want 20h", s.MTTRCriticalHrs)
	}
}
