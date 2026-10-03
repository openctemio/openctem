package postgres

import (
	"context"
	"testing"
	"time"
)

// GetStats scanned AVG(duration_ms), a numeric such as "7.5000", into an
// int64, so GET /scan-sessions/stats answered 500 for every tenant with a
// completed run with a duration (the Scans page's Runs tab showed "Server
// Error" toasts).
func TestScanSessionRepository_GetStats_AverageDuration(t *testing.T) {
	ctx := context.Background()
	db := openGroupsDB(t)
	repo := NewScanSessionRepository(&DB{DB: db})
	tenant := seedTestTenant(ctx, t, db)

	for _, ms := range []int{7000, 8000} {
		if _, err := db.ExecContext(ctx,
			`INSERT INTO scan_sessions (tenant_id, scanner_name, asset_type, asset_value, status, duration_ms)
			 VALUES ($1, 'nuclei', 'domain', 'example.com', 'completed', $2)`, tenant.String(), ms); err != nil {
			t.Fatalf("seed session: %v", err)
		}
	}
	if _, err := db.ExecContext(ctx,
		`INSERT INTO scan_sessions (tenant_id, scanner_name, asset_type, asset_value, status, duration_ms)
		 VALUES ($1, 'nuclei', 'domain', 'example.com', 'failed', 1)`, tenant.String()); err != nil {
		t.Fatalf("seed failed session: %v", err)
	}

	stats, err := repo.GetStats(ctx, tenant, time.Now().Add(-time.Hour))
	if err != nil {
		t.Fatalf("GetStats: %v", err)
	}
	if stats.Total != 3 || stats.Completed != 2 || stats.Failed != 1 {
		t.Fatalf("counts: %+v", stats)
	}
	if stats.AvgDurationMs != 7500 {
		t.Fatalf("average duration of completed runs: got %d, want 7500", stats.AvgDurationMs)
	}
}
