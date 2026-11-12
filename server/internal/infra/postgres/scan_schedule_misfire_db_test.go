package postgres

import (
	"context"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/scan"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// A skipped occurrence is stored on the scan (and read back by the scan
// queries), only in the scan's own tenant; a later start clears it.
func TestScheduleMisfire_RecordReadClear_TenantScoped(t *testing.T) {
	ctx := context.Background()
	db := openScanDB(t)
	repo := NewScanRepository(&DB{DB: db})
	tenantID := seedScanTriggerTenant(ctx, t, db)
	otherTenant := seedScanTriggerTenant(ctx, t, db)

	scanID := shared.NewID()
	if _, err := db.ExecContext(ctx,
		`INSERT INTO scans (id, tenant_id, name, scan_type, scanner_name, schedule_type, status)
		 VALUES ($1, $2, 'misfire probe', 'single', 'nuclei', 'daily', 'active')`,
		scanID.String(), tenantID.String()); err != nil {
		t.Fatalf("seed scan: %v", err)
	}
	missed := time.Now().Add(-3 * time.Hour).UTC().Truncate(time.Microsecond)

	// Another tenant, same scan id: nothing is written.
	if err := repo.RecordScheduleMisfire(ctx, otherTenant, scanID, missed, scan.MissReasonPlatformUnavailable); err != nil {
		t.Fatal(err)
	}
	got, err := repo.GetByTenantAndID(ctx, tenantID, scanID)
	if err != nil {
		t.Fatal(err)
	}
	if got.LastMissedAt != nil || got.LastMissedReason != "" {
		t.Fatalf("another tenant wrote a misfire: %v %q", got.LastMissedAt, got.LastMissedReason)
	}

	if err := repo.RecordScheduleMisfire(ctx, tenantID, scanID, missed, scan.MissReasonPlatformUnavailable); err != nil {
		t.Fatal(err)
	}
	got, err = repo.GetByTenantAndID(ctx, tenantID, scanID)
	if err != nil {
		t.Fatal(err)
	}
	if got.LastMissedAt == nil || !got.LastMissedAt.Equal(missed) || got.LastMissedReason != scan.MissReasonPlatformUnavailable {
		t.Fatalf("misfire not stored: %v %q", got.LastMissedAt, got.LastMissedReason)
	}

	// Another tenant cannot clear it.
	if err := repo.ClearScheduleMisfire(ctx, otherTenant, scanID); err != nil {
		t.Fatal(err)
	}
	if got, _ = repo.GetByTenantAndID(ctx, tenantID, scanID); got.LastMissedAt == nil {
		t.Fatal("another tenant cleared the misfire")
	}
	if err := repo.ClearScheduleMisfire(ctx, tenantID, scanID); err != nil {
		t.Fatal(err)
	}
	if got, _ = repo.GetByTenantAndID(ctx, tenantID, scanID); got.LastMissedAt != nil || got.LastMissedReason != "" {
		t.Fatal("misfire not cleared")
	}
}
