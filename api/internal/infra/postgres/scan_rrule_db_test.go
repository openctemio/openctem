package postgres

import (
	"context"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/scan"
)

// An rrule schedule (RFC-046 D11) is stored and read back, tenant-scoped,
// and switching to another schedule type clears the rule.
func TestScanRepository_RRuleScheduleRoundTrip(t *testing.T) {
	ctx := context.Background()
	db := openScanDB(t)
	repo := NewScanRepository(&DB{DB: db})
	tenantID, scanID := seedCounterScan(ctx, t, db)

	sc, err := repo.GetByTenantAndID(ctx, tenantID, scanID)
	if err != nil {
		t.Fatal(err)
	}
	sc.Status = scan.StatusActive
	if err := sc.SetRRuleSchedule("FREQ=WEEKLY;BYDAY=MO;BYHOUR=2", "Asia/Ho_Chi_Minh"); err != nil {
		t.Fatal(err)
	}
	if err := repo.Update(ctx, sc); err != nil {
		t.Fatalf("update: %v", err)
	}
	got, err := repo.GetByTenantAndID(ctx, tenantID, scanID)
	if err != nil {
		t.Fatal(err)
	}
	if got.ScheduleType != scan.ScheduleRRule || got.ScheduleRRule != "FREQ=WEEKLY;BYDAY=MO;BYHOUR=2" ||
		got.ScheduleTimezone != "Asia/Ho_Chi_Minh" || got.NextRunAt == nil {
		t.Fatalf("read back %q %q %q next=%v", got.ScheduleType, got.ScheduleRRule, got.ScheduleTimezone, got.NextRunAt)
	}

	// Another tenant does not see it.
	other, _ := seedCounterScan(ctx, t, db)
	if _, err := repo.GetByTenantAndID(ctx, other, scanID); err == nil {
		t.Fatal("another tenant read the scan")
	}

	// A rule over the column bound is refused by the database too.
	if _, err := db.ExecContext(ctx, `UPDATE scans SET schedule_rrule = repeat($2, 501) WHERE id = $1`, scanID.String(), "x"); err == nil {
		t.Fatal("an oversized rule was stored")
	}

	if err := got.SetSchedule(scan.ScheduleManual, "", nil, nil, "UTC"); err != nil {
		t.Fatal(err)
	}
	if err := repo.Update(ctx, got); err != nil {
		t.Fatal(err)
	}
	var stored *string
	if err := db.QueryRowContext(ctx, `SELECT schedule_rrule FROM scans WHERE id = $1`, scanID.String()).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if stored != nil {
		t.Fatalf("schedule_rrule = %q after switching to manual, want NULL", *stored)
	}
}
