package postgres

import (
	"context"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/limits"
)

// Shared-sensor scans started today count one per run (a run's chunks
// count once) and one per command outside a run; yesterday's, organization
// jobs and other organizations' never count. Requires DATABASE_URL.
func TestPlanUsage_SharedScansToday(t *testing.T) {
	sqlDB := openSensorDB(t)
	ctx := context.Background()
	repo := NewLimitsRepository(&DB{DB: sqlDB})
	tenant := seedTestTenant(ctx, t, sqlDB)
	other := seedTestTenant(ctx, t, sqlDB)

	insert := func(tenantID, payload string, platform bool, age string) {
		t.Helper()
		if _, err := sqlDB.ExecContext(ctx, `
			INSERT INTO commands (id, tenant_id, type, priority, payload, status, is_platform_job, created_at)
			VALUES (gen_random_uuid(), $1, 'scan', 'normal', $2::jsonb, 'completed', $3, now() - $4::interval)`,
			tenantID, payload, platform, age); err != nil {
			t.Fatal(err)
		}
	}
	run := `{"scan_run_id": "11111111-1111-1111-1111-111111111111"}`
	insert(tenant.String(), run, true, "0 seconds")   // run chunk 1
	insert(tenant.String(), run, true, "0 seconds")   // run chunk 2: same run
	insert(tenant.String(), `{}`, true, "0 seconds")  // a command outside a run
	insert(tenant.String(), `{}`, false, "0 seconds") // organization job
	insert(tenant.String(), `{}`, true, "30 hours")   // before today (UTC)
	insert(other.String(), `{}`, true, "0 seconds")   // another organization

	usage, err := repo.Usage(ctx, tenant, false)
	if err != nil {
		t.Fatal(err)
	}
	if got := usage[limits.PlatformScansPerDay]; got != 2 {
		t.Errorf("shared scans today = %d, want 2", got)
	}
}
