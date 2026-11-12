package postgres

import (
	"context"
	"database/sql"
	"testing"
)

// The queue by lane-ish key: pending, unexpired commands by stage, platform
// tool, priority and wait reason, with the tenant dimension as two
// aggregates. Read before and after this test's own rows inside one
// REPEATABLE READ transaction (rolled back), so other tests' rows cancel
// out. Requires DATABASE_URL.
func TestReadOpsSnapshot_Queue(t *testing.T) {
	sqlDB := openSensorDB(t)
	ctx := context.Background()
	tenantA := seedTestTenant(ctx, t, sqlDB)
	tenantB := seedTestTenant(ctx, t, sqlDB)

	tx, err := sqlDB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()
	var platformTool string
	if err := tx.QueryRowContext(ctx, `SELECT name FROM tools WHERE tenant_id IS NULL ORDER BY name LIMIT 1`).Scan(&platformTool); err != nil {
		t.Skipf("no platform tool seeded: %v", err)
	}
	// insert adds a 'high' scan command; keys "" is no host keys, later
	// schedules it a day ahead (not due).
	insert := func(tenant, status, payload, keys string, later bool) {
		t.Helper()
		var hk, at any
		if keys != "" {
			hk = keys
		}
		if later {
			at = "1 day"
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO commands (tenant_id, type, status, priority, payload, host_keys, scheduled_at)
			VALUES ($1, 'scan', $2, 'high', $3::jsonb, $4::text[], now() + $5::interval)`,
			tenant, status, payload, hk, at); err != nil {
			t.Fatal(err)
		}
	}
	depth := func(s OpsSnapshot, stage, tool, wait string) (n int64) {
		for _, d := range s.CommandQueue {
			if d.Stage == stage && d.Tool == tool && d.Class == "high" && d.Wait == wait {
				n += d.Count
			}
		}
		return n
	}

	before, err := ReadOpsSnapshot(ctx, tx)
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	const st = "ops.queue.test@1"
	ports := `{"capability":"` + st + `","scanner":"` + platformTool + `"}`
	// Tenant A: one ready, one waiting for a busy host (another of A's
	// commands runs on 203.0.113.9), one not due until a window opens, one
	// on a tenant's own tool, one expired (not counted).
	insert(tenantA.String(), "pending", ports, "{203.0.113.8}", false)
	insert(tenantA.String(), "running", ports, "{203.0.113.9}", false)
	insert(tenantA.String(), "pending", ports, "{203.0.113.9}", false)
	insert(tenantA.String(), "pending", ports, "", true)
	insert(tenantA.String(), "pending", `{"capability":"`+st+`","scanner":"tenant-made-tool-x"}`, "", false)
	if _, err := tx.ExecContext(ctx, `INSERT INTO commands (tenant_id, type, status, priority, payload, expires_at)
		VALUES ($1, 'scan', 'pending', 'high', $2::jsonb, now() - interval '1 minute')`, tenantA.String(), ports); err != nil {
		t.Fatal(err)
	}
	// Tenant B's running command on the same address never holds A back.
	insert(tenantB.String(), "running", ports, "{203.0.113.8}", false)
	insert(tenantB.String(), "pending", ports, "{203.0.113.7}", false)

	after, err := ReadOpsSnapshot(ctx, tx)
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	for _, c := range []struct {
		tool, wait string
		want       int64
	}{
		{platformTool, QueueWaitReady, 2}, // A's free host + B's
		{platformTool, QueueWaitHostBusy, 1},
		{platformTool, QueueWaitScheduled, 1},
		{opsQueueToolCustom, QueueWaitReady, 1},
	} {
		if got := depth(after, st, c.tool, c.wait) - depth(before, st, c.tool, c.wait); got != c.want {
			t.Errorf("%s/%s: +%d, want +%d", c.tool, c.wait, got, c.want)
		}
	}
	for _, d := range after.CommandQueue {
		if d.Tool == "tenant-made-tool-x" {
			t.Fatal("a tenant's own tool name reached the platform metrics")
		}
	}
	if got := after.CommandQueueTenants - before.CommandQueueTenants; got != 2 {
		t.Errorf("tenants with pending commands +%d, want +2", got)
	}
	if after.CommandQueueTopTenant < 4 {
		t.Errorf("top tenant pending = %d, want at least tenant A's 4", after.CommandQueueTopTenant)
	}
}
