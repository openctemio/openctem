package postgres

import (
	"context"
	"testing"
	"time"
)

// research/22 P0-11: run-now is once per window per tenant across replicas
// (the lease outlives the request), tenants do not share it, and freshness
// is per tenant.
func TestEASMSweepRepository(t *testing.T) {
	sqlDB := openSensorDB(t)
	ctx := context.Background()
	r := NewEASMSweepRepository(&DB{DB: sqlDB})
	a := seedTestTenant(ctx, t, sqlDB)
	b := seedTestTenant(ctx, t, sqlDB)

	if until, err := r.RunNowAvailableAt(ctx, a); err != nil || !until.IsZero() {
		t.Fatalf("fresh tenant: %v %v", until, err)
	}
	ok, _, err := r.Acquire(ctx, a, 15*time.Minute)
	if err != nil || !ok {
		t.Fatalf("first: %v %v", ok, err)
	}
	ok, until, err := r.Acquire(ctx, a, 15*time.Minute)
	if err != nil || ok || until.Before(time.Now().Add(14*time.Minute)) {
		t.Fatalf("second: ok=%v until=%v err=%v", ok, until, err)
	}
	if ok, _, err := r.Acquire(ctx, b, 15*time.Minute); err != nil || !ok {
		t.Fatalf("tenant B shares tenant A's window: %v %v", ok, err)
	}
	// Expired window: allowed again.
	if _, err := sqlDB.ExecContext(ctx, `UPDATE controller_leases SET expires_at = now() - interval '1 second' WHERE name = $1`,
		runNowLease(a)); err != nil {
		t.Fatal(err)
	}
	if ok, _, err := r.Acquire(ctx, a, 15*time.Minute); err != nil || !ok {
		t.Fatalf("after the window: %v %v", ok, err)
	}

	if _, err := sqlDB.ExecContext(ctx, `INSERT INTO ct_monitor_state (tenant_id, domain, last_checked_at) VALUES ($1, 'a.example', now())`, a.String()); err != nil {
		t.Fatal(err)
	}
	ct, dns, err := r.Freshness(ctx, a)
	if err != nil || ct == nil || dns != nil {
		t.Fatalf("freshness A: %v %v %v", ct, dns, err)
	}
	if ct, _, _ := r.Freshness(ctx, b); ct != nil {
		t.Fatal("tenant B sees tenant A's CT run")
	}
}
