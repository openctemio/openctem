package postgres

import (
	"context"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/internal/app/certmonitor"
)

// The CT sweep's rotation record round-trips through ct_monitor_state, an
// upsert replaces the row (clearing the back-off on recovery), and tenants
// never see each other's rows. Requires DATABASE_URL (CI applies every
// migration first).
func TestCTMonitorStateRepository_RoundTripAndIsolation(t *testing.T) {
	sqlDB := openSensorDB(t)
	ctx := context.Background()
	repo := NewCTMonitorStateRepository(&DB{DB: sqlDB})
	tenant := seedTestTenant(ctx, t, sqlDB)
	other := seedTestTenant(ctx, t, sqlDB)

	checked := time.Date(2026, 10, 2, 3, 0, 0, 0, time.UTC)
	next := checked.Add(12 * time.Hour)
	failed := certmonitor.DomainState{
		Domain: "example.com", LastCheckedAt: &checked, LastError: "crt.sh returned status 502",
		ConsecutiveFailures: 1, NextAttemptAt: &next,
	}
	if err := repo.SaveState(ctx, tenant, failed); err != nil {
		t.Fatalf("save: %v", err)
	}
	if err := repo.SaveState(ctx, other, certmonitor.DomainState{Domain: "other.com", LastCheckedAt: &checked}); err != nil {
		t.Fatalf("save other: %v", err)
	}

	got, err := repo.ListStates(ctx, tenant)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("tenant sees %d rows, want 1 (isolation): %+v", len(got), got)
	}
	st := got["example.com"]
	if st.ConsecutiveFailures != 1 || st.NextAttemptAt == nil || !st.NextAttemptAt.Equal(next) ||
		st.LastSuccessAt != nil || st.LastError == "" || !st.LastCheckedAt.Equal(checked) {
		t.Errorf("round trip = %+v", st)
	}

	// Recovery: success clears the back-off.
	success := checked.Add(24 * time.Hour)
	if err := repo.SaveState(ctx, tenant, certmonitor.DomainState{
		Domain: "example.com", LastCheckedAt: &success, LastSuccessAt: &success,
		LastSource: certmonitor.SourceCertSpotter, SubdomainsSeen: 7,
	}); err != nil {
		t.Fatal(err)
	}
	got, err = repo.ListStates(ctx, tenant)
	if err != nil {
		t.Fatal(err)
	}
	st = got["example.com"]
	if st.ConsecutiveFailures != 0 || st.NextAttemptAt != nil || st.LastError != "" ||
		st.LastSource != certmonitor.SourceCertSpotter || st.SubdomainsSeen != 7 || !st.LastSuccessAt.Equal(success) {
		t.Errorf("after recovery = %+v", st)
	}

	// The source column only takes the known sources.
	if err := repo.SaveState(ctx, tenant, certmonitor.DomainState{Domain: "x.com", LastSource: "shodan"}); err == nil {
		t.Error("unknown last_source accepted")
	}
}

// Two replicas: the second cannot take a tenant's sweep lock while the first
// holds it, other tenants are unaffected, and release frees it.
func TestCTMonitorStateRepository_TenantLock(t *testing.T) {
	sqlDB := openSensorDB(t)
	ctx := context.Background()
	a := NewCTMonitorStateRepository(&DB{DB: sqlDB})
	b := NewCTMonitorStateRepository(&DB{DB: sqlDB})
	tenant := seedTestTenant(ctx, t, sqlDB)
	other := seedTestTenant(ctx, t, sqlDB)

	release, ok, err := a.TryLockTenant(ctx, tenant)
	if err != nil || !ok {
		t.Fatalf("first lock: ok=%v err=%v", ok, err)
	}
	if _, ok, err := b.TryLockTenant(ctx, tenant); err != nil || ok {
		t.Fatalf("second replica took a held lock: ok=%v err=%v", ok, err)
	}
	relOther, ok, err := b.TryLockTenant(ctx, other)
	if err != nil || !ok {
		t.Fatalf("other tenant blocked: ok=%v err=%v", ok, err)
	}
	relOther()
	release()
	rel2, ok, err := b.TryLockTenant(ctx, tenant)
	if err != nil || !ok {
		t.Fatalf("lock not released: ok=%v err=%v", ok, err)
	}
	rel2()
}
