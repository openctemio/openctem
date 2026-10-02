package postgres

import (
	"context"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/reportschedule"
)

// Create did not write next_run_at, so every new schedule was stored with NULL
// and the scheduler (ListDue: next_run_at IS NULL ... NULLS FIRST) sent it on
// its next tick, whatever the cron said. The computed first slot must persist,
// and a not-yet-due schedule must not be listed as due.
func TestReportScheduleRepository_CreatePersistsNextRun(t *testing.T) {
	db := openGroupsDB(t)
	ctx := context.Background()
	tenant := seedTestTenant(ctx, t, db)
	repo := NewReportScheduleRepository(&DB{DB: db})

	s, err := reportschedule.NewReportSchedule(tenant, "Daily", "executive_summary", "pdf", "0 9 * * *")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Update("", "executive_summary", "pdf", "0 9 * * *", "Asia/Ho_Chi_Minh"); err != nil {
		t.Fatal(err)
	}
	if err := repo.Create(ctx, s); err != nil {
		t.Fatalf("create: %v", err)
	}
	t.Cleanup(func() { _ = repo.Delete(context.Background(), tenant, s.ID()) })

	got, err := repo.GetByID(ctx, tenant, s.ID())
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.NextRunAt() == nil {
		t.Fatal("next_run_at was not persisted; the scheduler sends a NULL next run immediately")
	}
	if !got.NextRunAt().Equal(s.NextRunAt().Truncate(time.Microsecond)) && !got.NextRunAt().Equal(*s.NextRunAt()) {
		t.Fatalf("persisted next run %v, want %v", got.NextRunAt(), s.NextRunAt())
	}

	due, err := repo.ListDue(ctx, time.Now())
	if err != nil {
		t.Fatalf("list due: %v", err)
	}
	for _, d := range due {
		if d.ID() == s.ID() {
			t.Fatal("a freshly created schedule is listed as due before its first cron slot")
		}
	}
}
