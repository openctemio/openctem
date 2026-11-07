package scan

import (
	"context"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/openctemio/openctem/api/internal/app/outbox"

	"github.com/openctemio/openctem/api/internal/metrics"
	"github.com/openctemio/openctem/api/pkg/logger"

	"github.com/openctemio/openctem/api/pkg/domain/scan"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Misfire grace (RFC-046 §6.1): an occurrence is skipped only when the next
// one is also already due.
func TestIsMisfire(t *testing.T) {
	sc, err := scan.NewScan(shared.NewID(), "misfire", shared.NewID(), scan.ScanTypeSingle)
	if err != nil {
		t.Fatal(err)
	}
	sc.Status = scan.StatusActive
	if err := sc.SetSchedule(scan.ScheduleCrontab, "0 * * * *", nil, nil, "UTC"); err != nil {
		t.Fatal(err)
	}
	occ := time.Date(2026, 10, 4, 10, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		now  time.Time
		want bool
	}{
		{occ.Add(30 * time.Second), false}, // on time
		{occ.Add(59 * time.Minute), false}, // late, but the next is not due
		{occ.Add(61 * time.Minute), true},  // the 11:00 occurrence is due too
	} {
		if got := isMisfire(sc, occ, tc.now); got != tc.want {
			t.Errorf("isMisfire at %s = %v, want %v", tc.now.Format("15:04"), got, tc.want)
		}
	}
	// A legacy every-minute crontab is spaced to 15 minutes: a scheduler a
	// few minutes late is not a misfire.
	sc.ScheduleCron = "* * * * *"
	if isMisfire(sc, occ, occ.Add(5*time.Minute)) {
		t.Error("a 5-minute delay of an every-minute crontab counted as a misfire")
	}
}

// claimingScanRepo grants every claim and counts them.
type claimingScanRepo struct {
	scan.Repository
	claims int
}

func (r *claimingScanRepo) ClaimScheduledRun(context.Context, shared.ID, shared.ID, time.Time, *time.Time) (bool, error) {
	r.claims++
	return true, nil
}

// The scheduler's misfire path end to end: the occurrence is claimed and
// skipped (never triggered), and counted as skipped_misfire. Runs the real
// metric call, so a label-count mismatch panics here, not in production.
func TestScheduler_MisfiredOccurrenceIsSkippedAndCounted(t *testing.T) {
	sc, err := scan.NewScan(shared.NewID(), "misfire e2e", shared.NewID(), scan.ScanTypeSingle)
	if err != nil {
		t.Fatal(err)
	}
	sc.Status = scan.StatusActive
	if err := sc.SetSchedule(scan.ScheduleCrontab, "0 * * * *", nil, nil, "UTC"); err != nil {
		t.Fatal(err)
	}
	// Due three hours ago: the next two occurrences are due too.
	occ := time.Now().UTC().Truncate(time.Hour).Add(-3 * time.Hour)
	sc.NextRunAt = &occ

	repo := &claimingScanRepo{}
	// A nil-dependency Service: reaching TriggerScan would panic, so the
	// test also proves the misfire is never triggered.
	s := &ScanScheduler{scanRepo: repo, scanService: &Service{logger: logger.NewNop()}, logger: logger.NewNop()}

	c := metrics.ScanScheduleOutcomes.WithLabelValues("skipped_misfire")
	before := testutil.ToFloat64(c)
	s.triggerScan(sc)
	if repo.claims != 1 {
		t.Fatalf("claims = %d, want the occurrence claimed once", repo.claims)
	}
	if got := testutil.ToFloat64(c) - before; got != 1 {
		t.Fatalf("skipped_misfire counted %v, want 1", got)
	}
}

// A one-off run has no following occurrence: it still starts when somewhat
// late, and is skipped once it is later than OnceMisfireGrace.
func TestIsMisfire_Once(t *testing.T) {
	sc, err := scan.NewScan(shared.NewID(), "once", shared.NewID(), scan.ScanTypeSingle)
	if err != nil {
		t.Fatal(err)
	}
	sc.Status = scan.StatusActive
	runAt := time.Now().Add(time.Hour)
	if err := sc.SetOnceSchedule(&runAt, "UTC", time.Now()); err != nil {
		t.Fatal(err)
	}
	if isMisfire(sc, runAt, runAt.Add(5*time.Minute)) {
		t.Error("5 minutes late: skipped, want run")
	}
	if !isMisfire(sc, runAt, runAt.Add(scan.OnceMisfireGrace+time.Minute)) {
		t.Error("past the grace: run, want skipped")
	}
}

// misfireRepo grants claims and keeps the misfire notes, per tenant and scan.
type misfireRepo struct {
	claimingScanRepo
	notes  map[string]string // tenant/scan -> reason
	clears int
	missed []time.Time
}

func (r *misfireRepo) RecordScheduleMisfire(_ context.Context, tenantID, id shared.ID, at time.Time, reason string) error {
	if r.notes == nil {
		r.notes = map[string]string{}
	}
	r.notes[tenantID.String()+"/"+id.String()] = reason
	r.missed = append(r.missed, at)
	return nil
}

func (r *misfireRepo) ClearScheduleMisfire(context.Context, shared.ID, shared.ID) error {
	r.clears++
	return nil
}

type fakeMissEvents struct{ got []outbox.EnqueueParams }

func (f *fakeMissEvents) Enqueue(_ context.Context, p outbox.EnqueueParams) error {
	f.got = append(f.got, p)
	return nil
}

func newMisfiredScan(t *testing.T) (*scan.Scan, time.Time) {
	t.Helper()
	sc, err := scan.NewScan(shared.NewID(), "misfire note", shared.NewID(), scan.ScanTypeSingle)
	if err != nil {
		t.Fatal(err)
	}
	sc.Status = scan.StatusActive
	if err := sc.SetSchedule(scan.ScheduleCrontab, "0 * * * *", nil, nil, "UTC"); err != nil {
		t.Fatal(err)
	}
	occ := time.Now().UTC().Truncate(time.Hour).Add(-3 * time.Hour)
	sc.NextRunAt = &occ
	return sc, occ
}

// 468 P0-9: a misfire is recorded on the scan (its tenant and id) and one
// scan.schedule_missed event is enqueued, tenant-scoped, without secrets.
func TestScheduler_MisfireIsRecordedAndAnnouncedOnce(t *testing.T) {
	sc, occ := newMisfiredScan(t)
	repo := &misfireRepo{}
	ev := &fakeMissEvents{}
	s := &ScanScheduler{scanRepo: repo, scanService: &Service{logger: logger.NewNop(), misfireEvents: ev}, logger: logger.NewNop()}

	s.triggerScan(sc)

	key := sc.TenantID.String() + "/" + sc.ID.String()
	if repo.notes[key] != scan.MissReasonPlatformUnavailable || len(repo.notes) != 1 {
		t.Fatalf("notes = %v, want one for %s", repo.notes, key)
	}
	if len(repo.missed) != 1 || !repo.missed[0].Equal(occ) {
		t.Fatalf("missed occurrence = %v, want %v", repo.missed, occ)
	}
	if len(ev.got) != 1 {
		t.Fatalf("events = %d, want exactly one per missed occurrence", len(ev.got))
	}
	e := ev.got[0]
	if e.EventType != "scan.schedule_missed" || e.TenantID != sc.TenantID {
		t.Fatalf("event = %q tenant %s", e.EventType, e.TenantID)
	}
	if e.Metadata["scan_id"] != sc.ID.String() || e.Metadata["missed_at"] != occ.Format(time.RFC3339) || e.Metadata["next_run_at"] == nil {
		t.Fatalf("payload = %v", e.Metadata)
	}
	if repo.clears != 0 {
		t.Fatal("a misfire cleared the note")
	}
}

// A scan that was not late records nothing and sends nothing; the earlier
// note clears once the scheduled run starts (here the trigger path is not
// reached without a full service, so the on-time check uses isMisfire).
func TestScheduler_OnTimeOccurrenceRecordsNoMisfire(t *testing.T) {
	sc, _ := newMisfiredScan(t)
	onTime := time.Now().UTC().Truncate(time.Hour)
	if isMisfire(sc, onTime, onTime.Add(20*time.Second)) {
		t.Fatal("an on-time occurrence counted as a misfire")
	}
	repo := &misfireRepo{}
	ev := &fakeMissEvents{}
	s := &ScanScheduler{scanRepo: repo, scanService: &Service{logger: logger.NewNop(), misfireEvents: ev}, logger: logger.NewNop()}
	s.clearMisfire(context.Background(), sc) // no note on the scan: nothing to clear
	if repo.clears != 0 || len(repo.notes) != 0 || len(ev.got) != 0 {
		t.Fatalf("on-time path wrote: clears=%d notes=%v events=%d", repo.clears, repo.notes, len(ev.got))
	}
	at := time.Now()
	sc.LastMissedAt = &at
	s.clearMisfire(context.Background(), sc)
	if repo.clears != 1 {
		t.Fatalf("clears = %d, want 1 once a run started after a misfire", repo.clears)
	}
}
