package scan

import (
	"context"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

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

func (r *claimingScanRepo) ClaimScheduledRun(context.Context, shared.ID, time.Time, *time.Time) (bool, error) {
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
