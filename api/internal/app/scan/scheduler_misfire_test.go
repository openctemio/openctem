package scan

import (
	"testing"
	"time"

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
