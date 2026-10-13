package scanrun

import (
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/scanrun"
)

// The 2026-10-13 incident: nuclei was dispatched with 2 minutes left on the
// run's clock and canceled 7 seconds later. With less than the tool's least
// useful time left, the step is refused; with enough, or with no deadline,
// it is admitted.
func TestDeadlineTooClose(t *testing.T) {
	now := time.Date(2026, 10, 13, 13, 53, 2, 0, time.UTC)
	at := func(d time.Duration) *scanrun.Run {
		dl := now.Add(d)
		return &scanrun.Run{DeadlineAt: &dl}
	}
	if e := deadlineTooClose(at(2*time.Minute), "nuclei", now); e == nil {
		t.Fatal("nuclei with 2m left was admitted")
	} else if e.left != 2*time.Minute || e.need != 7*time.Minute {
		t.Fatalf("left %s need %s", e.left, e.need)
	}
	if e := deadlineTooClose(at(-time.Minute), "nuclei", now); e == nil || e.left != 0 {
		t.Fatalf("past deadline: %+v", e)
	}
	if e := deadlineTooClose(at(8*time.Minute), "nuclei", now); e != nil {
		t.Fatalf("nuclei with 8m left refused: %v", e)
	}
	if e := deadlineTooClose(at(2*time.Minute), "dnsx", now); e != nil {
		t.Fatalf("dnsx (17s least useful) with 2m left refused: %v", e)
	}
	if e := deadlineTooClose(&scanrun.Run{}, "nuclei", now); e != nil {
		t.Fatalf("run without deadline refused: %v", e)
	}
	if e := deadlineTooClose(nil, "nuclei", now); e != nil {
		t.Fatal("nil run refused")
	}
}
