package scan

import (
	"context"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/scanworkflow"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/openctemio/openctem/api/internal/metrics"
	"github.com/openctemio/openctem/api/pkg/domain/scan"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

type deferringScanRepo struct {
	scan.Repository
	from  *time.Time
	until time.Time
	calls int
}

func (r *deferringScanRepo) DeferScheduledRun(_ context.Context, _, _ shared.ID, from *time.Time, until time.Time) (bool, error) {
	r.calls++
	r.from, r.until = from, until
	return true, nil
}

// A scheduled occurrence stopped by a freeze window moves next_run_at from
// the claimed next occurrence to the window's end, and is counted.
func TestScheduler_FrozenOccurrenceIsDeferredToTheWindowEnd(t *testing.T) {
	sc, err := scan.NewScan(shared.NewID(), "frozen", shared.NewID(), scan.ScanTypeSingle)
	if err != nil {
		t.Fatal(err)
	}
	repo := &deferringScanRepo{}
	s := &ScanScheduler{scanRepo: repo, scanService: &Service{logger: logger.NewNop()}, logger: logger.NewNop()}
	next := time.Now().Add(time.Hour).UTC()
	until := time.Now().Add(3 * time.Hour).UTC()

	c := metrics.ScanScheduleOutcomes.WithLabelValues("deferred_freeze")
	before := testutil.ToFloat64(c)
	s.deferFrozen(context.Background(), sc, &next, &FrozenError{WindowID: shared.NewID(), WindowName: "w", Until: until})
	if repo.calls != 1 || repo.from == nil || !repo.from.Equal(next) || !repo.until.Equal(until) {
		t.Fatalf("deferral = %d calls from %v to %v, want %v -> %v", repo.calls, repo.from, repo.until, next, until)
	}
	if got := testutil.ToFloat64(c) - before; got != 1 {
		t.Errorf("deferred_freeze counted %v, want 1", got)
	}
}

func TestWorkflowActive(t *testing.T) {
	step := func(tool string, caps ...string) *scanworkflow.Step {
		return &scanworkflow.Step{Tool: tool, Capabilities: caps}
	}
	cases := []struct {
		name  string
		steps []*scanworkflow.Step
		want  bool
	}{
		{"passive tools only", []*scanworkflow.Step{step("subfinder"), step("dnsx")}, false},
		{"passive capability", []*scanworkflow.Step{step("", "discover.subdomains")}, false},
		{"an active tool", []*scanworkflow.Step{step("subfinder"), step("nuclei")}, true},
		{"an active capability", []*scanworkflow.Step{step("", "probe.http")}, true},
		{"unknown capability counts as active", []*scanworkflow.Step{step("", "recon")}, true},
		{"unknown tool counts as active", []*scanworkflow.Step{step("custom-scanner")}, true},
	}
	for _, tc := range cases {
		if got := workflowActive(tc.steps); got != tc.want {
			t.Errorf("%s: workflowActive = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestFrozenError(t *testing.T) {
	err := error(&FrozenError{WindowName: "w", Until: time.Date(2026, 10, 5, 6, 0, 0, 0, time.UTC)})
	if AsFrozen(err) == nil || !isConflict(err) {
		t.Errorf("FrozenError = %v, want a conflict found by AsFrozen", err)
	}
}

func isConflict(err error) bool {
	de, ok := AsFrozen(err).Unwrap().(*shared.DomainError)
	return ok && de.Code == CodeScanFrozen && de.Err == shared.ErrConflict
}
