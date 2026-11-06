package cirun

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/cirun"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

type fakeSweepRepo struct {
	tenants   []shared.ID
	runs      map[shared.ID][]cirun.UnjudgedRun
	before    time.Time
	saved     map[shared.ID]string
	detail    map[shared.ID][]byte
	saveErr   map[shared.ID]error
	refreshed int
}

func (f *fakeSweepRepo) RetentionTenantsForPlatform(context.Context) ([]shared.ID, error) {
	return f.tenants, nil
}
func (f *fakeSweepRepo) UnjudgedRuns(_ context.Context, t shared.ID, before time.Time, _ int) ([]cirun.UnjudgedRun, error) {
	f.before = before
	return f.runs[t], nil
}
func (f *fakeSweepRepo) SaveVerdict(_ context.Context, _, id shared.ID, verdict string, detail []byte, _ time.Time, _ int, _ []string) error {
	if err := f.saveErr[id]; err != nil {
		return err
	}
	f.saved[id] = verdict
	f.detail[id] = detail
	return nil
}
func (f *fakeSweepRepo) RefreshPipeline(context.Context, shared.ID, shared.ID) error {
	f.refreshed++
	return nil
}

func TestSweepConcludesUnjudgedRunsAsFailNotPass(t *testing.T) {
	tenant, a, b, c := shared.NewID(), shared.NewID(), shared.NewID(), shared.NewID()
	pid := shared.NewID()
	f := &fakeSweepRepo{tenants: []shared.ID{tenant}, saved: map[shared.ID]string{}, detail: map[shared.ID][]byte{},
		saveErr: map[shared.ID]error{b: cirun.ErrRunEvaluated},
		runs: map[shared.ID][]cirun.UnjudgedRun{tenant: {
			{ID: a, PipelineID: &pid}, {ID: b}, {ID: c, OverCap: true}}}}
	now := time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)
	j := NewSweepJob(f, nil, nil)
	j.SetClock(func() time.Time { return now })
	res, err := j.Run(context.Background())
	if err != nil || res.Concluded != 2 {
		t.Fatalf("res=%+v err=%v", res, err)
	}
	// Only runs older than the pipeline window are listed.
	if want := now.Add(-MaxRunContinuation); !f.before.Equal(want) {
		t.Fatalf("window cutoff = %v, want %v", f.before, want)
	}
	if f.saved[a] != cirun.VerdictFail {
		t.Fatalf("verdict = %q, want fail", f.saved[a])
	}
	if _, ok := f.saved[b]; ok {
		t.Fatal("a run judged meanwhile was overwritten")
	}
	var v cirun.GateVerdict
	if err := json.Unmarshal(f.detail[a], &v); err != nil || len(v.Reasons) != 1 || v.Reasons[0].Code != cirun.ReasonNotJudged {
		t.Fatalf("detail = %s", f.detail[a])
	}
	// An over-cap run must name the cap or the repository refuses the verdict.
	if err := json.Unmarshal(f.detail[c], &v); err != nil || v.Reasons[len(v.Reasons)-1].Code != cirun.ReasonTooManyFindings {
		t.Fatalf("over-cap detail = %s", f.detail[c])
	}
	if f.refreshed != 1 {
		t.Fatalf("pipeline refreshed %d times, want 1", f.refreshed)
	}
}

func TestSweepSkipsRunThatChangedAndReportsOtherErrors(t *testing.T) {
	tenant, a := shared.NewID(), shared.NewID()
	f := &fakeSweepRepo{tenants: []shared.ID{tenant}, saved: map[shared.ID]string{}, detail: map[shared.ID][]byte{},
		saveErr: map[shared.ID]error{a: cirun.ErrRunChanged},
		runs:    map[shared.ID][]cirun.UnjudgedRun{tenant: {{ID: a}}}}
	n, err := NewSweepJob(f, nil, nil).SweepTenant(context.Background(), tenant)
	if err != nil || n != 0 {
		t.Fatalf("n=%d err=%v", n, err)
	}
	f.saveErr[a] = errors.New("db down")
	if _, err := NewSweepJob(f, nil, nil).SweepTenant(context.Background(), tenant); err == nil {
		t.Fatal("a store failure was swallowed")
	}
}
