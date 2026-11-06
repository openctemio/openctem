package sla

import (
	"context"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// daysCalc returns start + days(class), like the real policy lookup.
type daysCalc struct {
	days   map[string]int
	starts []time.Time
}

func (c *daysCalc) CalculateSLADeadlineForPriority(_ context.Context, _, _, class string, _ vulnerability.Severity, start time.Time) (time.Time, error) {
	c.starts = append(c.starts, start)
	return start.Add(time.Duration(c.days[class]) * 24 * time.Hour), nil
}

func policy() *daysCalc {
	return &daysCalc{days: map[string]int{"P0": 7, "P1": 30, "P2": 60, "P3": 90}}
}

func withDeadline(t *testing.T, class string, deadline time.Time) *vulnerability.Finding {
	t.Helper()
	f := newAppliedFinding(t, class, vulnerability.SeverityHigh)
	f.SetSLADeadline(deadline)
	return f
}

func TestSLAApplier_FirstDeadlineFromDetection(t *testing.T) {
	calc := policy()
	f := newAppliedFinding(t, "P1", vulnerability.SeverityHigh)
	if err := NewApplier(calc).ApplyBatch(context.Background(), shared.NewID(), []*vulnerability.Finding{f}); err != nil {
		t.Fatal(err)
	}
	want := f.FirstDetectedAt().Add(30 * 24 * time.Hour)
	if f.SLADeadline() == nil || !f.SLADeadline().Equal(want) {
		t.Fatalf("deadline = %v, want %v", f.SLADeadline(), want)
	}
}

// A priority rise late in a finding's life: min(old, now + new SLA), never
// a deadline in the past.
func TestSLAApplier_PriorityUpTightensFromNow(t *testing.T) {
	old := time.Now().Add(30 * 24 * time.Hour)
	f := withDeadline(t, "P0", old) // class already raised to P0; deadline from P3
	before := time.Now()
	if err := NewApplier(policy()).ApplyBatch(context.Background(), shared.NewID(), []*vulnerability.Finding{f}); err != nil {
		t.Fatal(err)
	}
	got := *f.SLADeadline()
	lo, hi := before.Add(7*24*time.Hour), time.Now().Add(7*24*time.Hour)
	if got.Before(lo) || got.After(hi) {
		t.Fatalf("deadline = %v, want now + 7 days", got)
	}
}

// A priority drop or a longer policy never moves the deadline later.
func TestSLAApplier_PriorityDownKeepsDeadline(t *testing.T) {
	old := time.Now().Add(3 * 24 * time.Hour).UTC().Truncate(time.Second)
	f := withDeadline(t, "P3", old)
	if err := NewApplier(policy()).ApplyBatch(context.Background(), shared.NewID(), []*vulnerability.Finding{f}); err != nil {
		t.Fatal(err)
	}
	if !f.SLADeadline().Equal(old) {
		t.Fatalf("deadline moved to %v, want it kept at %v", f.SLADeadline(), old)
	}
}

// An overdue finding stays overdue when its priority drops.
func TestSLAApplier_OverdueStaysOverdueOnDrop(t *testing.T) {
	old := time.Now().Add(-48 * time.Hour)
	f := withDeadline(t, "P3", old)
	if err := NewApplier(policy()).ApplyBatch(context.Background(), shared.NewID(), []*vulnerability.Finding{f}); err != nil {
		t.Fatal(err)
	}
	if !f.SLADeadline().Equal(old) || f.SLAStatus() != vulnerability.SLAStatusOverdue {
		t.Fatalf("deadline=%v status=%s, want the old deadline and overdue", f.SLADeadline(), f.SLAStatus())
	}
}

func TestSLAApplier_ClosedFindingKeepsDeadline(t *testing.T) {
	old := time.Now().Add(60 * 24 * time.Hour).UTC().Truncate(time.Second)
	f := withDeadline(t, "P0", old)
	if err := f.TransitionStatus(vulnerability.FindingStatusFalsePositive, "fp", nil); err != nil {
		t.Fatal(err)
	}
	calc := policy()
	if err := NewApplier(calc).ApplyBatch(context.Background(), shared.NewID(), []*vulnerability.Finding{f}); err != nil {
		t.Fatal(err)
	}
	if !f.SLADeadline().Equal(old) || len(calc.starts) != 0 {
		t.Fatalf("closed finding: deadline=%v calls=%d", f.SLADeadline(), len(calc.starts))
	}
}
