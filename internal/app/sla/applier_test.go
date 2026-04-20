package sla

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/vulnerability"
)

// F3 WIRE tests. The applier is the piece that connects the SLA
// domain primitive to the ingest pipeline. Tests here exercise ONLY
// the applier's orchestration via a fake calculator — the real SLA
// calculation paths are covered in pkg/domain/sla + sla_service_test.

type fakeCalc struct {
	deadline time.Time
	err      error
	calls    int
	lastClass string
	lastSev  vulnerability.Severity
}

func (f *fakeCalc) CalculateSLADeadlineForPriority(
	_ context.Context,
	_, _, priorityClass string,
	severity vulnerability.Severity,
	_ time.Time,
) (time.Time, error) {
	f.calls++
	f.lastClass = priorityClass
	f.lastSev = severity
	if f.err != nil {
		return time.Time{}, f.err
	}
	return f.deadline, nil
}

func newAppliedFinding(t *testing.T, priorityClass string, severity vulnerability.Severity) *vulnerability.Finding {
	t.Helper()
	f, err := vulnerability.NewFinding(
		shared.NewID(), shared.NewID(),
		vulnerability.FindingSourceManual, "T-1",
		severity, "test",
	)
	if err != nil {
		t.Fatalf("new finding: %v", err)
	}
	if priorityClass != "" {
		pc := vulnerability.PriorityClass(priorityClass)
		f.SetPriorityClassification(pc, "test")
	}
	return f
}

func TestSLAApplier_NilCalculatorNoOp(t *testing.T) {
	a := NewApplier(nil)
	if err := a.ApplyBatch(context.Background(), shared.NewID(), []*vulnerability.Finding{
		newAppliedFinding(t, "P0", vulnerability.SeverityCritical),
	}); err != nil {
		t.Fatalf("nil calc should be safe, got %v", err)
	}
}

func TestSLAApplier_EmptyBatchNoOp(t *testing.T) {
	a := NewApplier(&fakeCalc{})
	if err := a.ApplyBatch(context.Background(), shared.NewID(), nil); err != nil {
		t.Fatalf("empty batch should be safe: %v", err)
	}
}

func TestSLAApplier_SetsDeadlineOnFinding(t *testing.T) {
	deadline := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	calc := &fakeCalc{deadline: deadline}
	a := NewApplier(calc)

	f := newAppliedFinding(t, "P0", vulnerability.SeverityCritical)
	if err := a.ApplyBatch(context.Background(), shared.NewID(), []*vulnerability.Finding{f}); err != nil {
		t.Fatalf("%v", err)
	}
	if f.SLADeadline() == nil || !f.SLADeadline().Equal(deadline) {
		t.Fatalf("deadline not written: got %v", f.SLADeadline())
	}
}

func TestSLAApplier_PassesPriorityClassThrough(t *testing.T) {
	calc := &fakeCalc{deadline: time.Now().Add(48 * time.Hour)}
	a := NewApplier(calc)
	f := newAppliedFinding(t, "P1", vulnerability.SeverityHigh)
	_ = a.ApplyBatch(context.Background(), shared.NewID(), []*vulnerability.Finding{f})

	if calc.lastClass != "P1" {
		t.Fatalf("priority class not passed: got %q", calc.lastClass)
	}
	if calc.lastSev != vulnerability.SeverityHigh {
		t.Fatalf("severity not passed: got %q", calc.lastSev)
	}
}

func TestSLAApplier_EmptyClassWhenUnset(t *testing.T) {
	// Legacy finding with no priority class → applier passes "" and
	// the calculator falls back to severity.
	calc := &fakeCalc{deadline: time.Now().Add(48 * time.Hour)}
	a := NewApplier(calc)
	f := newAppliedFinding(t, "", vulnerability.SeverityHigh)
	_ = a.ApplyBatch(context.Background(), shared.NewID(), []*vulnerability.Finding{f})

	if calc.lastClass != "" {
		t.Fatalf("expected empty class, got %q", calc.lastClass)
	}
}

func TestSLAApplier_PartialFailure_Tolerated(t *testing.T) {
	// 2 findings, calculator works for both → no error. We verify
	// that the applier does NOT return error when SOME findings
	// apply successfully.
	calc := &fakeCalc{deadline: time.Now().Add(24 * time.Hour)}
	a := NewApplier(calc)
	findings := []*vulnerability.Finding{
		newAppliedFinding(t, "P0", vulnerability.SeverityCritical),
		newAppliedFinding(t, "P2", vulnerability.SeverityMedium),
	}
	if err := a.ApplyBatch(context.Background(), shared.NewID(), findings); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if calc.calls != 2 {
		t.Fatalf("calc called %d times, want 2", calc.calls)
	}
}

func TestSLAApplier_AllFailed_ReturnsError(t *testing.T) {
	// Calculator always errors → all failed → error returned so
	// caller can log/alert.
	calc := &fakeCalc{err: errors.New("policy lookup failed")}
	a := NewApplier(calc)
	findings := []*vulnerability.Finding{
		newAppliedFinding(t, "P0", vulnerability.SeverityCritical),
		newAppliedFinding(t, "P3", vulnerability.SeverityLow),
	}
	err := a.ApplyBatch(context.Background(), shared.NewID(), findings)
	if err == nil {
		t.Fatal("all-failed batch must return error")
	}
	// None of the findings should have had a deadline set.
	for _, f := range findings {
		if f.SLADeadline() != nil {
			t.Fatalf("no deadline should be set on failed findings")
		}
	}
}
