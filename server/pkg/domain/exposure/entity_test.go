package exposure

import "testing"

func TestPeakSeverityNeverLowers(t *testing.T) {
	e := &ExposureEvent{severity: SeverityLow}
	if e.PeakSeverity() != SeverityLow {
		t.Fatalf("no stored peak: %s", e.PeakSeverity())
	}
	e.WithPeakSeverity(SeverityCritical)
	if e.PeakSeverity() != SeverityCritical || !NeedsSecondApprover(e.PeakSeverity()) {
		t.Fatalf("stored peak ignored: %s", e.PeakSeverity())
	}
	if err := e.UpdateSeverity(SeverityInfo); err != nil || e.PeakSeverity() != SeverityCritical {
		t.Fatalf("lowering the severity lowered the peak: %v %s", err, e.PeakSeverity())
	}
	e.WithPeakSeverity(Severity("bogus"))
	if e.PeakSeverity() != SeverityCritical {
		t.Fatal("an invalid stored peak replaced the peak")
	}
}
