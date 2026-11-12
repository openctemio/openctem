package exposure

import (
	"errors"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func newHigh(t *testing.T) *ExposureEvent {
	t.Helper()
	e, err := NewExposureEvent(shared.NewID(), EventTypePortOpen, SeverityHigh, "Open port", "scanner", map[string]any{"port": 22})
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func TestOverrideKeepsReportedAndPeak(t *testing.T) {
	e := newHigh(t)
	by := shared.NewID()
	if err := e.OverrideSeverity(SeverityLow, "  behind VPN only  ", by, time.Now()); err != nil {
		t.Fatal(err)
	}
	if e.Severity() != SeverityLow || e.SourceSeverity() != SeverityHigh || !e.HasSeverityOverride() {
		t.Fatalf("effective %s reported %s override %v", e.Severity(), e.SourceSeverity(), e.HasSeverityOverride())
	}
	if p := e.SeverityProvenance(); p.OverrideReason != "behind VPN only" || p.OverriddenBy == nil || *p.OverriddenBy != by {
		t.Fatalf("provenance %+v", p)
	}
	if e.PeakSeverity() == SeverityLow {
		t.Fatal("an override must never lower the peak the four-eyes rule reads")
	}
	// A second override keeps the original reported severity.
	if err := e.OverrideSeverity(SeverityMedium, "re-rated", by, time.Now()); err != nil {
		t.Fatal(err)
	}
	if e.SourceSeverity() != SeverityHigh {
		t.Fatalf("reported severity lost: %s", e.SourceSeverity())
	}
	if err := e.RestoreReportedSeverity("scan agrees again", time.Now()); err != nil {
		t.Fatal(err)
	}
	if e.Severity() != SeverityHigh || e.HasSeverityOverride() {
		t.Fatalf("restore: %s %v", e.Severity(), e.HasSeverityOverride())
	}
}

func TestOverrideNeedsReasonActorAndValidSeverity(t *testing.T) {
	e := newHigh(t)
	if err := e.OverrideSeverity(SeverityLow, "  ", shared.NewID(), time.Now()); !errors.Is(err, ErrSeverityReasonRequired) {
		t.Errorf("blank reason: %v", err)
	}
	if err := e.OverrideSeverity(Severity("urgent"), "x", shared.NewID(), time.Now()); !errors.Is(err, shared.ErrValidation) {
		t.Errorf("bad severity: %v", err)
	}
	if err := e.OverrideSeverity(SeverityLow, "x", shared.ID{}, time.Now()); !errors.Is(err, shared.ErrValidation) {
		t.Errorf("no actor: %v", err)
	}
	if err := e.RestoreReportedSeverity("x", time.Now()); !errors.Is(err, ErrNoSeverityOverride) {
		t.Errorf("restore without override: %v", err)
	}
	if e.Severity() != SeverityHigh {
		t.Error("a refused change must not change the severity")
	}
}

func TestInProgressState(t *testing.T) {
	e := newHigh(t)
	if err := e.StartProgress(); err != nil {
		t.Fatal(err)
	}
	if e.State() != StateInProgress || !e.State().IsOpen() || e.State().IsClosed() {
		t.Fatalf("state %s", e.State())
	}
	if err := e.StartProgress(); err == nil {
		t.Error("in_progress -> in_progress must be refused")
	}
	if err := e.Reactivate(); err != nil || e.State() != StateActive {
		t.Fatalf("back to active: %v %s", err, e.State())
	}
	_ = e.Resolve(shared.NewID(), "fixed")
	if err := e.StartProgress(); err == nil {
		t.Error("a resolved exposure cannot be in progress")
	}
	for _, s := range OpenStates() {
		if !s.IsOpen() {
			t.Errorf("%s must be open", s)
		}
	}
}
