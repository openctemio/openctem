package sla

import (
	"testing"
	"time"
)

// A new policy gives informational findings no SLA: no deadline from the
// severity window, and none from the priority class either.
func TestNewPolicy_InformationalHasNoSLA(t *testing.T) {
	p := newTestPolicy(t)
	if p.InfoDays() != NoSLA || p.InformationalHasSLA() {
		t.Fatalf("new policy info days = %d, want NoSLA", p.InfoDays())
	}
	now := time.Now().UTC()
	for _, sev := range []string{"info", "none"} {
		if d := p.CalculateDeadline(sev, now); !d.IsZero() {
			t.Errorf("CalculateDeadline(%s) = %v, want zero (no SLA)", sev, d)
		}
		for _, class := range []string{"", "P0", "P3"} {
			if d := p.CalculateDeadlineFor(class, sev, now); !d.IsZero() {
				t.Errorf("CalculateDeadlineFor(%q, %s) = %v, want zero (no SLA)", class, sev, d)
			}
		}
	}
	// Every other severity keeps its deadline.
	if d := p.CalculateDeadlineFor("P3", "low", now); d.IsZero() {
		t.Error("a low finding must still get a deadline")
	}
}

// A tenant that opts in (info days > 0) gets info deadlines back, priority
// class first as for every other severity.
func TestPolicy_InformationalSLAOptIn(t *testing.T) {
	p := newTestPolicy(t)
	if err := p.UpdateSLADays(2, 15, 30, 60, 120); err != nil {
		t.Fatalf("UpdateSLADays: %v", err)
	}
	now := time.Now().UTC()
	if got, want := p.CalculateDeadline("info", now), now.Add(120*24*time.Hour); !got.Equal(want) {
		t.Errorf("info deadline = %v, want %v", got, want)
	}
	if got, want := p.CalculateDeadlineFor("P3", "info", now), now.Add(30*24*time.Hour); !got.Equal(want) {
		t.Errorf("info P3 deadline = %v, want %v", got, want)
	}
}

func TestUpdateSLADays_InfoZeroAllowedNegativeRejected(t *testing.T) {
	p := newTestPolicy(t)
	if err := p.UpdateSLADays(2, 15, 30, 60, NoSLA); err != nil {
		t.Errorf("info = NoSLA rejected: %v", err)
	}
	if err := p.UpdateSLADays(2, 15, 30, 60, -1); err == nil {
		t.Error("negative info days accepted")
	}
	if err := p.UpdateSLADays(2, 15, 30, 0, 90); err == nil {
		t.Error("low = 0 accepted; only info may be NoSLA")
	}
}
