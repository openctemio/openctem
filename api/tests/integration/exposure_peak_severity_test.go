package integration

import (
	"context"
	"testing"

	exposureapp "github.com/openctemio/openctem/api/internal/app/exposure"
	"github.com/openctemio/openctem/api/pkg/domain/exposure"
)

// The two-approver rule of a high or critical exposure is decided on the
// highest severity the exposure ever had, not the current one: re-ingesting
// the same exposure (same fingerprint) with a lower severity must not let one
// person accept or dismiss it alone.
func TestExposureDisposition_ReingestAsLowerSeverityKeepsTwoApprovers(t *testing.T) {
	f := newDispositionFixture(t)
	ctx := context.Background()
	in := exposureapp.CreateExposureInput{
		TenantID: f.a.String(), EventType: "port_open", Severity: "critical",
		Title: "peak severity RDP open", Source: "manual", Details: map[string]any{"port": 3389},
	}
	ev, err := f.svc.IngestExposure(ctx, in)
	if err != nil {
		t.Fatalf("ingest critical: %v", err)
	}

	// A critical exposure needs a second approver: the first call only requests.
	out, err := f.call(f.a, ev.ID(), f.u1, exposure.StateAccepted)
	if err != nil || !out.Pending {
		t.Fatalf("critical accept by u1: pending=%v err=%v (want pending)", out != nil && out.Pending, err)
	}

	// The same person re-ingests the same exposure as low.
	in.Severity = "low"
	if _, err := f.svc.IngestExposure(ctx, in); err != nil {
		t.Fatalf("re-ingest low: %v", err)
	}
	var sev, peak string
	if err := f.db.QueryRow(`SELECT severity, COALESCE(peak_severity, '') FROM exposure_events WHERE id = $1`, ev.ID().String()).Scan(&sev, &peak); err != nil {
		t.Fatal(err)
	}
	if sev != "low" || peak != "critical" {
		t.Fatalf("after re-ingest severity=%s peak=%s, want low / critical", sev, peak)
	}

	// Accepting again as the same person is still not enough on their own.
	out, err = f.call(f.a, ev.ID(), f.u1, exposure.StateAccepted)
	if err == nil && !out.Pending {
		t.Fatalf("one person accepted a once-critical exposure alone after lowering its severity (state=%s)", f.state(t, ev.ID()))
	}
	if s := f.state(t, ev.ID()); s != "active" {
		t.Fatalf("state = %s, want active", s)
	}

	// A second approver can still confirm the pending request.
	out, err = f.call(f.a, ev.ID(), f.u2, exposure.StateAccepted)
	if err != nil || out.Pending || f.state(t, ev.ID()) != "accepted" {
		t.Fatalf("second approver: err=%v out=%+v state=%s", err, out, f.state(t, ev.ID()))
	}

	// A fresh low exposure that was never higher is still a one-step decision.
	lowIn := in
	lowIn.Title = "peak severity banner"
	low, err := f.svc.IngestExposure(ctx, lowIn)
	if err != nil {
		t.Fatal(err)
	}
	if out, err := f.call(f.a, low.ID(), f.u1, exposure.StateAccepted); err != nil || out.Pending {
		t.Fatalf("never-high exposure: err=%v pending=%v, want applied", err, out != nil && out.Pending)
	}

	// A re-ingest never lowers the peak, and a higher one raises it.
	in.Severity = "high"
	if _, err := f.svc.IngestExposure(ctx, in); err != nil {
		t.Fatal(err)
	}
	_ = f.db.QueryRow(`SELECT severity, COALESCE(peak_severity, '') FROM exposure_events WHERE id = $1`, ev.ID().String()).Scan(&sev, &peak)
	if sev != "high" || peak != "critical" {
		t.Fatalf("severity=%s peak=%s, want high / critical", sev, peak)
	}
}
