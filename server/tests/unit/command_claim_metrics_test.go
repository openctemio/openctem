package unit

import (
	"context"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	dto "github.com/prometheus/client_model/go"

	"github.com/openctemio/openctem/api/internal/app/command"
	"github.com/openctemio/openctem/api/internal/metrics"
	commanddom "github.com/openctemio/openctem/api/pkg/domain/command"
)

// histCount is the number of observations of one histogram series.
func histCount(t *testing.T, h *prometheus.HistogramVec, label string) uint64 {
	t.Helper()
	m := &dto.Metric{}
	if err := h.WithLabelValues(label).(prometheus.Metric).Write(m); err != nil {
		t.Fatal(err)
	}
	return m.GetHistogram().GetSampleCount()
}

// The poll's claim (claim-N) counts every command it hands out under
// mode "claim_n" (it was never counted before), observes its latency and
// each command's wait, and counts the candidates it left out by reason.
func TestClaimMetrics_ClaimN(t *testing.T) {
	f := newRecheckFixture()
	f.gate.excluded["a.example.com"] = true
	f.gate.excluded["b.example.com"] = true
	f.gate.excluded["c.example.com"] = true
	for range 2 {
		c := f.repo.add(f.tenant, commanddom.CommandTypeScan, `{"scanner":"nuclei","targets":["x.example.com"]}`, nil)
		c.Priority = commanddom.CommandPriorityHigh
	}
	f.repo.add(f.tenant, commanddom.CommandTypeScan, stepPayload, &commanddom.DispatchGate{Tier: 1}) // nothing left after the re-check

	claimed := testutil.ToFloat64(metrics.CommandClaimsTotal.WithLabelValues("claim_n"))
	scope := testutil.ToFloat64(metrics.CommandClaimSkippedTotal.WithLabelValues("scope_changed"))
	polls := histCount(t, metrics.CommandClaimDuration, "claim_n")
	waits := histCount(t, metrics.CommandClaimWait, "high")

	cmds, err := f.svc.Claim(context.Background(), command.ClaimInput{TenantID: f.tenant.String(), SensorID: f.sensor.String(), Limit: 10, MaxJobs: 10})
	if err != nil || len(cmds) != 2 {
		t.Fatalf("claimed %d (%v), want 2", len(cmds), err)
	}
	if got := testutil.ToFloat64(metrics.CommandClaimsTotal.WithLabelValues("claim_n")) - claimed; got != 2 {
		t.Errorf("command_claims_total{mode=claim_n} +%v, want +2", got)
	}
	if got := testutil.ToFloat64(metrics.CommandClaimSkippedTotal.WithLabelValues("scope_changed")) - scope; got != 1 {
		t.Errorf("command_claim_skipped_total{reason=scope_changed} +%v, want +1", got)
	}
	if got := histCount(t, metrics.CommandClaimDuration, "claim_n") - polls; got != 1 {
		t.Errorf("claim_n latency observations +%d, want +1", got)
	}
	if got := histCount(t, metrics.CommandClaimWait, "high") - waits; got != 2 {
		t.Errorf("wait observations of class high +%d, want +2", got)
	}
}

// A claim by id counts under mode "claim" and observes its latency.
func TestClaimMetrics_ClaimByID(t *testing.T) {
	f := newRecheckFixture()
	c := f.repo.add(f.tenant, commanddom.CommandTypeScan, `{"scanner":"nuclei","targets":["x.example.com"]}`, nil)
	claimed := testutil.ToFloat64(metrics.CommandClaimsTotal.WithLabelValues("claim"))
	calls := histCount(t, metrics.CommandClaimDuration, "claim")
	if _, err := f.svc.Acknowledge(context.Background(), f.tenant.String(), f.sensor.String(), c.ID.String()); err != nil {
		t.Fatal(err)
	}
	if got := testutil.ToFloat64(metrics.CommandClaimsTotal.WithLabelValues("claim")) - claimed; got != 1 {
		t.Errorf("command_claims_total{mode=claim} +%v, want +1", got)
	}
	if got := histCount(t, metrics.CommandClaimDuration, "claim") - calls; got != 1 {
		t.Errorf("claim latency observations +%d, want +1", got)
	}
}
