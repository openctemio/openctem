package telemetry

import (
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

// unit tests for the CTEM stage metrics. These verify that
// every canonical stage has metrics defined and the label set is
// locked — the SLOs in alert on these exact series.
//
// We use testutil.ToFloat64 rather than parsing exposition text —
// simpler and less brittle when Prom updates its format.

func TestAllStages_Canonical(t *testing.T) {
	// The canonical ordered list must match the public constants.
	// Adding a stage requires an explicit team decision because it
	// ripples into dashboards, SLOs, and this test.
	want := []Stage{
		StageScoping,
		StageDiscovery,
		StagePrioritization,
		StageValidation,
		StageMobilization,
	}
	if len(AllStages) != len(want) {
		t.Fatalf("AllStages length = %d, want %d", len(AllStages), len(want))
	}
	for i, s := range want {
		if AllStages[i] != s {
			t.Errorf("AllStages[%d] = %q, want %q", i, AllStages[i], s)
		}
	}
}

func TestObserveStageIn_IncrementsCounter(t *testing.T) {
	tid := "t-" + t.Name()
	ObserveStageIn(StagePrioritization, tid, "P0")
	ObserveStageIn(StagePrioritization, tid, "P0")
	got := testutil.ToFloat64(stageFindingsIn.WithLabelValues(
		string(StagePrioritization), tid, "P0",
	))
	if got != 2 {
		t.Fatalf("counter = %v, want 2", got)
	}
}

func TestObserveStageIn_EmptyPriorityBecomesUnclassified(t *testing.T) {
	// A finding that hasn't been classified yet should still be
	// counted — but under a predictable "unclassified" label so the
	// Grafana panel doesn't render an empty string.
	tid := "t-" + t.Name()
	ObserveStageIn(StageDiscovery, tid, "")
	got := testutil.ToFloat64(stageFindingsIn.WithLabelValues(
		string(StageDiscovery), tid, "unclassified",
	))
	if got != 1 {
		t.Fatalf("unclassified counter = %v, want 1", got)
	}
}

func TestObserveStageOut_IncrementsByOutcome(t *testing.T) {
	tid := "t-" + t.Name()
	ObserveStageOut(StageValidation, tid, OutcomeAdvanced)
	ObserveStageOut(StageValidation, tid, OutcomeFailed)
	ObserveStageOut(StageValidation, tid, OutcomeAdvanced)

	adv := testutil.ToFloat64(stageFindingsOut.WithLabelValues(
		string(StageValidation), tid, string(OutcomeAdvanced),
	))
	if adv != 2 {
		t.Errorf("advanced counter = %v, want 2", adv)
	}
	fail := testutil.ToFloat64(stageFindingsOut.WithLabelValues(
		string(StageValidation), tid, string(OutcomeFailed),
	))
	if fail != 1 {
		t.Errorf("failed counter = %v, want 1", fail)
	}
}

func TestObserveStageLatency_IgnoresZeroOrNegative(t *testing.T) {
	tid := "t-" + t.Name()
	// The histogram count must not advance for zero / negative values.
	before := testutil.CollectAndCount(stageLatency, "ctem_stage_latency_seconds")
	ObserveStageLatency(StageScoping, tid, 0)
	ObserveStageLatency(StageScoping, tid, -5*time.Second)
	after := testutil.CollectAndCount(stageLatency, "ctem_stage_latency_seconds")
	if after != before {
		t.Fatalf("zero/negative samples increased collect count: %d -> %d", before, after)
	}
}

func TestObserveStageLatency_RecordsPositive(t *testing.T) {
	tid := "t-" + t.Name()
	ObserveStageLatency(StagePrioritization, tid, 500*time.Millisecond)
	ObserveStageLatency(StagePrioritization, tid, 10*time.Second)
	// CollectAndCount returns the number of distinct label-sets the
	// histogram has observed. Two samples under the same label set
	// should result in exactly one series.
	n := testutil.CollectAndCount(stageLatency, "ctem_stage_latency_seconds")
	if n < 1 {
		t.Fatalf("expected ≥1 series, got %d", n)
	}
}

// Naming is part of the public contract — dashboards and alerts
// query by these exact strings. If someone renames a metric, the
// CollectAndCount call filtering by name returns 0 and this test
// fails, forcing a conscious rename.
func TestMetricNames_Stable(t *testing.T) {
	// Seed one observation per metric so they have at least one
	// series to collect. The sub-tests then assert the metric can
	// be found by its canonical name.
	tid := "t-" + t.Name()
	ObserveStageIn(StageScoping, tid, "P0")
	ObserveStageOut(StageScoping, tid, OutcomeAdvanced)
	ObserveStageLatency(StageScoping, tid, time.Second)

	cases := []struct {
		name string
		col  interface{ Collect(ch chan<- prometheusMetric) }
	}{}
	// CollectAndCount accepts any prometheus.Collector; we invoke it
	// through the concrete vars so the import-identity check works.
	if n := testutil.CollectAndCount(stageFindingsIn, "ctem_stage_findings_in_total"); n == 0 {
		t.Errorf("ctem_stage_findings_in_total not registered")
	}
	if n := testutil.CollectAndCount(stageFindingsOut, "ctem_stage_findings_out_total"); n == 0 {
		t.Errorf("ctem_stage_findings_out_total not registered")
	}
	if n := testutil.CollectAndCount(stageLatency, "ctem_stage_latency_seconds"); n == 0 {
		t.Errorf("ctem_stage_latency_seconds not registered")
	}
	_ = cases // keep the slice declaration to avoid lint churn
}

// prometheusMetric is an alias for prometheus.Metric used only to
// keep the (unused) collector struct type-checkable without pulling
// the full prometheus import into the test.
type prometheusMetric interface{}
