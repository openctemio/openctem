package telemetry

import (
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

func histogramCount(t *testing.T, h prometheus.Histogram) (uint64, float64) {
	t.Helper()
	var m dto.Metric
	if err := h.Write(&m); err != nil {
		t.Fatal(err)
	}
	return m.GetHistogram().GetSampleCount(), m.GetHistogram().GetSampleSum()
}

// One observation per heartbeat that had a previous one; the ratio only
// when the followed interval is known. No labels: fixed cardinality.
func TestSensorHeartbeatMetrics(t *testing.T) {
	n0, _ := histogramCount(t, sensorHeartbeatGap)
	r0, s0 := histogramCount(t, sensorHeartbeatGapRatio)
	m := SensorHeartbeatMetrics{}
	m.ObserveHeartbeatGap(45*time.Second, 30*time.Second)
	m.ObserveHeartbeatGap(30*time.Second, 0)
	m.ObserveHeartbeatGap(0, 30*time.Second) // first heartbeat: nothing
	n1, _ := histogramCount(t, sensorHeartbeatGap)
	r1, s1 := histogramCount(t, sensorHeartbeatGapRatio)
	if n1-n0 != 2 || r1-r0 != 1 || s1-s0 != 1.5 {
		t.Fatalf("gap observations %d, ratio observations %d (sum +%.2f)", n1-n0, r1-r0, s1-s0)
	}
}
