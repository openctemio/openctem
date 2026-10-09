package handler

import (
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// Controllers are read from the registry the controller manager writes:
// last run, errors and running, per controller, sorted by name.
func TestControllersFromRegistry(t *testing.T) {
	reg := prometheus.NewRegistry()
	last := prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: metricControllerLast}, []string{"controller"})
	errs := prometheus.NewCounterVec(prometheus.CounterOpts{Name: metricControllerErrors}, []string{"controller"})
	running := prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: metricControllerRunning}, []string{"controller"})
	other := prometheus.NewGauge(prometheus.GaugeOpts{Name: "unrelated_gauge"})
	reg.MustRegister(last, errs, running, other)

	at := time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)
	last.WithLabelValues("scan-timeout").Set(float64(at.Unix()))
	errs.WithLabelValues("scan-timeout").Add(3)
	running.WithLabelValues("audit-retention").Set(1)

	got := controllersFrom(reg)
	if len(got) != 2 || got[0].Name != "audit-retention" || got[1].Name != "scan-timeout" {
		t.Fatalf("controllers = %+v", got)
	}
	if !got[0].Running || got[0].LastReconcile != nil {
		t.Fatalf("audit-retention = %+v", got[0])
	}
	if got[1].Errors != 3 || got[1].LastReconcile == nil || !got[1].LastReconcile.Equal(at) {
		t.Fatalf("scan-timeout = %+v", got[1])
	}
}
