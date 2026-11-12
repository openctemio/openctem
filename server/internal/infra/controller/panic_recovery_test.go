package controller

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/openctemio/openctem/api/internal/metrics"
)

// panickyController panics on its first run and counts every run.
type panickyController struct {
	runs atomic.Int32
}

func (c *panickyController) Name() string            { return "panic-probe" }
func (c *panickyController) Interval() time.Duration { return 20 * time.Millisecond }
func (c *panickyController) Reconcile(context.Context) (int, error) {
	if c.runs.Add(1) == 1 {
		panic("reconcile probe: boom")
	}
	return 1, nil
}

// errorCounter records IncrementReconcileErrors.
type errorCounter struct {
	NoopMetrics
	mu     sync.Mutex
	errors map[string]int
}

func (e *errorCounter) IncrementReconcileErrors(name string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.errors[name]++
}

func (e *errorCounter) count(name string) int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.errors[name]
}

// A panic in Reconcile is a failed run: the process and the manager keep
// going, the panic is counted, and the next tick runs the controller again.
func TestManager_PanickingControllerIsRecoveredAndRunsAgain(t *testing.T) {
	ec := &errorCounter{errors: map[string]int{}}
	m := newTestManager()
	m.metrics = ec
	c := &panickyController{}
	other := &probeController{interval: 20 * time.Millisecond}
	m.Register(c)
	m.Register(other)
	before := testutil.ToFloat64(metrics.PanicsRecoveredTotal.WithLabelValues("controller:panic-probe"))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := m.Start(ctx); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for c.runs.Load() < 3 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if err := m.Stop(); err != nil {
		t.Fatal(err)
	}

	if got := c.runs.Load(); got < 3 {
		t.Fatalf("controller ran %d times after its panic, want the next ticks to run it", got)
	}
	if got := ec.count("panic-probe"); got != 1 {
		t.Fatalf("reconcile errors = %d, want 1 (the panicking run)", got)
	}
	after := testutil.ToFloat64(metrics.PanicsRecoveredTotal.WithLabelValues("controller:panic-probe"))
	if after-before != 1 {
		t.Fatalf("panics recovered = %v, want 1", after-before)
	}
}

func TestReconcileRecovered_ReturnsThePanicAsAnError(t *testing.T) {
	m := newTestManager()
	n, err := m.reconcileRecovered(context.Background(), &panickyController{})
	if err == nil || n != 0 {
		t.Fatalf("reconcileRecovered = %d, %v; want 0 and an error", n, err)
	}
}
