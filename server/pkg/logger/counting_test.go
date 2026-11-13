package logger

import (
	"io"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

// WARN and ERROR records are counted by component, before sampling; INFO is
// not counted.
func TestCountingHandlerCountsWarnAndErrorByComponent(t *testing.T) {
	log := New(Config{Level: "info", Format: "json", Output: io.Discard, Sampling: SamplingConfig{
		Enabled: true, Threshold: 1, Rate: 0, ErrorRate: 0, // drop nearly everything
	}})
	ctrl := log.With("controller", "count-test-ctrl")

	errBefore := testutil.ToFloat64(logRecordsTotal.WithLabelValues("error", "count-test-ctrl"))
	warnBefore := testutil.ToFloat64(logRecordsTotal.WithLabelValues("warn", "count-test-ctrl"))
	infoBefore := testutil.ToFloat64(logRecordsTotal.WithLabelValues("info", "count-test-ctrl"))

	for i := 0; i < 5; i++ {
		ctrl.Error("reconcile failed")
	}
	ctrl.Warn("slow")
	ctrl.Info("fine")

	if got := testutil.ToFloat64(logRecordsTotal.WithLabelValues("error", "count-test-ctrl")) - errBefore; got != 5 {
		t.Fatalf("errors counted = %v, want 5 (counted before sampling)", got)
	}
	if got := testutil.ToFloat64(logRecordsTotal.WithLabelValues("warn", "count-test-ctrl")) - warnBefore; got != 1 {
		t.Fatalf("warnings counted = %v, want 1", got)
	}
	if got := testutil.ToFloat64(logRecordsTotal.WithLabelValues("info", "count-test-ctrl")) - infoBefore; got != 0 {
		t.Fatalf("info counted = %v, want 0", got)
	}
}

// A component attribute that does not look like a code constant (a value
// from a request or a row) is never a label.
func TestComponentLabelIsBounded(t *testing.T) {
	for _, v := range []string{"alice@example.com", "Payroll Server", strings.Repeat("a", 60), "", "x/y"} {
		if got := componentLabel(v); got != componentOther {
			t.Errorf("componentLabel(%q) = %q, want %q", v, got, componentOther)
		}
	}
	if got := componentLabel("cert-monitor"); got != "cert-monitor" {
		t.Errorf("componentLabel(cert-monitor) = %q", got)
	}
	// The cap: past maxComponents distinct values, new ones are "other".
	componentsMu.Lock()
	saved := componentsSeen
	componentsSeen = map[string]bool{}
	for i := 0; i < maxComponents; i++ {
		componentsSeen[strings.Repeat("c", 1)+string(rune('a'+i%26))+strings.Repeat("z", i/26)] = true
	}
	componentsMu.Unlock()
	defer func() { componentsMu.Lock(); componentsSeen = saved; componentsMu.Unlock() }()
	if got := componentLabel("brand-new-component"); got != componentOther {
		t.Errorf("past the cap componentLabel = %q, want %q", got, componentOther)
	}
}
