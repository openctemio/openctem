package coverage

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	covdom "github.com/openctemio/openctem/api/pkg/domain/coverage"
	"github.com/openctemio/openctem/api/pkg/logger"
)

type fakePlatformReader struct {
	counts []covdom.PlatformFailureCount
	err    error
	reads  int
}

func (f *fakePlatformReader) PlatformFailures(context.Context) ([]covdom.PlatformFailureCount, error) {
	f.reads++
	return f.counts, f.err
}

type fakeOperatorNotifier struct{ subjects, bodies []string }

func (f *fakeOperatorNotifier) NotifyAdmins(_ context.Context, subject, body string) error {
	f.subjects = append(f.subjects, subject)
	f.bodies = append(f.bodies, body)
	return nil
}

// Platform-side failures reach the administrators once when they appear,
// again only when clearly worse after a day, and re-arm after clearing; the
// fleet is read at most every DetectEvery. The message carries counts only.
func TestOperatorPass(t *testing.T) {
	now := time.Date(2026, 10, 30, 8, 0, 0, 0, time.UTC)
	s := NewService(nil, logger.NewNop())
	s.now = func() time.Time { return now }
	r := &fakePlatformReader{counts: []covdom.PlatformFailureCount{
		{Capability: "vuln.templates", Outcome: covdom.OutcomeNotDispatched, Pairs: 40, Tenants: 3},
		{Capability: "vuln.templates", Outcome: "tool_error", Pairs: 2, Tenants: 1},
	}}
	n := &fakeOperatorNotifier{}
	s.EnableOperatorAlerts(r, n)
	ctx := context.Background()

	s.operatorPass(ctx)
	if len(n.subjects) != 1 || !strings.Contains(n.subjects[0], "vuln.templates cannot run on 42 assets") {
		t.Fatalf("first pass sent %v", n.subjects)
	}
	if b := n.bodies[0]; !strings.Contains(b, "not_dispatched: 40") || !strings.Contains(b, "at least 3 organizations") ||
		!strings.Contains(b, "says nothing about the assets") {
		t.Fatalf("body %q", b)
	}

	// Within DetectEvery the fleet is not read again.
	now = now.Add(time.Minute)
	s.operatorPass(ctx)
	if r.reads != 1 {
		t.Fatalf("reads %d, want 1", r.reads)
	}

	// Worse, but within a day: silent.
	r.counts[0].Pairs = 200
	now = now.Add(DetectEvery)
	s.operatorPass(ctx)
	if len(n.subjects) != 1 {
		t.Fatalf("re-sent within a day: %v", n.subjects)
	}
	// A day later and clearly worse: sent again.
	now = now.Add(covdom.AlertRenotifyAfter)
	s.operatorPass(ctx)
	if len(n.subjects) != 2 {
		t.Fatalf("clearly worse after a day not sent: %v", n.subjects)
	}
	// Same count a day later: silent.
	now = now.Add(covdom.AlertRenotifyAfter)
	s.operatorPass(ctx)
	if len(n.subjects) != 2 {
		t.Fatalf("unchanged count re-sent: %v", n.subjects)
	}
	// Cleared, then back: sent again.
	saved := r.counts
	r.counts = nil
	now = now.Add(DetectEvery)
	s.operatorPass(ctx)
	r.counts = saved
	now = now.Add(DetectEvery)
	s.operatorPass(ctx)
	if len(n.subjects) != 3 {
		t.Fatalf("back after clearing not sent: %v", n.subjects)
	}

	// A read error sends nothing and does not panic.
	r.err = errors.New("db down")
	now = now.Add(DetectEvery)
	s.operatorPass(ctx)
	if len(n.subjects) != 3 {
		t.Fatalf("sent on a read error: %v", n.subjects)
	}
}

// Without the wiring the pass does nothing.
func TestOperatorPass_NotWired(t *testing.T) {
	s := NewService(nil, logger.NewNop())
	s.operatorPass(context.Background())
	s.EnableOperatorAlerts(nil, &fakeOperatorNotifier{})
	if s.operator != nil {
		t.Fatal("a nil reader wired the pass")
	}
}
