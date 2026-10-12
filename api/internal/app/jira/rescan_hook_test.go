package jira

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// B3 wire tests. The hook is the wire; these cover its orchestration
// (cooldown, status check, nil-safety). The proof-of-fix retest itself is
// covered in internal/app/retest.

type fakeFindingReader struct {
	f   *vulnerability.Finding
	err error
}

func (r *fakeFindingReader) GetByID(_ context.Context, _, _ shared.ID) (*vulnerability.Finding, error) {
	if r.err != nil {
		return nil, r.err
	}
	return r.f, nil
}

// fakeRequester captures proof-of-fix requests.
type fakeRequester struct {
	calls       int32
	err         error
	lastFinding shared.ID
}

func (f *fakeRequester) ValidateFinding(_ context.Context, _, findingID shared.ID) (shared.ID, error) {
	atomic.AddInt32(&f.calls, 1)
	f.lastFinding = findingID
	if f.err != nil {
		return shared.ID{}, f.err
	}
	return shared.NewID(), nil
}

func newHookWithFinding(t *testing.T, toolName string) (*RescanHook, *fakeRequester, *vulnerability.Finding) {
	t.Helper()
	f, err := vulnerability.NewFinding(
		shared.NewID(), shared.NewID(),
		vulnerability.FindingSourceSAST,
		toolName,
		vulnerability.SeverityHigh, "test",
	)
	if err != nil {
		t.Fatalf("%v", err)
	}
	for _, st := range []vulnerability.FindingStatus{
		vulnerability.FindingStatusConfirmed,
		vulnerability.FindingStatusInProgress,
		vulnerability.FindingStatusFixApplied,
	} {
		_ = f.TransitionStatus(st, "", nil)
	}

	requester := &fakeRequester{}
	reader := &fakeFindingReader{f: f}
	hook := NewRescanHook(requester, reader, logger.NewNop())
	return hook, requester, f
}

func TestJiraRescanHook_TriggersOnce(t *testing.T) {
	hook, trigger, f := newHookWithFinding(t, "semgrep")
	err := hook.Hook(context.Background(), f.TenantID(), f.ID())
	if err != nil {
		t.Fatalf("hook: %v", err)
	}
	if atomic.LoadInt32(&trigger.calls) != 1 {
		t.Fatalf("trigger calls = %d, want 1", trigger.calls)
	}
}

func TestJiraRescanHook_CooldownSuppressesSecondCall(t *testing.T) {
	hook, trigger, f := newHookWithFinding(t, "semgrep")
	ctx := context.Background()
	if err := hook.Hook(ctx, f.TenantID(), f.ID()); err != nil {
		t.Fatal(err)
	}
	// Second call within cooldown → no new trigger.
	if err := hook.Hook(ctx, f.TenantID(), f.ID()); err != nil {
		t.Fatal(err)
	}
	if atomic.LoadInt32(&trigger.calls) != 1 {
		t.Fatalf("cooldown failed: trigger calls = %d, want 1", trigger.calls)
	}
}

func TestJiraRescanHook_CooldownAllowsAfterWindow(t *testing.T) {
	hook, trigger, f := newHookWithFinding(t, "semgrep")
	hook.SetCooldown(1 * time.Millisecond)

	ctx := context.Background()
	_ = hook.Hook(ctx, f.TenantID(), f.ID())
	time.Sleep(10 * time.Millisecond)
	_ = hook.Hook(ctx, f.TenantID(), f.ID())

	if atomic.LoadInt32(&trigger.calls) != 2 {
		t.Fatalf("after cooldown should re-fire: got %d calls", trigger.calls)
	}
}

func TestJiraRescanHook_DifferentFindingsIndependentCooldown(t *testing.T) {
	// Two findings share a tenant; hitting one should not block the other.
	hook, trigger, f := newHookWithFinding(t, "semgrep")
	ctx := context.Background()
	if err := hook.Hook(ctx, f.TenantID(), f.ID()); err != nil {
		t.Fatal(err)
	}

	// Second finding, same tenant.
	f2, _ := vulnerability.NewFinding(
		f.TenantID(), shared.NewID(),
		vulnerability.FindingSourceSAST, "semgrep",
		vulnerability.SeverityHigh, "test2",
	)
	for _, st := range []vulnerability.FindingStatus{
		vulnerability.FindingStatusConfirmed,
		vulnerability.FindingStatusInProgress,
		vulnerability.FindingStatusFixApplied,
	} {
		_ = f2.TransitionStatus(st, "", nil)
	}
	hook.repo = &fakeFindingReader{f: f2}
	if err := hook.Hook(ctx, f2.TenantID(), f2.ID()); err != nil {
		t.Fatal(err)
	}
	if atomic.LoadInt32(&trigger.calls) != 2 {
		t.Fatalf("each finding should have own cooldown; calls=%d", trigger.calls)
	}
}

// A finding that something else already moved off fix_applied is not
// re-verified.
func TestJiraRescanHook_SkipsFindingNoLongerFixApplied(t *testing.T) {
	hook, trigger, f := newHookWithFinding(t, "nuclei")
	if err := f.TransitionStatus(vulnerability.FindingStatusResolved, "", nil); err != nil {
		t.Fatal(err)
	}
	if err := hook.Hook(context.Background(), f.TenantID(), f.ID()); err != nil {
		t.Fatal(err)
	}
	if atomic.LoadInt32(&trigger.calls) != 0 {
		t.Fatalf("a resolved finding was sent for proof of fix")
	}
}

func TestJiraRescanHook_FindingLookupError_Propagates(t *testing.T) {
	boom := errors.New("db down")
	hook := NewRescanHook(&fakeRequester{}, &fakeFindingReader{err: boom}, logger.NewNop())
	err := hook.Hook(context.Background(), shared.NewID(), shared.NewID())
	if !errors.Is(err, boom) {
		t.Fatalf("want boom, got %v", err)
	}
}

func TestJiraRescanHook_NilDeps_SafeNoOp(t *testing.T) {
	hook := NewRescanHook(nil, nil, nil)
	if err := hook.Hook(context.Background(), shared.NewID(), shared.NewID()); err != nil {
		t.Fatal(err)
	}
}
