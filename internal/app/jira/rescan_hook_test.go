package jira

import (
	"github.com/openctemio/api/internal/app"
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/vulnerability"
	"github.com/openctemio/api/pkg/logger"
)

// B3 wire tests. The hook is the wire; these cover its orchestration
// (cooldown, scanner lookup, nil-safety). The underlying
// RequestVerificationScan is covered by its own unit tests.

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

// fakeRequester captures RequestVerificationScan calls directly —
// avoids instantiating the full FindingActionsService graph.
type fakeRequester struct {
	calls       int32
	err         error
	lastScanner string
}

func (f *fakeRequester) RequestVerificationScan(_ context.Context, _, _ string, input app.RequestVerificationScanInput) (*app.RequestVerificationScanResult, error) {
	atomic.AddInt32(&f.calls, 1)
	f.lastScanner = input.ScannerName
	if f.err != nil {
		return nil, f.err
	}
	return &app.RequestVerificationScanResult{FindingID: input.FindingID}, nil
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

// NOTE: domain forbids creating a Finding with empty ToolName
// (NewFinding returns ErrValidation). The "empty scanner → skip"
// branch in the hook guards against legacy DB rows only and is
// covered by integration tests, not unit.

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
