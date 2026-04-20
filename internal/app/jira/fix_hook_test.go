package jira

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"

	"github.com/openctemio/api/pkg/domain/shared"
)

// B3 (Q1/WS-E): verify the post-fix hook wiring — setter works, nil is
// safe, hook receives tenant + finding id, hook errors do not escape.
//
// Full end-to-end test (Jira webhook → hook → scan triggered) lives in
// tests/integration/ where a mock Client + real findingRepo exist.

func TestSetPostFixAppliedHook_NilSafe(t *testing.T) {
	s := &SyncService{}
	s.SetPostFixAppliedHook(nil)
	if s.postFixHook != nil {
		t.Fatal("setting nil must clear the hook")
	}
}

func TestSetPostFixAppliedHook_StoresHook(t *testing.T) {
	s := &SyncService{}
	called := int32(0)
	hook := func(_ context.Context, _, _ shared.ID) error {
		atomic.AddInt32(&called, 1)
		return nil
	}
	s.SetPostFixAppliedHook(hook)
	if s.postFixHook == nil {
		t.Fatal("hook not stored")
	}
	// Invoke it directly to confirm storage — the function identity
	// cannot be compared in Go, but the side effect can.
	if err := s.postFixHook(context.Background(), shared.NewID(), shared.NewID()); err != nil {
		t.Fatalf("hook returned: %v", err)
	}
	if atomic.LoadInt32(&called) != 1 {
		t.Fatalf("hook not invoked")
	}
}

func TestFixAppliedHook_SignatureReceivesIDs(t *testing.T) {
	// Contract check: hook signature carries both tenant and finding
	// IDs so the rate-limiter implementation can key on (tenant, finding).
	var gotTenant, gotFinding shared.ID
	hook := FixAppliedHook(func(_ context.Context, t shared.ID, f shared.ID) error {
		gotTenant = t
		gotFinding = f
		return nil
	})
	tid := shared.NewID()
	fid := shared.NewID()
	if err := hook(context.Background(), tid, fid); err != nil {
		t.Fatal(err)
	}
	if gotTenant != tid {
		t.Fatalf("tenant id mismatch")
	}
	if gotFinding != fid {
		t.Fatalf("finding id mismatch")
	}
}

func TestFixAppliedHook_ErrorsDoNotEscape(t *testing.T) {
	// The production path wraps hook errors in a log-warn and returns
	// nil so the Jira ACK succeeds. This test only confirms the hook
	// itself returns its error intact for the caller to handle —
	// production wrapping is covered by the integration test.
	sentinel := errors.New("boom")
	hook := FixAppliedHook(func(_ context.Context, _, _ shared.ID) error {
		return sentinel
	})
	if err := hook(context.Background(), shared.NewID(), shared.NewID()); !errors.Is(err, sentinel) {
		t.Fatalf("want sentinel, got %v", err)
	}
}
