package compliance

import (
	"context"
	"testing"

	"github.com/openctemio/api/pkg/domain/shared"
)

// The composition root called SetSafeCheckDispatcher(s.ValidationRun) fourteen
// lines before s.ValidationRun was assigned, so it handed this setter a nil
// *validation.RunService.
//
// A nil pointer stored in a non-nil interface is the trap: `s.safeCheck == nil`
// is FALSE, so tryDispatchLive walks straight past its guard and calls through
// the nil receiver. The failure is not a silent no-op — it is a panic, which
// the HTTP middleware converts into a 500. RFC-012 live simulation dispatch has
// been dead this way since it merged, and it fails by data shape: a simulation
// with no target assets returns early and looks fine, one with a target asset
// crashes.
//
// The setter now refuses a nil, so a mis-ordered wiring degrades to the
// synthetic path — which is the documented fallback — instead of crashing.

// nilDispatcher is a pointer type implementing SafeCheckDispatcher, so a nil
// value of it is exactly the shape the composition root passed.
type nilDispatcher struct{}

func (*nilDispatcher) DispatchSimulationCheck(_ context.Context, _, _, _ shared.ID, _ string) (shared.ID, error) {
	panic("dispatch called on a nil dispatcher — the guard did not hold")
}

func TestSetSafeCheckDispatcher_RejectsTypedNil(t *testing.T) {
	s := &SimulationService{}

	var typedNil *nilDispatcher // nil pointer...
	s.SetSafeCheckDispatcher(typedNil)

	// ...which, stored naively, would make this comparison false.
	if s.safeCheck != nil {
		t.Fatal("a nil *nilDispatcher was stored; tryDispatchLive's `s.safeCheck == nil` " +
			"guard will not fire and the next call panics on the nil receiver")
	}
}

func TestSetSafeCheckDispatcher_AcceptsRealDispatcher(t *testing.T) {
	s := &SimulationService{}

	s.SetSafeCheckDispatcher(&nilDispatcher{})

	if s.safeCheck == nil {
		t.Fatal("a real dispatcher was rejected — the nil guard is too broad and " +
			"live safe-check dispatch would never run")
	}
}

func TestSetSafeCheckDispatcher_RejectsUntypedNil(t *testing.T) {
	s := &SimulationService{}

	s.SetSafeCheckDispatcher(nil)

	if s.safeCheck != nil {
		t.Fatal("untyped nil was stored")
	}
}
