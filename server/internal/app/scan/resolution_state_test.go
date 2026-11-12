package scan

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/assetresolution"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// resolutionStates answers fixed not-resolving names per tenant.
type resolutionStates struct{ by map[shared.ID]map[string]bool }

func (r *resolutionStates) NotResolving(_ context.Context, t shared.ID, names []string) (map[string]bool, error) {
	out := map[string]bool{}
	for _, n := range names {
		if r.by[t][n] {
			out[n] = true
		}
	}
	return out, nil
}

func (r *resolutionStates) RecordResolved(context.Context, shared.ID, []shared.ID, time.Time) error {
	return nil
}

func (r *resolutionStates) RecordFailed(context.Context, shared.ID, []shared.ID, time.Time, string) error {
	return nil
}

func (r *resolutionStates) RecordFailedNames(context.Context, shared.ID, []string, time.Time, string) error {
	return nil
}

func (r *resolutionStates) Get(context.Context, shared.ID, shared.ID) (*assetresolution.Resolution, error) {
	return nil, nil
}

// An active stage leaves out a name the platform knows does not resolve,
// even one it holds no evidence about at all (a historic name from
// certificate transparency); the name is handed on again once its state
// clears, and another tenant's state never leaves a name out.
func TestDropStaleNames_NotResolvingState(t *testing.T) {
	tenant, other := shared.NewID(), shared.NewID()
	states := &resolutionStates{by: map[shared.ID]map[string]bool{tenant: {"dertrial.example.com": true}}}
	s := &Service{}
	s.SetResolutionStore(states)

	targets := []string{"dertrial.example.com", "www.example.com", "198.51.100.7"}
	kept, stale, err := s.DropStaleNames(context.Background(), tenant, targets)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(stale, []string{"dertrial.example.com"}) || !slices.Equal(kept, []string{"www.example.com", "198.51.100.7"}) {
		t.Fatalf("kept %v stale %v", kept, stale)
	}

	// Another tenant's state does not apply.
	if kept, stale, _ := s.DropStaleNames(context.Background(), other, targets); len(stale) != 0 || len(kept) != 3 {
		t.Fatalf("tenant %v: kept %v stale %v", other, kept, stale)
	}

	// It resolves again: the state clears and the name comes back.
	delete(states.by[tenant], "dertrial.example.com")
	if kept, stale, _ := s.DropStaleNames(context.Background(), tenant, targets); len(stale) != 0 || len(kept) != 3 {
		t.Fatalf("after it resolves: kept %v stale %v", kept, stale)
	}
}
