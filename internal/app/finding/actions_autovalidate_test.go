package finding

import (
	"context"
	"testing"

	"github.com/openctemio/api/internal/app/validation"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
)

// recordingAutoValidator records each ValidateFinding call and returns a
// per-call error keyed by call index (nil = success).
type recordingAutoValidator struct {
	calls []shared.ID
	errAt map[int]error
}

func (v *recordingAutoValidator) ValidateFinding(_ context.Context, _, findingID shared.ID) (shared.ID, error) {
	idx := len(v.calls)
	v.calls = append(v.calls, findingID)
	if v.errAt != nil {
		if err, ok := v.errAt[idx]; ok {
			return shared.ID{}, err
		}
	}
	return shared.NewID(), nil
}

func newFindingIDs(n int) []shared.ID {
	ids := make([]shared.ID, n)
	for i := range ids {
		ids[i] = shared.NewID()
	}
	return ids
}

func TestAutoQueueValidations_NilValidator(t *testing.T) {
	s := &FindingActionsService{logger: logger.NewNop()}
	if got := s.autoQueueValidations(context.Background(), shared.NewID(), newFindingIDs(3)); got != 0 {
		t.Fatalf("queued = %d, want 0 when no validator wired", got)
	}
}

func TestAutoQueueValidations_QueuesEachFinding(t *testing.T) {
	av := &recordingAutoValidator{}
	s := &FindingActionsService{logger: logger.NewNop(), autoValidator: av}

	ids := newFindingIDs(5)
	got := s.autoQueueValidations(context.Background(), shared.NewID(), ids)
	if got != 5 {
		t.Fatalf("queued = %d, want 5", got)
	}
	if len(av.calls) != 5 {
		t.Fatalf("validator called %d times, want 5", len(av.calls))
	}
}

func TestAutoQueueValidations_SkipsNonNetworkAndCountsRest(t *testing.T) {
	av := &recordingAutoValidator{errAt: map[int]error{
		0: validation.ErrNotNetworkAddressable, // code finding — expected skip
		2: validation.ErrNotNetworkAddressable,
	}}
	s := &FindingActionsService{logger: logger.NewNop(), autoValidator: av}

	got := s.autoQueueValidations(context.Background(), shared.NewID(), newFindingIDs(4))
	if got != 2 {
		t.Fatalf("queued = %d, want 2 (4 findings − 2 non-network)", got)
	}
	if len(av.calls) != 4 {
		t.Fatalf("validator should still be attempted for all 4, got %d", len(av.calls))
	}
}

func TestAutoQueueValidations_CapsAtMax(t *testing.T) {
	av := &recordingAutoValidator{}
	s := &FindingActionsService{logger: logger.NewNop(), autoValidator: av}

	got := s.autoQueueValidations(context.Background(), shared.NewID(), newFindingIDs(maxAutoValidations+50))
	if got != maxAutoValidations {
		t.Fatalf("queued = %d, want cap %d", got, maxAutoValidations)
	}
	if len(av.calls) != maxAutoValidations {
		t.Fatalf("validator called %d times, want cap %d (must stop, not flood)", len(av.calls), maxAutoValidations)
	}
}
