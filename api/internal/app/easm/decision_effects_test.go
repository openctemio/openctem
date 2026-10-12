package easm

import (
	"context"
	"errors"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/attribution"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

type fakeResolver struct {
	calls [][]shared.ID
	err   error
}

func (f *fakeResolver) ResolveRejectedNames(_ context.Context, _ shared.ID, ids []shared.ID) (int, error) {
	f.calls = append(f.calls, ids)
	return len(ids), f.err
}

// research/22 P0-9: every decision reclassifies the decided assets; only a
// rejection resolves exposures; failures never stop the other follow-up.
func TestDecisionEffects(t *testing.T) {
	res := &fakeResolver{}
	var reclassified []shared.ID
	e := NewDecisionEffects(res, func(_ context.Context, _ shared.ID, ids []shared.ID) { reclassified = append(reclassified, ids...) }, nil)
	tenant := shared.NewID()
	a, b := shared.NewID(), shared.NewID()

	e.AfterDecision(context.Background(), tenant, []string{a.String(), "not-an-id"}, attribution.StateConfirmed)
	if len(res.calls) != 0 || len(reclassified) != 1 || reclassified[0] != a {
		t.Fatalf("confirm: resolver %v reclassified %v", res.calls, reclassified)
	}
	res.err = errors.New("db down")
	e.AfterDecision(context.Background(), tenant, []string{b.String()}, attribution.StateRejected)
	if len(res.calls) != 1 || res.calls[0][0] != b || len(reclassified) != 2 {
		t.Fatalf("reject: resolver %v reclassified %v", res.calls, reclassified)
	}
	var nilEffects *DecisionEffects
	nilEffects.AfterDecision(context.Background(), tenant, []string{a.String()}, attribution.StateRejected)
	NewDecisionEffects(nil, nil, nil).AfterDecision(context.Background(), tenant, []string{a.String()}, attribution.StateRejected)
}
