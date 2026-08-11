package finding

import (
	"context"
	"errors"
	"testing"

	"github.com/openctemio/api/pkg/domain/asset"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/vulnerability"
	"github.com/openctemio/api/pkg/logger"
)

// stubAIVerdictLookup returns a fixed verdict map (or an error) for testing.
type stubAIVerdictLookup struct {
	verdicts map[shared.ID]AIFalsePositiveVerdict
	err      error
	calls    int
}

func (s *stubAIVerdictLookup) GetFalsePositiveVerdicts(_ context.Context, _ shared.ID, findingIDs []shared.ID) (map[shared.ID]AIFalsePositiveVerdict, error) {
	s.calls++
	if s.err != nil {
		return nil, s.err
	}
	out := make(map[shared.ID]AIFalsePositiveVerdict)
	for _, id := range findingIDs {
		if v, ok := s.verdicts[id]; ok {
			out[id] = v
		}
	}
	return out, nil
}

// A high-confidence verdict flows into the PriorityContext and de-escalates a
// finding that would otherwise be P1 (critical + reachable) down to P2.
func TestBuildPriorityContext_AIFalsePositiveDeescalates(t *testing.T) {
	f := newTestFinding(t)
	f.SetIsInKEV(false) // critical + reachable but not KEV → P1, not P0
	a := newTestAsset(t, asset.ExposurePublic)

	verdict := map[shared.ID]AIFalsePositiveVerdict{
		f.ID(): {Likely: true, Likelihood: 0.9},
	}

	svc := newReachabilitySvc()
	ctx := svc.buildPriorityContext(f, a, "", nil, nil, verdict)
	if !ctx.AIFalsePositiveLikely || ctx.AIFalsePositiveLikelihood != 0.9 {
		t.Fatalf("expected AI FP signal set on context, got likely=%v likelihood=%v",
			ctx.AIFalsePositiveLikely, ctx.AIFalsePositiveLikelihood)
	}
	if got := vulnerability.ClassifyPriority(ctx); got.Class != vulnerability.PriorityP2 {
		t.Fatalf("high-confidence AI FP should de-escalate P1→P2, got %s (%s)", got.Class, got.Reason)
	}

	// Without a verdict the same finding stays P1.
	noVerdict := svc.buildPriorityContext(f, a, "", nil, nil, nil)
	if noVerdict.AIFalsePositiveLikely {
		t.Fatal("no verdict must leave AIFalsePositiveLikely false")
	}
	if got := vulnerability.ClassifyPriority(noVerdict); got.Class != vulnerability.PriorityP1 {
		t.Fatalf("without AI verdict finding should stay P1, got %s", got.Class)
	}
}

// aiFalsePositiveVerdicts is fail-safe: a nil lookup or a lookup error yields a
// nil map (no AI signal), never a panic or a downgrade.
func TestAIFalsePositiveVerdicts_FailSafe(t *testing.T) {
	// nil lookup.
	svc := &PriorityClassificationService{logger: logger.NewNop()}
	if m := svc.aiFalsePositiveVerdicts(context.Background(), shared.NewID(), []shared.ID{shared.NewID()}); m != nil {
		t.Fatalf("nil lookup must yield nil map, got %v", m)
	}

	// lookup returns an error → nil map, no propagation.
	stub := &stubAIVerdictLookup{err: errors.New("db down")}
	svc.SetAITriageVerdictLookup(stub)
	if m := svc.aiFalsePositiveVerdicts(context.Background(), shared.NewID(), []shared.ID{shared.NewID()}); m != nil {
		t.Fatalf("errored lookup must yield nil map, got %v", m)
	}
	if stub.calls != 1 {
		t.Fatalf("expected lookup to be called once, got %d", stub.calls)
	}

	// empty finding set short-circuits (no call).
	stub2 := &stubAIVerdictLookup{}
	svc.SetAITriageVerdictLookup(stub2)
	if m := svc.aiFalsePositiveVerdicts(context.Background(), shared.NewID(), nil); m != nil {
		t.Fatalf("empty id set must yield nil map, got %v", m)
	}
	if stub2.calls != 0 {
		t.Fatalf("empty id set must not call the lookup, got %d calls", stub2.calls)
	}
}
