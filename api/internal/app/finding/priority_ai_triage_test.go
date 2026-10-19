package finding

import (
	"context"
	"errors"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/api/pkg/logger"
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

// A high-confidence verdict flows into the PriorityContext. It lowers a P2
// finding (critical, isolated asset) to P3, and never lowers a P1 finding
// (critical + reachable): the verdict reads attacker-influenced scanner
// output, so urgent work keeps its class with a review note.
func TestBuildPriorityContext_AIFalsePositiveDeescalates(t *testing.T) {
	f := newTestFinding(t)
	f.SetIsInKEV(false) // not KEV: no exploitation floor
	verdict := map[shared.ID]AIFalsePositiveVerdict{
		f.ID(): {Likely: true, Likelihood: 0.9},
	}
	svc := newReachabilitySvc()

	isolated := newTestAsset(t, asset.ExposureIsolated)
	ctx := svc.buildPriorityContext(f, isolated, "", nil, nil, verdict, nil)
	if !ctx.AIFalsePositiveLikely || ctx.AIFalsePositiveLikelihood != 0.9 {
		t.Fatalf("expected AI FP signal set on context, got likely=%v likelihood=%v",
			ctx.AIFalsePositiveLikely, ctx.AIFalsePositiveLikelihood)
	}
	if got := vulnerability.ClassifyPriority(ctx); got.Class != vulnerability.PriorityP3 {
		t.Fatalf("high-confidence AI FP should de-escalate P2→P3, got %s (%s)", got.Class, got.Reason)
	}

	public := newTestAsset(t, asset.ExposurePublic)
	if got := vulnerability.ClassifyPriority(svc.buildPriorityContext(f, public, "", nil, nil, verdict, nil)); got.Class != vulnerability.PriorityP1 {
		t.Fatalf("AI FP must not lower a P1 finding, got %s (%s)", got.Class, got.Reason)
	}

	// Without a verdict the isolated finding stays P2.
	noVerdict := svc.buildPriorityContext(f, isolated, "", nil, nil, nil, nil)
	if noVerdict.AIFalsePositiveLikely {
		t.Fatal("no verdict must leave AIFalsePositiveLikely false")
	}
	if got := vulnerability.ClassifyPriority(noVerdict); got.Class != vulnerability.PriorityP2 {
		t.Fatalf("without AI verdict finding should stay P2, got %s", got.Class)
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
