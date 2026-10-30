package ingest

import (
	"context"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/tenant"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// proposalRepo records what the evaluator proposes; the read and decision
// methods are not used by the evaluator.
type proposalRepo struct {
	*coverageFindingRepo
	vulnerability.ClosureProposalRepository
	recorded []vulnerability.ClosureProposalRecord
	canceled int
}

func (p *proposalRepo) RecordClosureProposals(_ context.Context, _ shared.ID, recs []vulnerability.ClosureProposalRecord) (int, error) {
	p.recorded = append(p.recorded, recs...)
	return len(recs), nil
}

func (p *proposalRepo) CancelStaleClosureProposals(context.Context, shared.ID) (int, error) {
	p.canceled++
	return 0, nil
}

// In enforce, what the closing mode sends to a person is stored as a
// proposal with the evidence of the look, and stale proposals are swept;
// a run the blinding guard holds proposes every candidate and closes none.
func TestEvaluateCommandCoverage_RecordsProposals(t *testing.T) {
	ctx := context.Background()
	t.Run("auto: the critical finding is proposed with its evidence", func(t *testing.T) {
		svc, repo, critical, medium := closureCase(t, fixedClosure{Mode: tenant.ClosingModeAuto})
		pr := &proposalRepo{coverageFindingRepo: repo}
		svc.findingRepo = pr
		cmd := shared.NewID()
		out := svc.EvaluateCommandCoverage(ctx, shared.NewID(), cmd)
		if len(pr.recorded) != 1 || pr.recorded[0].FindingID != critical || pr.recorded[0].Method != vulnerability.ClosureMethodCoveredScan {
			t.Fatalf("recorded = %+v", pr.recorded)
		}
		ev := pr.recorded[0].Evidence
		if ev["command_id"] != cmd.String() || ev["tool"] != "nuclei" || ev["held"] != false || pr.recorded[0].CommandID != cmd {
			t.Fatalf("evidence = %v", ev)
		}
		if len(out.Resolved) != 1 || out.Resolved[0] != medium || pr.canceled != 1 {
			t.Fatalf("outcome %+v, sweeps %d", out, pr.canceled)
		}
	})
	t.Run("held run: everything proposed, nothing closed", func(t *testing.T) {
		svc, repo, _, _ := closureCase(t, fixedClosure{Mode: tenant.ClosingModeAuto})
		repo.open = 2 // both of two open findings vanish at once
		svc.SetCoverageAutoResolve(CoverageAutoResolveEnforce, BlindingGuard{Ratio: 0.5, MinFindings: 1})
		pr := &proposalRepo{coverageFindingRepo: repo}
		svc.findingRepo = pr
		out := svc.EvaluateCommandCoverage(ctx, shared.NewID(), shared.NewID())
		if !out.Held || len(repo.resolved) != 0 || len(pr.recorded) != 2 || pr.recorded[0].Evidence["held"] != true {
			t.Fatalf("held: outcome %+v, recorded %+v", out, pr.recorded)
		}
	})
	t.Run("dry run records nothing", func(t *testing.T) {
		svc, repo, _, _ := closureCase(t, fixedClosure{Mode: tenant.ClosingModeReview})
		svc.SetCoverageAutoResolve(CoverageAutoResolveDryRun, BlindingGuard{})
		pr := &proposalRepo{coverageFindingRepo: repo}
		svc.findingRepo = pr
		_ = svc.EvaluateCommandCoverage(ctx, shared.NewID(), shared.NewID())
		if len(pr.recorded) != 0 || pr.canceled != 0 {
			t.Fatalf("dry run recorded %+v", pr.recorded)
		}
	})
}
