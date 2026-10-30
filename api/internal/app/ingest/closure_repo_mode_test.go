package ingest

import (
	"context"
	"testing"

	"github.com/openctemio/ctis"

	"github.com/openctemio/openctem/api/pkg/domain/ingestreport"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/tenant"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

func (r *coverageFindingRepo) RepoCoverageStaleFindings(_ context.Context, _ shared.ID, q ingestreport.CoverageQuery) ([]shared.ID, int, error) {
	r.query = q
	return r.stale, r.open, nil
}

func (r *coverageFindingRepo) ResolveRepoCoverageStale(_ context.Context, _ shared.ID, ids []shared.ID) ([]shared.ID, error) {
	r.resolved = append(r.resolved, ids...)
	return ids, nil
}

// proposalRecorder is a finding repository that also records the closure
// proposals written to it.
type proposalRecorder struct {
	*coverageFindingRepo
	vulnerability.ClosureProposalRepository
	recs []vulnerability.ClosureProposalRecord
}

func (p *proposalRecorder) RecordClosureProposals(_ context.Context, _ shared.ID, recs []vulnerability.ClosureProposalRecord) (int, error) {
	p.recs = append(p.recs, recs...)
	return len(recs), nil
}

func (p *proposalRecorder) CancelStaleClosureProposals(context.Context, shared.ID) (int, error) {
	return 0, nil
}

// repoCase is a clean full default-branch run with one stale critical and
// one stale medium finding, under the given organization policy.
func repoCase(t *testing.T, reader ClosureSettingsReader) (*Service, *proposalRecorder, shared.ID, shared.ID) {
	t.Helper()
	svc, repo := coverageService(t, CoverageAutoResolveEnforce, []string{"semgrep"})
	repo.cov.Reports[0].ToolName = "semgrep"
	repo.cov.Reports[0].Header = coverageHeader(t, "semgrep", ctis.ReportMetadata{CoverageType: "full", Branch: &ctis.BranchInfo{Name: "main", IsDefaultBranch: true}})
	critical, medium := shared.NewID(), shared.NewID()
	repo.stale, repo.open = []shared.ID{critical, medium}, 10
	repo.tiers = map[shared.ID]vulnerability.RiskTier{critical: vulnerability.RiskTierCritical}
	rec := &proposalRecorder{coverageFindingRepo: repo}
	svc.findingRepo = rec
	svc.SetClosureSettings(reader)
	return svc, rec, critical, medium
}

// The default-branch close goes through the organization's closing mode
// (method ci_default_branch), not around it.
func TestEvaluateRepoCoverage_ClosingMode(t *testing.T) {
	ctx := context.Background()
	run := func(svc *Service, rec *proposalRecorder) CoverageOutcome {
		out := svc.evaluateRepoCoverage(ctx, shared.NewID(), shared.NewID(), rec.cov, svc.coverageGuard)
		if out.Reason != coverageEligible {
			t.Fatalf("not eligible: %+v", out)
		}
		return out
	}
	t.Run("off: nothing closes, nothing is proposed", func(t *testing.T) {
		svc, rec, _, _ := repoCase(t, fixedClosure{Mode: tenant.ClosingModeOff})
		out := run(svc, rec)
		if len(rec.resolved) != 0 || len(out.Resolved) != 0 || len(out.Proposed) != 0 || len(rec.recs) != 0 {
			t.Fatalf("off: outcome %+v, recorded %v", out, rec.recs)
		}
	})
	t.Run("review (and unset, no reader, unreadable): all proposed", func(t *testing.T) {
		for name, reader := range map[string]ClosureSettingsReader{
			"review": fixedClosure{Mode: tenant.ClosingModeReview}, "unset": fixedClosure{}, "none": nil, "failing": failingClosure{},
		} {
			svc, rec, _, _ := repoCase(t, reader)
			out := run(svc, rec)
			if len(rec.resolved) != 0 || len(out.Proposed) != 2 || len(rec.recs) != 2 {
				t.Fatalf("%s: outcome %+v, recorded %d", name, out, len(rec.recs))
			}
			for _, r := range rec.recs {
				if r.Method != vulnerability.ClosureMethodCIDefaultBranch {
					t.Fatalf("%s: method %q, want ci_default_branch", name, r.Method)
				}
			}
		}
	})
	t.Run("auto: a default-branch close closes at every tier", func(t *testing.T) {
		svc, rec, _, _ := repoCase(t, fixedClosure{Mode: tenant.ClosingModeAuto})
		out := run(svc, rec)
		if len(rec.resolved) != 2 || len(out.Resolved) != 2 || len(rec.recs) != 0 {
			t.Fatalf("auto: outcome %+v, recorded %v", out, rec.recs)
		}
	})
	t.Run("held run proposes, closes nothing", func(t *testing.T) {
		svc, rec, _, _ := repoCase(t, fixedClosure{Mode: tenant.ClosingModeAuto})
		rec.stale = make([]shared.ID, 150)
		for i := range rec.stale {
			rec.stale[i] = shared.NewID()
		}
		rec.open = 160
		out := run(svc, rec)
		if !out.Held || len(rec.resolved) != 0 || len(rec.recs) != 150 {
			t.Fatalf("held: outcome held=%v resolved=%d recorded=%d", out.Held, len(rec.resolved), len(rec.recs))
		}
	})
	t.Run("held run under off proposes nothing", func(t *testing.T) {
		svc, rec, _, _ := repoCase(t, fixedClosure{Mode: tenant.ClosingModeOff})
		rec.stale = make([]shared.ID, 150)
		for i := range rec.stale {
			rec.stale[i] = shared.NewID()
		}
		rec.open = 160
		run(svc, rec)
		if len(rec.resolved) != 0 || len(rec.recs) != 0 {
			t.Fatalf("held+off: resolved %d recorded %d", len(rec.resolved), len(rec.recs))
		}
	})
}
