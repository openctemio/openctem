package ingest

import (
	"context"
	"errors"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/tenant"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// fixedClosure is an organization closing policy for the tests.
type fixedClosure tenant.ClosureSettings

func (f fixedClosure) GetClosureSettings(context.Context, string) (*tenant.ClosureSettings, error) {
	cs := tenant.ClosureSettings(f)
	return &cs, nil
}

type failingClosure struct{}

func (failingClosure) GetClosureSettings(context.Context, string) (*tenant.ClosureSettings, error) {
	return nil, errors.New("db down")
}

// FindingRiskTiers serves the tiers a test set; an id without one is standard.
func (r *coverageFindingRepo) FindingRiskTiers(_ context.Context, _ shared.ID, ids []shared.ID) (map[shared.ID]vulnerability.RiskTier, error) {
	out := make(map[shared.ID]vulnerability.RiskTier, len(ids))
	for _, id := range ids {
		if t, ok := r.tiers[id]; ok {
			out[id] = t
		} else {
			out[id] = vulnerability.RiskTierStandard
		}
	}
	return out, nil
}

// closureCase is an enforce run with a stale critical and a stale medium
// finding.
func closureCase(t *testing.T, reader ClosureSettingsReader) (svc *Service, repo *coverageFindingRepo, critical, medium shared.ID) {
	t.Helper()
	svc, repo = coverageService(t, CoverageAutoResolveEnforce, []string{"nuclei"})
	critical, medium = shared.NewID(), shared.NewID()
	repo.stale = []shared.ID{critical, medium}
	repo.open = 10
	repo.tiers = map[shared.ID]vulnerability.RiskTier{critical: vulnerability.RiskTierCritical}
	svc.SetClosureSettings(reader)
	return svc, repo, critical, medium
}

func TestEvaluateCommandCoverage_ClosingMode(t *testing.T) {
	ctx := context.Background()
	t.Run("review: nothing resolved, all proposed", func(t *testing.T) {
		svc, repo, _, _ := closureCase(t, fixedClosure{Mode: tenant.ClosingModeReview})
		out := svc.EvaluateCommandCoverage(ctx, shared.NewID(), shared.NewID())
		if len(repo.resolved) != 0 || len(out.Resolved) != 0 || len(out.Proposed) != 2 {
			t.Fatalf("review: outcome %+v, repo resolved %v", out, repo.resolved)
		}
	})
	t.Run("unset mode (existing organization) is review", func(t *testing.T) {
		svc, repo, _, _ := closureCase(t, fixedClosure{})
		out := svc.EvaluateCommandCoverage(ctx, shared.NewID(), shared.NewID())
		if len(repo.resolved) != 0 || len(out.Proposed) != 2 {
			t.Fatalf("unset: outcome %+v", out)
		}
	})
	t.Run("no reader wired is review", func(t *testing.T) {
		svc, repo, _, _ := closureCase(t, nil)
		out := svc.EvaluateCommandCoverage(ctx, shared.NewID(), shared.NewID())
		if len(repo.resolved) != 0 || len(out.Proposed) != 2 {
			t.Fatalf("nil reader: outcome %+v", out)
		}
	})
	t.Run("unreadable policy is review", func(t *testing.T) {
		svc, repo, _, _ := closureCase(t, failingClosure{})
		out := svc.EvaluateCommandCoverage(ctx, shared.NewID(), shared.NewID())
		if len(repo.resolved) != 0 || len(out.Proposed) != 2 {
			t.Fatalf("failing reader: outcome %+v", out)
		}
	})
	t.Run("auto: the critical is proposed, the medium resolved", func(t *testing.T) {
		svc, repo, critical, medium := closureCase(t, fixedClosure{Mode: tenant.ClosingModeAuto})
		out := svc.EvaluateCommandCoverage(ctx, shared.NewID(), shared.NewID())
		if len(repo.resolved) != 1 || repo.resolved[0] != medium {
			t.Fatalf("auto: resolved %v, want only the medium", repo.resolved)
		}
		if len(out.Proposed) != 1 || out.Proposed[0] != critical {
			t.Fatalf("auto: proposed %v, want only the critical", out.Proposed)
		}
	})
	t.Run("auto with the owner's critical opt-in resolves both", func(t *testing.T) {
		svc, repo, _, _ := closureCase(t, fixedClosure{Mode: tenant.ClosingModeAuto, CriticalAutoClose: true})
		out := svc.EvaluateCommandCoverage(ctx, shared.NewID(), shared.NewID())
		if len(repo.resolved) != 2 || len(out.Proposed) != 0 {
			t.Fatalf("auto+critical: outcome %+v", out)
		}
	})
	t.Run("off: nothing resolved or proposed", func(t *testing.T) {
		svc, repo, _, _ := closureCase(t, fixedClosure{Mode: tenant.ClosingModeOff})
		out := svc.EvaluateCommandCoverage(ctx, shared.NewID(), shared.NewID())
		if len(repo.resolved) != 0 || len(out.Proposed) != 0 || len(out.Resolved) != 0 {
			t.Fatalf("off: outcome %+v", out)
		}
	})
	t.Run("dry_run ceiling: auto closes nothing", func(t *testing.T) {
		svc, repo, _, _ := closureCase(t, fixedClosure{Mode: tenant.ClosingModeAuto, CriticalAutoClose: true})
		svc.SetCoverageAutoResolve(CoverageAutoResolveDryRun, DefaultBlindingGuard())
		out := svc.EvaluateCommandCoverage(ctx, shared.NewID(), shared.NewID())
		if len(repo.resolved) != 0 || len(out.Proposed) != 0 || len(out.WouldResolve) != 2 {
			t.Fatalf("dry run: outcome %+v", out)
		}
	})
	t.Run("held run never closes, whatever the mode", func(t *testing.T) {
		svc, repo, _, _ := closureCase(t, fixedClosure{Mode: tenant.ClosingModeAuto, CriticalAutoClose: true})
		repo.stale = make([]shared.ID, 150)
		for i := range repo.stale {
			repo.stale[i] = shared.NewID()
		}
		repo.open = 160
		out := svc.EvaluateCommandCoverage(ctx, shared.NewID(), shared.NewID())
		if !out.Held || len(repo.resolved) != 0 {
			t.Fatalf("held: outcome %+v", out)
		}
	})
}

// A finding the tier query does not return (another tenant's id, or deleted)
// is kept, never closed.
func TestSplitByClosureDecision_UnknownIDKept(t *testing.T) {
	svc, repo := coverageService(t, CoverageAutoResolveEnforce, []string{"nuclei"})
	known, unknown := shared.NewID(), shared.NewID()
	svc.findingRepo = &partialTierRepo{coverageFindingRepo: repo, known: known}
	closeIDs, propose, keep := svc.splitByClosureDecision(context.Background(), shared.NewID(), []shared.ID{known, unknown}, vulnerability.ClosureMethodCoveredScan)
	if len(closeIDs) != 1 || closeIDs[0] != known || len(propose) != 0 || len(keep) != 1 || keep[0] != unknown {
		t.Fatalf("close %v propose %v keep %v", closeIDs, propose, keep)
	}
}

type partialTierRepo struct {
	*coverageFindingRepo
	known shared.ID
}

func (r *partialTierRepo) FindingRiskTiers(context.Context, shared.ID, []shared.ID) (map[shared.ID]vulnerability.RiskTier, error) {
	return map[shared.ID]vulnerability.RiskTier{r.known: vulnerability.RiskTierStandard}, nil
}

func TestParseCoverageAutoResolveMode_TenantAlias(t *testing.T) {
	if got := ParseCoverageAutoResolveMode(" Tenant "); got != CoverageAutoResolveEnforce {
		t.Fatalf("tenant = %q, want enforce", got)
	}
}

// In auto mode a mixed run records the proposals on the receipt (note
// review) and in their own dry-run audit entry, next to the resolved one.
func TestEvaluateCommandCoverage_ProposalsRecorded(t *testing.T) {
	svc, _, critical, medium := closureCase(t, fixedClosure{Mode: tenant.ClosingModeAuto})
	rec := &fakeReceipts{}
	svc.SetReceiptRecorder(rec)
	auditRepo := &recordingAuditRepo{}
	svc.auditRepo = auditRepo
	svc.EvaluateCommandCoverage(context.Background(), shared.NewID(), shared.NewID())

	if len(rec.deltas) != 1 || rec.deltas[0].CoverageNote != "review" || len(rec.deltas[0].Closed) != 1 || rec.deltas[0].Closed[0] != medium {
		t.Fatalf("receipt = %+v", rec.deltas)
	}
	byAction := map[audit.Action]map[string]any{}
	for _, l := range auditRepo.logs {
		byAction[l.Action()] = l.Metadata()
	}
	prop, ok := byAction[audit.ActionIngestCoverageAutoResolveDryRun]
	if !ok || prop["decision"] != "review" {
		t.Fatalf("no review audit entry: %v", byAction)
	}
	if ids, _ := prop["finding_ids"].([]string); len(ids) != 1 || ids[0] != critical.String() {
		t.Fatalf("review entry ids = %v", prop["finding_ids"])
	}
	if res, ok := byAction[audit.ActionIngestCoverageAutoResolved]; !ok || res["decision"] != "resolved" {
		t.Fatalf("no resolved audit entry: %v", byAction)
	}
}
