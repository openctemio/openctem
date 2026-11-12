package cirun

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	auditdom "github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/cirun"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// SweepRepository is what the not-judged sweeper needs.
type SweepRepository interface {
	RetentionTenantsForPlatform(ctx context.Context) ([]shared.ID, error)
	// UnjudgedRuns lists up to limit of the tenant's runs still running
	// that started before the time.
	UnjudgedRuns(ctx context.Context, tenantID shared.ID, before time.Time, limit int) ([]cirun.UnjudgedRun, error)
	SaveVerdict(ctx context.Context, tenantID, runID shared.ID, verdict string, detail []byte, at time.Time, expectFindings int, failedCapabilities []string) error
	RefreshPipeline(ctx context.Context, tenantID, pipelineID shared.ID) error
}

// SweepBatch bounds the runs one tenant gets concluded per pass.
const SweepBatch = 200

// SweepJob concludes the runs that never got a verdict. A run whose gate job
// never ran (pipeline canceled, gate removed, a rule that skipped it) stays
// running for ever, and without a verdict nothing blocks the merge and the
// run view says "Running". After the pipeline window (MaxRunContinuation, the
// longest a run can still get a token) the sweeper stores the verdict `fail`
// with the reason `not_judged`: silence is never a pass. The findings the run
// uploaded are kept.
type SweepJob struct {
	repo  SweepRepository
	audit Auditor
	log   *logger.Logger
	now   func() time.Time
}

// NewSweepJob creates the job. audit may be nil.
func NewSweepJob(repo SweepRepository, audit Auditor, log *logger.Logger) *SweepJob {
	if log == nil {
		log = logger.NewNop()
	}
	return &SweepJob{repo: repo, audit: audit, log: log.With("job", "ci-sweep"), now: time.Now}
}

// SetClock replaces the clock (tests).
func (j *SweepJob) SetClock(now func() time.Time) { j.now = now }

// SweepResult counts one pass.
type SweepResult struct {
	Tenants        int
	Concluded      int
	TenantFailures int
}

// Run sweeps every tenant. A tenant that fails is logged and skipped.
func (j *SweepJob) Run(ctx context.Context) (SweepResult, error) {
	var res SweepResult
	tenants, err := j.repo.RetentionTenantsForPlatform(ctx)
	if err != nil {
		return res, fmt.Errorf("list tenants with CI runs: %w", err)
	}
	for _, t := range tenants {
		if ctx.Err() != nil {
			return res, ctx.Err()
		}
		n, err := j.SweepTenant(ctx, t)
		res.Tenants++
		res.Concluded += n
		if err != nil {
			res.TenantFailures++
			j.log.Warn("ci sweep: tenant not swept", "tenant_id", t.String(), "error", logger.SanitizeError(err))
		}
	}
	return res, nil
}

// SweepTenant concludes one tenant's unjudged runs and returns how many.
func (j *SweepJob) SweepTenant(ctx context.Context, tenantID shared.ID) (int, error) {
	now := j.now().UTC()
	runs, err := j.repo.UnjudgedRuns(ctx, tenantID, now.Add(-MaxRunContinuation), SweepBatch)
	if err != nil {
		return 0, fmt.Errorf("list unjudged runs: %w", err)
	}
	done := 0
	for _, r := range runs {
		detail, err := notJudgedDetail(r)
		if err != nil {
			return done, err
		}
		err = j.repo.SaveVerdict(ctx, tenantID, r.ID, cirun.VerdictFail, detail, now, r.FindingsCount, nil)
		switch {
		case err == nil:
		case errors.Is(err, cirun.ErrRunEvaluated), errors.Is(err, cirun.ErrRunChanged), errors.Is(err, cirun.ErrRunNotFound):
			// Judged or changed meanwhile: the next pass looks again.
			continue
		default:
			return done, fmt.Errorf("save not-judged verdict: %w", err)
		}
		done++
		if r.PipelineID != nil {
			if err := j.repo.RefreshPipeline(ctx, tenantID, *r.PipelineID); err != nil {
				j.log.Warn("ci pipeline summary not refreshed", "pipeline_id", r.PipelineID.String(), "error", logger.SanitizeError(err))
			}
		}
		j.auditConcluded(ctx, tenantID, r)
	}
	return done, nil
}

func notJudgedDetail(r cirun.UnjudgedRun) ([]byte, error) {
	reasons := []cirun.GateReason{{Code: cirun.ReasonNotJudged,
		Message: "The pipeline run ended without asking the platform for a verdict (the gate job did not run), so it was not judged."}}
	if r.OverCap {
		// SaveVerdict only stores a verdict of an over-cap run when it names the cap.
		reasons = append(reasons, cirun.GateReason{Code: cirun.ReasonTooManyFindings,
			Message: "The run reported more findings than the gate records."})
	}
	b, err := json.Marshal(struct {
		RunID string `json:"run_id"`
		cirun.GateVerdict
	}{RunID: r.ID.String(), GateVerdict: cirun.GateVerdict{Verdict: cirun.VerdictFail, Reasons: reasons}})
	if err != nil {
		return nil, fmt.Errorf("marshal verdict: %w", err)
	}
	return b, nil
}

func (j *SweepJob) auditConcluded(ctx context.Context, tenantID shared.ID, r cirun.UnjudgedRun) {
	if j.audit == nil {
		return
	}
	ev := auditapp.NewSuccessEvent(auditdom.ActionCIRunEvaluated, auditdom.ResourceTypeCIRun, r.ID.String()).
		WithResourceName(r.Repository).
		WithMessage(fmt.Sprintf("CI run for %s was never judged: concluded as fail (not_judged)", r.Repository)).
		WithSeverity(auditdom.SeverityMedium).
		WithMetadata("verdict", cirun.VerdictFail).
		WithMetadata("reason", cirun.ReasonNotJudged).
		WithMetadata("pipeline_run_id", r.ExternalRunID)
	if err := j.audit.LogEvent(ctx, auditapp.AuditContext{TenantID: tenantID.String(), ActorEmail: "system:ci-sweep"}, ev); err != nil {
		j.log.Warn("ci audit record not written", "error", logger.SanitizeError(err))
	}
}
