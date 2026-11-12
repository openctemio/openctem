package cirun

import (
	"context"
	"fmt"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/cirun"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// RetentionJob purges old CI run data tenant by tenant, in bounded batches:
// expired run token hashes, the sighted fingerprints of runs older than
// cirun.RunFindingsRetention, and runs older than cirun.RunRetention. Each
// pipeline's latest run and latest default-branch run are always kept.
type RetentionJob struct {
	repo cirun.RetentionRepository
	log  *logger.Logger
	now  func() time.Time
}

// NewRetentionJob creates the job.
func NewRetentionJob(repo cirun.RetentionRepository, log *logger.Logger) *RetentionJob {
	if log == nil {
		log = logger.NewNop()
	}
	return &RetentionJob{repo: repo, log: log.With("job", "ci-retention"), now: time.Now}
}

// SetClock replaces the clock (tests).
func (j *RetentionJob) SetClock(now func() time.Time) { j.now = now }

// RetentionResult counts one pass.
type RetentionResult struct {
	Tenants        int
	TokensCleared  int64
	FindingsPurged int64
	RunsPurged     int64
	TenantFailures int
}

// Run purges every tenant. A tenant that fails is logged and skipped.
func (j *RetentionJob) Run(ctx context.Context) (RetentionResult, error) {
	var res RetentionResult
	tenants, err := j.repo.RetentionTenantsForPlatform(ctx)
	if err != nil {
		return res, fmt.Errorf("list tenants with CI runs: %w", err)
	}
	for _, t := range tenants {
		if ctx.Err() != nil {
			return res, ctx.Err()
		}
		r, err := j.PurgeTenant(ctx, t)
		res.Tenants++
		res.TokensCleared += r.TokensCleared
		res.FindingsPurged += r.FindingsPurged
		res.RunsPurged += r.RunsPurged
		if err != nil {
			res.TenantFailures++
			j.log.Warn("ci retention: tenant not purged", "tenant_id", t.String(), "error", logger.SanitizeError(err))
		}
	}
	return res, nil
}

// PurgeTenant purges one tenant.
func (j *RetentionJob) PurgeTenant(ctx context.Context, tenantID shared.ID) (RetentionResult, error) {
	var res RetentionResult
	now := j.now().UTC()
	n, err := j.repo.ClearExpiredRunTokens(ctx, tenantID, now.Add(-cirun.RunTokenClearAfter))
	if err != nil {
		return res, fmt.Errorf("clear expired run tokens: %w", err)
	}
	res.TokensCleared = n
	for range cirun.RetentionMaxBatches {
		n, err := j.repo.PurgeRunFindings(ctx, tenantID, now.Add(-cirun.RunFindingsRetention), cirun.RetentionBatch)
		if err != nil {
			return res, fmt.Errorf("purge run findings: %w", err)
		}
		res.FindingsPurged += n
		if n == 0 {
			break
		}
	}
	for range cirun.RetentionMaxBatches {
		n, err := j.repo.PurgeRuns(ctx, tenantID, now.Add(-cirun.RunRetention), cirun.RetentionBatch)
		if err != nil {
			return res, fmt.Errorf("purge runs: %w", err)
		}
		res.RunsPurged += n
		if n < cirun.RetentionBatch {
			break
		}
	}
	return res, nil
}
