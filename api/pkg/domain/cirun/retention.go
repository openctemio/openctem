package cirun

import (
	"context"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Retention of CI runs (RFC-051, "Data model"). A run's per-run evidence
// (the fingerprints it sighted) is kept 90 days and the run itself 400 days;
// each pipeline's latest run and latest default-branch run are always kept,
// whatever their age (the gate baseline and the pipeline summary read them).
// An upload token is useless after it expires, so its hash is cleared then.
const (
	RunFindingsRetention = 90 * 24 * time.Hour
	RunRetention         = 400 * 24 * time.Hour
	// RunTokenClearAfter is how long after expiry a run's token hash is kept
	// (none is needed; the margin covers clock skew between replicas).
	RunTokenClearAfter = time.Hour
	// RetentionBatch bounds the runs one statement handles: their findings,
	// or the runs themselves (whose findings cascade).
	RetentionBatch = 200
	// RetentionMaxBatches bounds the batches per tenant and kind in one pass;
	// the rest waits for the next pass.
	RetentionMaxBatches = 50
)

// RetentionRepository purges CI run data. Every method but
// RetentionTenantsForPlatform is tenant-scoped.
type RetentionRepository interface {
	// RetentionTenantsForPlatform lists the tenants that have CI runs or
	// pipelines (every later call is tenant-scoped).
	RetentionTenantsForPlatform(ctx context.Context) ([]shared.ID, error)
	// ClearExpiredRunTokens clears the token hash of runs whose token
	// expired before the time.
	ClearExpiredRunTokens(ctx context.Context, tenantID shared.ID, before time.Time) (int64, error)
	// PurgeRunFindings deletes the sighted fingerprints of up to limit runs
	// created before the time, keeping each pipeline's latest run and latest
	// default-branch run. It returns the fingerprints deleted (0: nothing
	// left to purge).
	PurgeRunFindings(ctx context.Context, tenantID shared.ID, before time.Time, limit int) (int64, error)
	// PurgeRuns deletes up to limit runs created before the time, with the
	// same exceptions.
	PurgeRuns(ctx context.Context, tenantID shared.ID, before time.Time, limit int) (int64, error)
}
