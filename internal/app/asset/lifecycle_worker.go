package asset

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/lib/pq"
	auditapp "github.com/openctemio/api/internal/app/audit"
	"github.com/openctemio/api/pkg/domain/audit"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/tenant"
	"github.com/openctemio/api/pkg/logger"
)

// AssetLifecycleWorker runs the stale-detection pass: assets that no
// scanner or integration has re-observed within the tenant's
// configured threshold are transitioned from active to stale. One
// worker instance is shared across tenants; the scheduler calls
// Run(ctx, tenantID, dryRun) once per tenant per cron tick. The
// worker is stateless between runs so failures and restarts are safe.
type AssetLifecycleWorker struct {
	db           *sql.DB
	tenantRepo   tenant.Repository
	auditService *auditapp.AuditService
	logger       *logger.Logger
}

// NewAssetLifecycleWorker constructs the worker. The tenant
// repository is needed to read per-tenant settings — the settings
// live inside tenants.settings JSONB which the repository already
// handles.
func NewAssetLifecycleWorker(db *sql.DB, tenantRepo tenant.Repository, log *logger.Logger) *AssetLifecycleWorker {
	return &AssetLifecycleWorker{
		db:         db,
		tenantRepo: tenantRepo,
		logger:     log.With("worker", "asset_lifecycle"),
	}
}

// SetAuditService wires the audit logger. When set, every non-empty
// batch run emits one asset.lifecycle_run audit entry so operators
// can trace exactly when and how many assets the automation demoted.
// Optional: leave nil in tests that don't want to assert audit side
// effects.
func (w *AssetLifecycleWorker) SetAuditService(svc *auditapp.AuditService) {
	w.auditService = svc
}

// LifecycleRunReport summarizes one worker pass. It is the audit
// payload (one row per run) and the dry-run response body. Keeping
// AffectedAssetIDs bounded prevents the payload from exploding when
// a tenant has millions of assets going stale at once (the
// pathological first-enable scenario).
type LifecycleRunReport struct {
	TenantID            string    `json:"tenant_id"`
	DryRun              bool      `json:"dry_run"`
	Enabled             bool      `json:"enabled"`
	Skipped             bool      `json:"skipped"`
	SkipReason          string    `json:"skip_reason,omitempty"`
	StartedAt           time.Time `json:"started_at"`
	CompletedAt         time.Time `json:"completed_at"`
	StaleThresholdDays  int       `json:"stale_threshold_days"`
	GracePeriodDays     int       `json:"grace_period_days"`
	ExcludedSourceTypes []string  `json:"excluded_source_types"`
	// Transitioned counts what would happen (dry-run) or did happen.
	TransitionedToStale int `json:"transitioned_to_stale"`
	// Capped list of asset IDs that transitioned. Bounded so the
	// audit row does not blow up under first-enable mass transitions.
	AffectedAssetIDs []string `json:"affected_asset_ids,omitempty"`
}

// maxAffectedIDsInReport caps the per-run list of asset IDs that
// surface in the report and audit event. Larger transitions are
// still observable via structured logs and the underlying DB state.
const maxAffectedIDsInReport = 100

// recentIngestWindow is the tenant-level liveness signal. If no
// asset has been re-observed within this window, the worker assumes
// the scanner fleet is silent and skips the whole tenant. Prevents
// the "scanner crashed, entire tenant gets demoted" failure mode.
// 48h gives room for weekly scans that run over a weekend.
const recentIngestWindow = 48 * time.Hour

// Run evaluates one tenant's lifecycle rules. dryRun=true returns
// the same report shape but writes nothing. Returns an error only on
// unrecoverable failure; a "skipped" run is not an error — the
// report carries the reason.
func (w *AssetLifecycleWorker) Run(ctx context.Context, tenantID shared.ID, dryRun bool) (*LifecycleRunReport, error) {
	startedAt := time.Now().UTC()
	report := &LifecycleRunReport{
		TenantID:  tenantID.String(),
		DryRun:    dryRun,
		StartedAt: startedAt,
	}

	t, err := w.tenantRepo.GetByID(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("load tenant %s: %w", tenantID, err)
	}
	settings := t.TypedSettings().AssetLifecycle
	report.Enabled = settings.Enabled
	report.StaleThresholdDays = settings.EffectiveStaleThresholdDays()
	report.GracePeriodDays = settings.EffectiveGracePeriodDays()
	report.ExcludedSourceTypes = settings.EffectiveExcludedSourceTypes()

	// When the feature is disabled AND this is not a dry-run,
	// we don't touch anything. Dry-run ignores the toggle — it
	// exists precisely to preview what would happen on enable.
	if !settings.Enabled && !dryRun {
		report.Skipped = true
		report.SkipReason = "feature_disabled"
		report.CompletedAt = time.Now().UTC()
		return report, nil
	}

	// Integration/agent health heuristic: if the tenant has had no
	// recent ingest activity at all, something upstream is broken
	// and we would create a storm of false positives by transitioning
	// everything to stale. Skip with a reason operators can search
	// for in logs. Dry-run proceeds so operators can still preview.
	if settings.PauseOnIntegrationFailure && !dryRun {
		recent, err := w.hasRecentIngest(ctx, tenantID)
		if err != nil {
			return nil, fmt.Errorf("liveness check: %w", err)
		}
		if !recent {
			report.Skipped = true
			report.SkipReason = "no_recent_ingest"
			report.CompletedAt = time.Now().UTC()
			w.logger.Warn("asset lifecycle skipped: no ingest in window",
				"tenant_id", tenantID.String(),
				"window", recentIngestWindow.String(),
			)
			return report, nil
		}
	}

	if dryRun {
		if err := w.countCandidates(ctx, tenantID, settings, report); err != nil {
			return nil, err
		}
	} else {
		if err := w.applyTransitions(ctx, tenantID, settings, report); err != nil {
			return nil, err
		}
	}

	report.CompletedAt = time.Now().UTC()

	// Audit every non-dry-run pass that actually transitioned
	// assets. Skipped runs already carry their reason in structured
	// logs; emitting audit rows for zero-transition runs would
	// create a daily row per tenant that carries no signal.
	if !dryRun && !report.Skipped && report.TransitionedToStale > 0 && w.auditService != nil {
		actx := auditapp.AuditContext{
			TenantID:   tenantID.String(),
			ActorID:    "system",
			ActorEmail: "asset-lifecycle-worker@system",
		}
		event := auditapp.NewSuccessEvent(
			audit.ActionAssetLifecycleRun,
			audit.ResourceTypeTenant,
			tenantID.String(),
		).
			WithMessage(fmt.Sprintf("Asset lifecycle worker demoted %d assets to stale", report.TransitionedToStale)).
			WithMetadata("transitioned_to_stale", report.TransitionedToStale).
			WithMetadata("stale_threshold_days", report.StaleThresholdDays).
			WithMetadata("grace_period_days", report.GracePeriodDays).
			WithMetadata("excluded_source_types", report.ExcludedSourceTypes).
			WithMetadata("sample_asset_ids", report.AffectedAssetIDs)
		if err := w.auditService.LogEvent(ctx, actx, event); err != nil {
			// Audit failure must not fail the worker run — structured
			// log + move on. Alerting picks this up if it becomes
			// frequent.
			w.logger.Warn("failed to emit lifecycle audit event",
				"tenant_id", tenantID.String(),
				"error", err,
			)
		}
	}

	return report, nil
}

// hasRecentIngest returns true if any asset in the tenant has been
// seen within recentIngestWindow. Cheap existence check, not a
// count — stops scanning at the first hit.
func (w *AssetLifecycleWorker) hasRecentIngest(ctx context.Context, tenantID shared.ID) (bool, error) {
	const q = `SELECT EXISTS (
		SELECT 1 FROM assets
		WHERE tenant_id = $1
		  AND last_seen_at > NOW() - make_interval(hours => $2)
	)`
	hours := int(recentIngestWindow.Hours())
	var exists bool
	if err := w.db.QueryRowContext(ctx, q, tenantID.String(), hours).Scan(&exists); err != nil {
		return false, err
	}
	return exists, nil
}

// countCandidates executes the SELECT shape used by dry-run. Same
// WHERE clause as applyTransitions — anything that would be updated
// is counted here, so the two paths stay in lockstep. Shared SQL
// fragment below.
func (w *AssetLifecycleWorker) countCandidates(
	ctx context.Context,
	tenantID shared.ID,
	settings tenant.AssetLifecycleSettings,
	report *LifecycleRunReport,
) error {
	query := `SELECT id FROM assets ` + lifecycleCandidateClauses + ` LIMIT $5`
	rows, err := w.db.QueryContext(ctx, query,
		tenantID.String(),
		settings.EffectiveStaleThresholdDays(),
		settings.EffectiveGracePeriodDays(),
		pq.Array(settings.EffectiveExcludedSourceTypes()),
		maxAffectedIDsInReport,
	)
	if err != nil {
		return fmt.Errorf("dry-run query: %w", err)
	}
	defer func() { _ = rows.Close() }()

	ids := make([]string, 0, maxAffectedIDsInReport)
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return fmt.Errorf("scan dry-run row: %w", err)
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return err
	}

	// For the count, we need the TOTAL not just the capped sample.
	// Run a cheaper COUNT(*) that reuses the same clauses.
	var total int
	countQuery := `SELECT COUNT(*) FROM assets ` + lifecycleCandidateClauses
	if err := w.db.QueryRowContext(ctx, countQuery,
		tenantID.String(),
		settings.EffectiveStaleThresholdDays(),
		settings.EffectiveGracePeriodDays(),
		pq.Array(settings.EffectiveExcludedSourceTypes()),
	).Scan(&total); err != nil {
		return fmt.Errorf("dry-run count: %w", err)
	}

	report.TransitionedToStale = total
	report.AffectedAssetIDs = ids
	return nil
}

// applyTransitions runs the atomic UPDATE. Because the WHERE clause
// mirrors countCandidates exactly, any row that would be counted in
// dry-run will also be transitioned in the real run — no drift
// between the preview and the commit.
//
// RETURNING id lets us capture the affected IDs in one round-trip
// without a follow-up SELECT that could race with another worker.
//
// A hard LIMIT per batch prevents a single pass from holding locks
// on millions of rows when a tenant with a huge fleet enables the
// feature for the first time. We loop until the batch returns fewer
// rows than the limit, capping the total at
// maxTransitionsPerRun so that a runaway configuration can't
// saturate the database with a single cron tick. Anything remaining
// after that will be picked up on the next daily run.
func (w *AssetLifecycleWorker) applyTransitions(
	ctx context.Context,
	tenantID shared.ID,
	settings tenant.AssetLifecycleSettings,
	report *LifecycleRunReport,
) error {
	// UPDATE with a self-referencing CTE so Postgres can use the
	// partial index to pick a bounded candidate set before locking.
	// Without the inner LIMIT the planner would filter the full set
	// up-front and the transaction would grow unbounded.
	const batchSize = lifecycleBatchSize
	query := `
		WITH candidates AS (
			SELECT id FROM assets ` + lifecycleCandidateClauses + `
			LIMIT $5
		)
		UPDATE assets SET status = 'stale', updated_at = NOW()
		WHERE id IN (SELECT id FROM candidates)
		RETURNING id
	`

	totalCount := 0
	ids := make([]string, 0, maxAffectedIDsInReport)

	for totalCount < maxTransitionsPerRun {
		rows, err := w.db.QueryContext(ctx, query,
			tenantID.String(),
			settings.EffectiveStaleThresholdDays(),
			settings.EffectiveGracePeriodDays(),
			pq.Array(settings.EffectiveExcludedSourceTypes()),
			batchSize,
		)
		if err != nil {
			return fmt.Errorf("lifecycle update: %w", err)
		}
		batchCount := 0
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				_ = rows.Close()
				return fmt.Errorf("scan updated row: %w", err)
			}
			batchCount++
			totalCount++
			if len(ids) < maxAffectedIDsInReport {
				ids = append(ids, id)
			}
		}
		if err := rows.Err(); err != nil {
			_ = rows.Close()
			return err
		}
		_ = rows.Close()

		// Short-circuit when the batch returned fewer rows than the
		// limit — no more candidates remain. Avoids a final empty
		// round trip.
		if batchCount < batchSize {
			break
		}
	}

	report.TransitionedToStale = totalCount
	report.AffectedAssetIDs = ids
	return nil
}

// lifecycleBatchSize bounds a single UPDATE pass. Chosen to keep
// transaction duration under a second on typical hardware while
// amortising the per-batch query setup cost over a useful amount of
// work. Operators that need bigger batches can rebuild from source;
// exposing this as a tunable is pre-mature until we see real numbers.
const lifecycleBatchSize = 5000

// maxTransitionsPerRun caps the total number of transitions per
// tenant per cron tick. Prevents the "first enable on 10M-asset
// tenant" scenario from blocking the worker pool on a single tenant
// for hours. 50K per day per tenant is still a generous budget — the
// remainder rolls into tomorrow's run.
const maxTransitionsPerRun = 50_000

// lifecycleCandidateClauses is the shared WHERE fragment used by
// both the dry-run and the actual UPDATE. Keeping one copy avoids
// the two paths drifting — a row either qualifies in both or
// neither.
//
// Parameter order:
//
//	$1 — tenant UUID
//	$2 — stale threshold (days)
//	$3 — grace period (days)
//	$4 — excluded source_type array (text[])
//
// Key design choices:
//   - status='active' — we never transition from stale/inactive/
//     archived. The worker is active→stale only; other transitions
//     are operator-driven.
//   - manual_status_override = false — respects operator control.
//   - lifecycle_paused_until — NULL or past → not paused. Honor
//     operator snooze (manual reactivation sets this to NOW+grace).
//   - GREATEST(last_seen_at, updated_at) — manually edited assets
//     count as "touched" even without scanner activity, so ops who
//     fix an asset manually do not wake up to it flagged stale.
//   - COALESCE(..., created_at) — legacy rows with NULL last_seen
//     fall back to created_at to avoid NULL-comparison pitfalls.
//   - Grace period on discovered_at (COALESCE with created_at again
//     for legacy rows with no discovery record).
//   - EXISTS asset_sources with non-excluded type — protects assets
//     that only have manual/import sources from quiet demotion.
//     Also protects assets with zero asset_sources rows (unknown
//     provenance is safest to leave alone).
const lifecycleCandidateClauses = `
	WHERE tenant_id = $1
	  AND status = 'active'
	  AND manual_status_override = FALSE
	  AND (lifecycle_paused_until IS NULL OR lifecycle_paused_until < NOW())
	  AND COALESCE(discovered_at, created_at) < NOW() - make_interval(days => $3)
	  AND GREATEST(COALESCE(last_seen_at, created_at), updated_at)
	      < NOW() - make_interval(days => $2)
	  AND EXISTS (
	      SELECT 1 FROM asset_sources s
	      WHERE s.asset_id = assets.id
	        AND NOT (s.source_type::text = ANY($4::text[]))
	  )
`
