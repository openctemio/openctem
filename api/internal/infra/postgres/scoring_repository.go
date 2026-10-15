package postgres

// Scoring versions and the finding-priority queue
// (docs/architecture/scoring-versions.md). Queue rows are written by
// database triggers (migration scoring_versions) and by EnqueueAssets /
// EnqueueTenant, and claimed by the finding-priority worker.

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/pkg/domain/scoring"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// ScoringRepository implements scoring.VersionRepository and
// scoring.PriorityQueue.
type ScoringRepository struct {
	db *DB
}

// NewScoringRepository creates the repository.
func NewScoringRepository(db *DB) *ScoringRepository {
	return &ScoringRepository{db: db}
}

var (
	_ scoring.VersionRepository = (*ScoringRepository)(nil)
	_ scoring.PriorityQueue     = (*ScoringRepository)(nil)
)

// CurrentVersion returns the version this build stamps on a value of the
// tenant (scoring_version bounds it by this build's model version).
func (r *ScoringRepository) CurrentVersion(ctx context.Context, tenantID shared.ID, kind scoring.Kind) (int64, error) {
	var v int64
	err := r.db.QueryRowContext(ctx, `SELECT scoring_version($1, $2, $3)`,
		tenantID.String(), string(kind), scoring.ModelVersion(kind)).Scan(&v)
	if err != nil {
		return 0, fmt.Errorf("scoring version: %w", err)
	}
	return v, nil
}

// RegisterModels records this build's model versions. Concurrent replicas
// are safe: the unique index keeps one row per (kind, model version).
func (r *ScoringRepository) RegisterModels(ctx context.Context) error {
	const q = `
		INSERT INTO scoring_changes (tenant_id, kind, source, model_version, summary)
		VALUES (NULL, $1, 'platform_model', $2, $3)
		ON CONFLICT (kind, model_version) WHERE source = 'platform_model' DO NOTHING`
	for _, k := range scoring.Kinds() {
		if _, err := r.db.ExecContext(ctx, q, string(k), scoring.ModelVersion(k), scoring.ModelSummary(k)); err != nil {
			return fmt.Errorf("register scoring model %s: %w", k, err)
		}
	}
	return nil
}

// EnqueueAssets queues the given assets of the tenant. The join on assets
// keeps another tenant's asset id out of the queue.
func (r *ScoringRepository) EnqueueAssets(ctx context.Context, tenantID shared.ID, assetIDs []shared.ID, reason string) error {
	if len(assetIDs) == 0 {
		return nil
	}
	ids := make([]string, 0, len(assetIDs))
	for _, id := range assetIDs {
		ids = append(ids, id.String())
	}
	const q = `
		INSERT INTO finding_priority_queue (asset_id, tenant_id, reason)
		SELECT a.id, a.tenant_id, $3 FROM assets a
		WHERE a.tenant_id = $1 AND a.id = ANY($2::uuid[]) AND a.deleted_at IS NULL
		ORDER BY a.id
		ON CONFLICT (asset_id) DO UPDATE SET enqueued_at = EXCLUDED.enqueued_at
			WHERE finding_priority_queue.enqueued_at > EXCLUDED.enqueued_at`
	if _, err := r.db.ExecContext(ctx, q, tenantID.String(), pq.Array(ids), reason); err != nil {
		return fmt.Errorf("enqueue finding priority: %w", err)
	}
	return nil
}

// EnqueueTenant queues every asset of the tenant with an open finding.
func (r *ScoringRepository) EnqueueTenant(ctx context.Context, tenantID shared.ID, reason string) error {
	q := `
		INSERT INTO finding_priority_queue (asset_id, tenant_id, reason)
		SELECT DISTINCT f.asset_id, f.tenant_id, $2 FROM findings f
		JOIN assets a ON a.id = f.asset_id AND a.tenant_id = f.tenant_id AND a.deleted_at IS NULL
		WHERE f.tenant_id = $1 AND ` + vulnerability.OpenStatusSQL("f.status") + `
		ORDER BY f.asset_id
		ON CONFLICT (asset_id) DO UPDATE SET enqueued_at = EXCLUDED.enqueued_at
			WHERE finding_priority_queue.enqueued_at > EXCLUDED.enqueued_at`
	if _, err := r.db.ExecContext(ctx, q, tenantID.String(), reason); err != nil {
		return fmt.Errorf("enqueue tenant finding priority: %w", err)
	}
	return nil
}

// Claim removes up to limit due rows, oldest first but at most perTenant
// rows of one tenant, so a tenant with a large backlog (a settings change
// over a big inventory) cannot starve the others. SKIP LOCKED keeps two
// replicas from claiming the same asset. A claimed row is deleted: a pass
// that crashes is healed by the reconcile (the findings keep a stale
// version).
func (r *ScoringRepository) Claim(ctx context.Context, limit, perTenant int) ([]scoring.QueueItem, error) {
	if limit <= 0 {
		return nil, nil
	}
	if perTenant <= 0 || perTenant > limit {
		perTenant = limit
	}
	const q = `
		WITH t AS (
			SELECT DISTINCT tenant_id FROM finding_priority_queue WHERE enqueued_at <= now()
		), due AS (
			SELECT p.asset_id FROM t
			CROSS JOIN LATERAL (
				SELECT q.asset_id, q.enqueued_at FROM finding_priority_queue q
				WHERE q.tenant_id = t.tenant_id AND q.enqueued_at <= now()
				ORDER BY q.enqueued_at
				LIMIT $2
				FOR UPDATE SKIP LOCKED
			) p
			ORDER BY p.enqueued_at
			LIMIT $1
		)
		DELETE FROM finding_priority_queue q
		USING due
		WHERE q.asset_id = due.asset_id
		RETURNING q.tenant_id, q.asset_id, q.reason, q.scoring_change_id`
	rows, err := r.db.QueryContext(ctx, q, limit, perTenant)
	if err != nil {
		return nil, fmt.Errorf("claim finding priority queue: %w", err)
	}
	defer func() { _ = rows.Close() }()
	items := make([]scoring.QueueItem, 0, limit)
	for rows.Next() {
		var (
			tid, aid, reason string
			change           sql.NullInt64
		)
		if err := rows.Scan(&tid, &aid, &reason, &change); err != nil {
			return nil, fmt.Errorf("scan finding priority queue: %w", err)
		}
		tenantID, err := shared.IDFromString(tid)
		if err != nil {
			continue
		}
		assetID, err := shared.IDFromString(aid)
		if err != nil {
			continue
		}
		it := scoring.QueueItem{TenantID: tenantID, AssetID: assetID, Reason: reason}
		if change.Valid {
			v := change.Int64
			it.ScoringChangeID = &v
		}
		items = append(items, it)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate finding priority queue: %w", err)
	}
	return items, nil
}

// Stats returns the queue depth and the age of the oldest due row.
func (r *ScoringRepository) Stats(ctx context.Context) (scoring.QueueStats, error) {
	const q = `
		SELECT COUNT(*),
		       COALESCE(EXTRACT(EPOCH FROM now() - MIN(enqueued_at) FILTER (WHERE enqueued_at <= now())), 0)
		FROM finding_priority_queue`
	var (
		depth  int64
		oldest float64
	)
	if err := r.db.QueryRowContext(ctx, q).Scan(&depth, &oldest); err != nil {
		return scoring.QueueStats{}, fmt.Errorf("finding priority queue stats: %w", err)
	}
	return scoring.QueueStats{Depth: depth, OldestAge: time.Duration(oldest * float64(time.Second))}, nil
}

// EnqueueReconcile queues, tenant by tenant, every asset with an open
// finding. An asset with a finding whose version is missing or older than
// the tenant's current one is due now; the others are due after delay, so
// event-driven rows go first. A queued asset keeps its row. Manual
// overrides are not stale: the worker never changes them.
func (r *ScoringRepository) EnqueueReconcile(ctx context.Context, delay time.Duration) (int64, error) {
	if delay < 0 {
		delay = 0
	}
	tenants, err := r.tenantIDs(ctx)
	if err != nil {
		return 0, err
	}
	q := `
		WITH cur AS (SELECT scoring_version($1, 'finding_priority', $3) AS v),
		todo AS (
			SELECT f.asset_id,
			       bool_or(NOT f.priority_class_override
			               AND (f.priority_version IS NULL OR f.priority_version < cur.v)) AS stale
			FROM findings f CROSS JOIN cur
			JOIN assets a ON a.id = f.asset_id AND a.tenant_id = f.tenant_id AND a.deleted_at IS NULL
			WHERE f.tenant_id = $1 AND ` + vulnerability.OpenStatusSQL("f.status") + `
			GROUP BY f.asset_id
		), ins AS (
			INSERT INTO finding_priority_queue (asset_id, tenant_id, reason, scoring_change_id, enqueued_at)
			SELECT t.asset_id, $1::uuid,
			       CASE WHEN t.stale THEN '` + scoring.ReasonScoringChange + `' ELSE '` + scoring.ReasonReconcile + `' END,
			       CASE WHEN t.stale AND cur.v > 0 THEN cur.v END,
			       CASE WHEN t.stale THEN now() ELSE now() + make_interval(secs => $2) END
			FROM todo t CROSS JOIN cur
			ORDER BY t.asset_id
			ON CONFLICT (asset_id) DO NOTHING
			RETURNING 1
		)
		SELECT COUNT(*) FROM ins`
	var total int64
	for _, tid := range tenants {
		var n int64
		var err error
		// A batch racing an asset delete (foreign key violation) is retried:
		// its next snapshot no longer sees the asset.
		for attempt := 0; attempt < 3; attempt++ {
			err = r.db.QueryRowContext(ctx, q, tid, delay.Seconds(), scoring.PriorityModelVersion).Scan(&n)
			if !isForeignKeyViolation(err) {
				break
			}
		}
		if err != nil {
			return total, fmt.Errorf("enqueue finding priority reconcile: %w", err)
		}
		total += n
	}
	return total, nil
}

// StampVersion records the version the given open findings of the tenant
// were computed with. Closed findings are skipped: they stay frozen.
func (r *ScoringRepository) StampVersion(ctx context.Context, tenantID shared.ID, findingIDs []shared.ID, version int64) error {
	if len(findingIDs) == 0 {
		return nil
	}
	ids := make([]string, 0, len(findingIDs))
	for _, id := range findingIDs {
		ids = append(ids, id.String())
	}
	q := `
		UPDATE findings SET priority_version = $3, priority_scored_at = now()
		WHERE tenant_id = $1 AND id = ANY($2::uuid[]) AND ` + vulnerability.OpenStatusSQL("status") + `
		  AND priority_version IS DISTINCT FROM $3`
	if _, err := r.db.ExecContext(ctx, q, tenantID.String(), pq.Array(ids), version); err != nil {
		return fmt.Errorf("stamp finding priority version: %w", err)
	}
	return nil
}

// RecordImpact adds a pass's counts to the change's summary row of the
// tenant.
func (r *ScoringRepository) RecordImpact(ctx context.Context, tenantID shared.ID, changeID int64, im scoring.ChangeImpact) error {
	const q = `
		INSERT INTO scoring_change_impacts (scoring_change_id, tenant_id, findings_checked, findings_changed,
			findings_raised, raised_to_p0, findings_lowered, deadlines_tightened)
		SELECT c.id, $2, $3, $4, $5, $6, $7, $8 FROM scoring_changes c
		WHERE c.id = $1 AND (c.tenant_id = $2 OR c.tenant_id IS NULL)
		ON CONFLICT (tenant_id, scoring_change_id) DO UPDATE SET
			findings_checked = scoring_change_impacts.findings_checked + EXCLUDED.findings_checked,
			findings_changed = scoring_change_impacts.findings_changed + EXCLUDED.findings_changed,
			findings_raised = scoring_change_impacts.findings_raised + EXCLUDED.findings_raised,
			raised_to_p0 = scoring_change_impacts.raised_to_p0 + EXCLUDED.raised_to_p0,
			findings_lowered = scoring_change_impacts.findings_lowered + EXCLUDED.findings_lowered,
			deadlines_tightened = scoring_change_impacts.deadlines_tightened + EXCLUDED.deadlines_tightened,
			notified_at = NULL,
			updated_at = now()`
	if _, err := r.db.ExecContext(ctx, q, changeID, tenantID.String(), im.Checked, im.Changed,
		im.Raised, im.RaisedToP0, im.Lowered, im.DeadlinesTightened); err != nil {
		return fmt.Errorf("record scoring change impact: %w", err)
	}
	return nil
}

// ClaimDrainedSummaries marks as notified, and returns, the summaries whose
// change has no asset of the tenant left in the queue. Each is claimed once
// (the UPDATE is the claim); a later pass of the same change (a requeue)
// re-opens it with its new counts.
func (r *ScoringRepository) ClaimDrainedSummaries(ctx context.Context, limit int) ([]scoring.ChangeSummary, error) {
	if limit <= 0 {
		limit = 50
	}
	const q = `
		WITH due AS (
			SELECT i.tenant_id, i.scoring_change_id FROM scoring_change_impacts i
			WHERE i.notified_at IS NULL
			  AND NOT EXISTS (
				SELECT 1 FROM finding_priority_queue q
				WHERE q.tenant_id = i.tenant_id AND q.scoring_change_id = i.scoring_change_id)
			ORDER BY i.updated_at
			LIMIT $1
			FOR UPDATE SKIP LOCKED
		)
		UPDATE scoring_change_impacts i SET notified_at = now()
		FROM due, scoring_changes c
		WHERE i.tenant_id = due.tenant_id AND i.scoring_change_id = due.scoring_change_id
		  AND c.id = i.scoring_change_id
		RETURNING i.tenant_id, i.scoring_change_id, c.source, c.summary, i.findings_checked, i.findings_changed,
			i.findings_raised, i.raised_to_p0, i.findings_lowered, i.deadlines_tightened`
	rows, err := r.db.QueryContext(ctx, q, limit)
	if err != nil {
		return nil, fmt.Errorf("claim scoring change summaries: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []scoring.ChangeSummary
	for rows.Next() {
		var (
			s   scoring.ChangeSummary
			tid string
		)
		if err := rows.Scan(&tid, &s.ChangeID, &s.Source, &s.Summary, &s.Checked, &s.Changed,
			&s.Raised, &s.RaisedToP0, &s.Lowered, &s.DeadlinesTightened); err != nil {
			return nil, fmt.Errorf("scan scoring change summary: %w", err)
		}
		id, err := shared.IDFromString(tid)
		if err != nil {
			continue
		}
		s.TenantID = id
		out = append(out, s)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate scoring change summaries: %w", err)
	}
	return out, nil
}

// SavePriorities writes what a finding-priority pass computed, and only
// that: class and reason (unless a person overrode the class), derived
// reachability, the EPSS / KEV enrichment and the SLA deadline and status.
// Only a finding that is still open is written, so a finding closed while
// the pass ran stays frozen, and no other column (status, assignee, ...) a
// concurrent edit may have changed is overwritten. Returns how many rows
// were written.
func (r *ScoringRepository) SavePriorities(ctx context.Context, tenantID shared.ID, findings []*vulnerability.Finding) (int, error) {
	q := `
		UPDATE findings SET
			priority_class = CASE WHEN priority_class_override THEN priority_class ELSE $3 END,
			priority_class_reason = CASE WHEN priority_class_override THEN priority_class_reason ELSE $4 END,
			is_reachable = $5, reachable_from_count = $6,
			epss_score = $7, epss_percentile = $8, is_in_kev = $9, kev_due_date = $10,
			sla_deadline = $11, sla_status = $12,
			updated_at = now()
		WHERE tenant_id = $1 AND id = $2 AND ` + vulnerability.OpenStatusSQL("status")
	saved := 0
	for _, f := range findings {
		if f == nil {
			continue
		}
		res, err := r.db.ExecContext(ctx, q, tenantID.String(), f.ID().String(),
			nullPriorityClass(f.PriorityClass()), nullString(f.PriorityClassReason()),
			f.IsReachable(), f.ReachableFromCount(),
			nullFloat64(f.EPSSScore()), nullFloat64(f.EPSSPercentile()), f.IsInKEV(), nullTime(f.KEVDueDate()),
			nullTime(f.SLADeadline()), string(f.SLAStatus()))
		if err != nil {
			return saved, fmt.Errorf("save finding priority: %w", err)
		}
		if n, _ := res.RowsAffected(); n > 0 {
			saved++
		}
	}
	return saved, nil
}

// tenantIDs lists every tenant id.
func (r *ScoringRepository) tenantIDs(ctx context.Context) ([]string, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT id FROM tenants ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("list tenants for finding priority reconcile: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var tenants []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("scan tenant: %w", err)
		}
		tenants = append(tenants, id)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate tenants: %w", err)
	}
	return tenants, nil
}
