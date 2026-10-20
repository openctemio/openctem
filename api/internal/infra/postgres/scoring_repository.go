package postgres

// Scoring versions and the finding-priority queue
// (docs/architecture/scoring-versions.md). Queue rows are written by
// database triggers (migration scoring_versions) and by EnqueueAssets /
// EnqueueTenant, and claimed by the finding-priority worker.

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
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

// ClaimDrainedSummaries sends the summaries whose change has no asset of the
// tenant left in the queue, and marks each notified in the same transaction
// as its send (the outbox insert): a send that fails rolls back to its
// savepoint, leaving the summary unmarked for a later pass, so a failure
// never loses a summary. FOR UPDATE SKIP LOCKED keeps two workers from
// sending the same one. A later pass of the same change (a requeue)
// re-opens it with its new counts (RecordImpact clears notified_at).
func (r *ScoringRepository) ClaimDrainedSummaries(ctx context.Context, limit int, send scoring.SummarySender) (int, error) {
	if limit <= 0 {
		limit = 50
	}
	const q = `
		SELECT i.tenant_id, i.scoring_change_id, c.source, c.summary, i.findings_checked, i.findings_changed,
			i.findings_raised, i.raised_to_p0, i.findings_lowered, i.deadlines_tightened
		FROM scoring_change_impacts i
		JOIN scoring_changes c ON c.id = i.scoring_change_id
		WHERE i.notified_at IS NULL
		  AND NOT EXISTS (
			SELECT 1 FROM finding_priority_queue q
			WHERE q.tenant_id = i.tenant_id AND q.scoring_change_id = i.scoring_change_id)
		ORDER BY i.updated_at
		LIMIT $1
		FOR UPDATE OF i SKIP LOCKED`
	marked := 0
	var sendErrs []error
	err := r.db.Transaction(ctx, func(tx *sql.Tx) error {
		due, err := scanDueSummaries(ctx, tx, q, limit)
		if err != nil {
			return err
		}
		for _, s := range due {
			if _, err := tx.ExecContext(ctx, `SAVEPOINT scoring_summary`); err != nil {
				return fmt.Errorf("savepoint scoring change summary: %w", err)
			}
			if send != nil {
				if serr := send(ctx, tx, s); serr != nil {
					if _, err := tx.ExecContext(ctx, `ROLLBACK TO SAVEPOINT scoring_summary`); err != nil {
						return fmt.Errorf("roll back scoring change summary: %w", err)
					}
					sendErrs = append(sendErrs, fmt.Errorf("tenant %s change %d: %w", s.TenantID, s.ChangeID, serr))
					continue
				}
			}
			if _, err := tx.ExecContext(ctx, `
				UPDATE scoring_change_impacts SET notified_at = now()
				WHERE tenant_id = $1 AND scoring_change_id = $2`, s.TenantID.String(), s.ChangeID); err != nil {
				return fmt.Errorf("mark scoring change summary notified: %w", err)
			}
			if _, err := tx.ExecContext(ctx, `RELEASE SAVEPOINT scoring_summary`); err != nil {
				return fmt.Errorf("release scoring change summary: %w", err)
			}
			marked++
		}
		return nil
	})
	if err != nil {
		return 0, fmt.Errorf("claim scoring change summaries: %w", err)
	}
	if len(sendErrs) > 0 {
		return marked, fmt.Errorf("send scoring change summaries: %w", errors.Join(sendErrs...))
	}
	return marked, nil
}

// scanDueSummaries reads the locked, drained summaries.
func scanDueSummaries(ctx context.Context, tx *sql.Tx, q string, limit int) ([]scoring.ChangeSummary, error) {
	rows, err := tx.QueryContext(ctx, q, limit)
	if err != nil {
		return nil, err
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
	return out, rows.Err()
}

// EnqueueIntelChanges queues, after a threat-intel refresh, only the assets
// of open findings whose intel moved in a way a model can see: the catalog
// EPSS crossed a threshold the classifier or one of the tenant's active
// priority rules uses (relative to the EPSS stored on the finding), or the
// CVE entered or left the KEV catalog. Never a whole tenant. Each finding's
// own tenant_id goes on its queue row.
func (r *ScoringRepository) EnqueueIntelChanges(ctx context.Context) (int64, error) {
	open := vulnerability.OpenStatusSQL("f.status")
	epss := `
		WITH th AS (
			SELECT NULL::uuid AS tenant_id, v FROM unnest(ARRAY[0.01, 0.1, 0.5]::numeric[]) AS v
			UNION ALL
			SELECT r.tenant_id, (c->>'value')::numeric
			FROM priority_override_rules r, jsonb_array_elements(r.conditions) c
			WHERE r.is_active AND c->>'field' = 'epss_score' AND jsonb_typeof(c->'value') = 'number'
		), moved AS (
			SELECT DISTINCT f.asset_id, f.tenant_id
			FROM findings f
			JOIN epss_scores e ON e.cve_id = f.cve_id
			JOIN assets a ON a.id = f.asset_id AND a.tenant_id = f.tenant_id AND a.deleted_at IS NULL
			WHERE ` + open + `
			  AND COALESCE(f.epss_score, 0) <> e.epss_score
			  AND EXISTS (
				SELECT 1 FROM th
				WHERE (th.tenant_id IS NULL OR th.tenant_id = f.tenant_id)
				  AND LEAST(COALESCE(f.epss_score, 0), e.epss_score) <= th.v
				  AND GREATEST(COALESCE(f.epss_score, 0), e.epss_score) >= th.v)
		)
		INSERT INTO finding_priority_queue (asset_id, tenant_id, reason)
		SELECT asset_id, tenant_id, '` + scoring.ReasonIntel + `' FROM moved
		ORDER BY asset_id
		ON CONFLICT (asset_id) DO UPDATE SET enqueued_at = EXCLUDED.enqueued_at
			WHERE finding_priority_queue.enqueued_at > EXCLUDED.enqueued_at`
	kev := `
		INSERT INTO finding_priority_queue (asset_id, tenant_id, reason)
		SELECT DISTINCT f.asset_id, f.tenant_id, '` + scoring.ReasonIntel + `'
		FROM findings f
		JOIN assets a ON a.id = f.asset_id AND a.tenant_id = f.tenant_id AND a.deleted_at IS NULL
		WHERE ` + open + ` AND f.cve_id IS NOT NULL AND f.cve_id <> ''
		  AND COALESCE(f.is_in_kev, false) <> EXISTS (SELECT 1 FROM kev_catalog k WHERE k.cve_id = f.cve_id)
		ORDER BY f.asset_id
		ON CONFLICT (asset_id) DO UPDATE SET enqueued_at = EXCLUDED.enqueued_at
			WHERE finding_priority_queue.enqueued_at > EXCLUDED.enqueued_at`
	var total int64
	for _, q := range []string{epss, kev} {
		var res sql.Result
		var err error
		for attempt := 0; attempt < 3; attempt++ {
			res, err = r.db.ExecContext(ctx, q)
			if !isForeignKeyViolation(err) {
				break
			}
		}
		if err != nil {
			return total, fmt.Errorf("enqueue intel changes: %w", err)
		}
		n, _ := res.RowsAffected()
		total += n
	}
	return total, nil
}

// SavePriorities writes what a finding-priority pass computed, and only
// that: class and reason (unless a person overrode the class), derived
// reachability, the EPSS / KEV enrichment and the SLA deadline and status.
// The deadline only tightens (min of the stored and the computed one, a
// missing computation keeps the stored one), so a pass that read the row
// before a concurrent tightening cannot undo it; the findings trigger
// trg_findings_sla_deadline_guard enforces the same rule for every writer.
// Only a finding that is still open is written, so a finding closed while
// the pass ran stays frozen, and no other column (status, assignee, ...) a
// concurrent edit may have changed is overwritten. One statement writes up to
// savePriorityBatch findings (UPDATE ... FROM VALUES), so a pass over a large
// tenant costs one round trip per batch, not one per finding. Returns how
// many rows were written.
func (r *ScoringRepository) SavePriorities(ctx context.Context, tenantID shared.ID, findings []*vulnerability.Finding) (int, error) {
	// One row per finding (the last copy wins): UPDATE ... FROM VALUES must
	// not see one id twice.
	seen := make(map[shared.ID]int, len(findings))
	rows := make([]*vulnerability.Finding, 0, len(findings))
	for _, f := range findings {
		if f == nil {
			continue
		}
		if i, dup := seen[f.ID()]; dup {
			rows[i] = f
			continue
		}
		seen[f.ID()] = len(rows)
		rows = append(rows, f)
	}
	saved := 0
	err := forEachStatementChunk(len(rows), savePriorityParams, 1, savePriorityBatch, func(start, end int) error {
		values := make([]string, 0, end-start)
		args := make([]any, 1, 1+(end-start)*savePriorityParams)
		args[0] = tenantID.String()
		for _, f := range rows[start:end] {
			n := len(args)
			values = append(values, fmt.Sprintf(
				"($%d::uuid, $%d::varchar, $%d::text, $%d::boolean, $%d::integer, $%d::numeric, $%d::numeric, "+
					"$%d::boolean, $%d::date, $%d::timestamptz, $%d::varchar)",
				n+1, n+2, n+3, n+4, n+5, n+6, n+7, n+8, n+9, n+10, n+11))
			args = append(args, f.ID().String(),
				nullPriorityClass(f.PriorityClass()), nullString(f.PriorityClassReason()),
				f.IsReachable(), f.ReachableFromCount(),
				nullFloat64(f.EPSSScore()), nullFloat64(f.EPSSPercentile()), f.IsInKEV(), nullTime(f.KEVDueDate()),
				nullTime(f.SLADeadline()), string(f.SLAStatus()))
		}
		res, err := r.db.ExecContext(ctx, `
		UPDATE findings f SET
			priority_class = CASE WHEN f.priority_class_override THEN f.priority_class ELSE v.class END,
			priority_class_reason = CASE WHEN f.priority_class_override THEN f.priority_class_reason ELSE v.reason END,
			is_reachable = v.reachable, reachable_from_count = v.reach_from,
			epss_score = v.epss, epss_percentile = v.epss_pct, is_in_kev = v.kev, kev_due_date = v.kev_due,
			sla_deadline = CASE
				WHEN v.sla IS NULL THEN f.sla_deadline
				WHEN f.sla_deadline IS NULL THEN v.sla
				ELSE LEAST(f.sla_deadline, v.sla) END,
			sla_status = CASE
				WHEN v.sla IS NULL THEN f.sla_status
				WHEN f.sla_deadline IS NULL OR v.sla < f.sla_deadline THEN v.sla_status
				ELSE f.sla_status END,
			updated_at = now()
		FROM (VALUES `+strings.Join(values, ", ")+`)
			AS v(id, class, reason, reachable, reach_from, epss, epss_pct, kev, kev_due, sla, sla_status)
		WHERE f.tenant_id = $1 AND f.id = v.id AND `+vulnerability.OpenStatusSQL("f.status"), args...)
		if err != nil {
			return fmt.Errorf("save finding priorities: %w", err)
		}
		n, _ := res.RowsAffected()
		saved += int(n)
		return nil
	})
	return saved, err
}

// savePriorityParams is the bind parameters per finding in SavePriorities;
// savePriorityBatch caps the findings per statement (rows locked at once).
const (
	savePriorityParams = 11
	savePriorityBatch  = 1000
)

// epssRefreshBatch bounds one EPSS refresh statement (rows locked at once).
const epssRefreshBatch = 2000

// RefreshFindingEPSS writes the catalog EPSS score onto every
// open finding whose CVE's catalog score differs from the stored one: a
// plain column update, tenant by tenant, in batches of epssRefreshBatch
// (rows another writer holds are skipped and picked up by the next run).
// Run it after EnqueueIntelChanges, which compares the stored values with
// the catalog to find threshold crossings. Closed findings keep the values
// they had when closed. Returns how many findings were written.
//
// Only the score is compared and written. The percentile is a rank that moves
// for almost every CVE on every feed; copying it rewrote nearly every open
// finding daily. A finding's stored percentile is the one in force when its
// score last moved (or when it was scored); the current rank is the catalog's.
func (r *ScoringRepository) RefreshFindingEPSS(ctx context.Context) (int64, error) {
	tenants, err := r.tenantIDs(ctx)
	if err != nil {
		return 0, err
	}
	q := `
		UPDATE findings f SET epss_score = s.epss_score
		FROM (
			SELECT f2.id, e.epss_score
			FROM findings f2
			JOIN epss_scores e ON e.cve_id = f2.cve_id
			WHERE f2.tenant_id = $1 AND ` + vulnerability.OpenStatusSQL("f2.status") + `
			  AND f2.epss_score IS DISTINCT FROM e.epss_score
			ORDER BY f2.id
			LIMIT $2
			FOR UPDATE OF f2 SKIP LOCKED
		) s
		WHERE f.tenant_id = $1 AND f.id = s.id`
	var total int64
	for _, tid := range tenants {
		for {
			if err := ctx.Err(); err != nil {
				return total, err
			}
			res, err := r.db.ExecContext(ctx, q, tid, epssRefreshBatch)
			if err != nil {
				return total, fmt.Errorf("refresh finding epss: %w", err)
			}
			n, _ := res.RowsAffected()
			total += n
			if n < epssRefreshBatch {
				break
			}
		}
	}
	return total, nil
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
