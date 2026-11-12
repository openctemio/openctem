package postgres

// Source retirements (docs/architecture/source-retirement.md): "stop using
// this source". One classifier decides, per finding the source reported,
// what retiring it does; the preview counts it and the archive updates the
// rows it marks "archive", so the two can never disagree.

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/domain/sourceretire"
	"github.com/openctemio/openctem/server/pkg/domain/vulnerability"
)

// SourceRetirementRepository implements sourceretire.Repository.
type SourceRetirementRepository struct {
	db *DB
}

// NewSourceRetirementRepository returns the repository.
func NewSourceRetirementRepository(db *DB) *SourceRetirementRepository {
	return &SourceRetirementRepository{db: db}
}

var _ sourceretire.Repository = (*SourceRetirementRepository)(nil)

// The statuses an archive moves (to resolved) and a restore returns to.
// Checked against the lifecycle when the package loads.
var (
	sourceRetireFromSQL = platformFromSQL(vulnerability.FindingStatusResolved,
		vulnerability.FindingStatusNew, vulnerability.FindingStatusConfirmed)
	_ = platformFromSQL(vulnerability.FindingStatusNew, vulnerability.FindingStatusResolved)
	_ = platformFromSQL(vulnerability.FindingStatusConfirmed, vulnerability.FindingStatusResolved)
)

// sourceDriverSQL is, per kind, the sighting predicate of the source on
// alias s, served by an index of finding_sightings (sensor, channel). The
// same rule as source_retirement_matches. Parameters: $3 sensor, $4 sender,
// $5 tool.
var sourceDriverSQL = map[sourceretire.Kind]string{ //nolint:gochecknoglobals // static fragments
	sourceretire.KindSensorTool: `s.sensor_id = $3::uuid AND lower(s.tool) = lower($5::text)`,
	sourceretire.KindUpload:     `s.channel = 'upload' AND s.sender = '' AND lower(s.tool) = lower($5::text)`,
	sourceretire.KindConnector:  `s.channel = 'connector' AND s.sender = $4::text`,
}

// sourceClassifySQL classifies every finding the source reported.
// Parameters: $1 tenant, $2 kind, $3 sensor, $4 sender, $5 tool,
// $6 severities to archive (empty: all), $7 include engaged. Columns: id,
// status, severity, is_in_kev, sla_deadline, cls.
//
// cls:
//   - corroborated: a source that is not retired reported it too, it has no
//     room for more recorded sources (at the cap another one may be
//     missing), or a person's channel owns it (pentest, manual, bug bounty,
//     red team);
//   - closed: it is not open;
//   - in_progress: open but past new/confirmed (someone works on it);
//   - secret: a secret stays open until it is rotated;
//   - engaged: a ticket, an open remediation task or an assignee (unless
//     included);
//   - severity: its severity was not selected;
//   - archive: archived as source retired.
func sourceClassifySQL(kind sourceretire.Kind) (string, error) {
	driver, ok := sourceDriverSQL[kind]
	if !ok {
		return "", fmt.Errorf("%w: unknown source kind", shared.ErrValidation)
	}
	//nolint:gosec // G202: fixed fragments only; values are numbered parameters
	return `WITH hit AS (
	SELECT DISTINCT s.finding_id FROM finding_sightings s WHERE s.tenant_id = $1 AND ` + driver + `
), c AS (
	SELECT f.id, f.status, lower(f.severity) AS severity, COALESCE(f.is_in_kev, false) AS is_in_kev, f.sla_deadline,
	CASE
		WHEN f.source IN ` + coverageProtectedSources + `
			OR EXISTS (SELECT 1 FROM finding_sightings o WHERE o.tenant_id = $1 AND o.finding_id = f.id
				AND NOT source_retirement_matches($2, $3::uuid, $4, $5, o.channel, o.sensor_id, o.sender, o.tool)
				AND NOT ` + vulnerability.SightingRetiredSQL("$1", "o") + `)
			OR (SELECT count(*) FROM finding_sightings o WHERE o.tenant_id = $1 AND o.finding_id = f.id) >= ` + fmt.Sprint(sourceretire.MaxSightingCap) + `
			THEN 'corroborated'
		WHEN NOT is_open_finding_status(f.status) THEN 'closed'
		WHEN f.status NOT IN ` + sourceRetireFromSQL + ` THEN 'in_progress'
		WHEN ` + secretFindingSQL("f") + ` THEN 'secret'
		WHEN NOT $7::boolean AND (f.assigned_to IS NOT NULL
			OR EXISTS (SELECT 1 FROM ticket_links t WHERE t.tenant_id = $1 AND t.finding_id = f.id AND t.state = 'active')
			OR EXISTS (SELECT 1 FROM remediation_task_members m WHERE m.tenant_id = $1 AND m.finding_id = f.id AND m.left_at IS NULL))
			THEN 'engaged'
		WHEN cardinality($6::text[]) > 0 AND NOT (lower(f.severity) = ANY($6::text[])) THEN 'severity'
		ELSE 'archive'
	END AS cls
	FROM hit JOIN findings f ON f.tenant_id = $1 AND f.id = hit.finding_id
)`, nil
}

func sourceArgs(tenantID shared.ID, sel sourceretire.Selector, opts sourceretire.Options) []any {
	var sensor sql.NullString
	if sel.SensorID != nil {
		sensor = sql.NullString{String: sel.SensorID.String(), Valid: true}
	}
	return []any{tenantID.String(), string(sel.Kind), sensor, sel.Sender, sel.Tool,
		pq.Array(opts.SeverityStrings()), opts.IncludeEngaged}
}

// Preview classifies the findings the source reported and counts them.
func (r *SourceRetirementRepository) Preview(ctx context.Context, tenantID shared.ID, sel sourceretire.Selector,
	opts sourceretire.Options, _ *shared.ID,
) (*sourceretire.Preview, error) {
	with, err := sourceClassifySQL(sel.Kind)
	if err != nil {
		return nil, err
	}
	var p sourceretire.Preview
	var bySev []byte
	err = r.db.QueryRowContext(ctx, with+`
SELECT count(*),
	count(*) FILTER (WHERE cls = 'archive'),
	count(*) FILTER (WHERE cls = 'archive' AND (severity = 'critical' OR is_in_kev)),
	count(*) FILTER (WHERE cls = 'archive' AND sla_deadline IS NOT NULL),
	count(*) FILTER (WHERE cls = 'corroborated'),
	count(*) FILTER (WHERE cls = 'engaged'),
	count(*) FILTER (WHERE cls = 'in_progress'),
	count(*) FILTER (WHERE cls = 'secret'),
	count(*) FILTER (WHERE cls = 'severity'),
	count(*) FILTER (WHERE cls = 'closed'),
	COALESCE((SELECT jsonb_object_agg(severity, n) FROM (SELECT severity, count(*) AS n FROM c WHERE cls = 'archive' GROUP BY severity) x), '{}'::jsonb)
FROM c`, sourceArgs(tenantID, sel, opts)...).Scan(&p.Total, &p.Archive, &p.CriticalOrKEV, &p.WithSLA, &p.Corroborated,
		&p.KeptEngaged, &p.KeptInProgress, &p.KeptSecret, &p.KeptSeveritySkipped, &p.AlreadyClosed, &bySev)
	if err != nil {
		return nil, fmt.Errorf("preview source retirement: %w", err)
	}
	p.ArchiveBySeverity = map[string]int{}
	if err := json.Unmarshal(bySev, &p.ArchiveBySeverity); err != nil {
		return nil, fmt.Errorf("preview severities: %w", err)
	}
	if opts.Mode == sourceretire.ModeKeepOpen {
		// Nothing is archived: what would have been is kept open.
		p.Archive, p.CriticalOrKEV, p.WithSLA, p.ArchiveBySeverity = 0, 0, 0, map[string]int{}
	}
	return &p, nil
}

const sourceRetirementColumns = `id, tenant_id, kind, sensor_id, sender, tool, integration_id, label, mode, severities,
	include_engaged, state, reason, planned_count, archived_count, restored_count, changed_count, retired_by, retired_at,
	restored_by, restore_reason, restored_at, updated_at`

func scanSourceRetirement(row interface{ Scan(...any) error }) (*sourceretire.Retirement, error) {
	var (
		out                                        sourceretire.Retirement
		id, tenant, kind, mode, state              string
		sensor, integration, retiredBy, restoredBy sql.NullString
		sevs                                       []string
		restoredAt                                 sql.NullTime
	)
	if err := row.Scan(&id, &tenant, &kind, &sensor, &out.Selector.Sender, &out.Selector.Tool, &integration, &out.Label,
		&mode, pq.Array(&sevs), &out.Options.IncludeEngaged, &state, &out.Reason, &out.PlannedCount, &out.ArchivedCount,
		&out.RestoredCount, &out.ChangedCount, &retiredBy, &out.RetiredAt, &restoredBy, &out.RestoreReason, &restoredAt,
		&out.UpdatedAt); err != nil {
		return nil, err
	}
	out.ID, _ = shared.IDFromString(id)
	out.TenantID, _ = shared.IDFromString(tenant)
	out.Selector.Kind, out.Options.Mode, out.State = sourceretire.Kind(kind), sourceretire.Mode(mode), sourceretire.State(state)
	out.Selector.SensorID = optionalID(sensor)
	out.IntegrationID = optionalID(integration)
	out.RetiredBy = optionalID(retiredBy)
	out.RestoredBy = optionalID(restoredBy)
	for _, s := range sevs {
		out.Options.Severities = append(out.Options.Severities, vulnerability.Severity(s))
	}
	if restoredAt.Valid {
		t := restoredAt.Time
		out.RestoredAt = &t
	}
	return &out, nil
}

// Create inserts the retirement, or returns the live retirement of the same
// source (AlreadyRetired): one live retirement per source.
func (r *SourceRetirementRepository) Create(ctx context.Context, in *sourceretire.Retirement) (*sourceretire.Retirement, error) {
	state := sourceretire.StateApplying
	if in.Options.Mode == sourceretire.ModeKeepOpen {
		state = sourceretire.StateActive
	}
	sel := in.Selector
	row := r.db.QueryRowContext(ctx, `INSERT INTO source_retirements (tenant_id, kind, sensor_id, sender, tool,
		integration_id, label, mode, severities, include_engaged, state, reason, planned_count, retired_by)
	VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
	ON CONFLICT (tenant_id, kind, sensor_id, sender, tool) WHERE state <> 'restored' DO NOTHING
	RETURNING `+sourceRetirementColumns,
		in.TenantID.String(), string(sel.Kind), nullableID(sel.SensorID), sel.Sender, sel.Tool, nullableID(in.IntegrationID),
		in.Label, string(in.Options.Mode), pq.Array(in.Options.SeverityStrings()), in.Options.IncludeEngaged, string(state),
		in.Reason, in.PlannedCount, nullableID(in.RetiredBy))
	out, err := scanSourceRetirement(row)
	if err == nil {
		return out, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("create source retirement: %w", err)
	}
	out, err = scanSourceRetirement(r.db.QueryRowContext(ctx, `SELECT `+sourceRetirementColumns+` FROM source_retirements
		WHERE tenant_id = $1 AND kind = $2 AND sensor_id IS NOT DISTINCT FROM $3::uuid AND sender = $4 AND tool = $5
		AND state <> 'restored'`, in.TenantID.String(), string(sel.Kind), nullableID(sel.SensorID), sel.Sender, sel.Tool))
	if err != nil {
		return nil, fmt.Errorf("read live source retirement: %w", err)
	}
	out.AlreadyRetired = true
	return out, nil
}

// Get returns one retirement of the tenant.
func (r *SourceRetirementRepository) Get(ctx context.Context, tenantID, id shared.ID) (*sourceretire.Retirement, error) {
	out, err := scanSourceRetirement(r.db.QueryRowContext(ctx, `SELECT `+sourceRetirementColumns+`
		FROM source_retirements WHERE tenant_id = $1 AND id = $2`, tenantID.String(), id.String()))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, sourceretire.ErrNotFound
	}
	return out, err
}

// List returns the tenant's retirements, live first, newest first.
func (r *SourceRetirementRepository) List(ctx context.Context, tenantID shared.ID, includeRestored bool, limit int) ([]*sourceretire.Retirement, error) {
	if limit <= 0 || limit > 500 {
		limit = 500
	}
	rows, err := r.db.QueryContext(ctx, `SELECT `+sourceRetirementColumns+` FROM source_retirements
		WHERE tenant_id = $1 AND ($2 OR state <> 'restored')
		ORDER BY (state = 'restored'), retired_at DESC LIMIT $3`, tenantID.String(), includeRestored, limit)
	if err != nil {
		return nil, fmt.Errorf("list source retirements: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := []*sourceretire.Retirement{}
	for rows.Next() {
		ret, err := scanSourceRetirement(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, ret)
	}
	return out, rows.Err()
}

// lockRetirement locks the retirement row in tx when it is in state.
func lockRetirement(ctx context.Context, tx *sql.Tx, tenantID, id shared.ID, state sourceretire.State) (*sourceretire.Retirement, error) {
	ret, err := scanSourceRetirement(tx.QueryRowContext(ctx, `SELECT `+sourceRetirementColumns+` FROM source_retirements
		WHERE tenant_id = $1 AND id = $2 FOR UPDATE`, tenantID.String(), id.String()))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, sourceretire.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if ret.State != state {
		return nil, nil //nolint:nilnil // not in the state: nothing to do
	}
	return ret, nil
}

func actorOf(id *shared.ID) (string, string) {
	if id == nil {
		return string(vulnerability.ActorTypeSystem), ""
	}
	return string(vulnerability.ActorTypeUser), id.String()
}

// ArchiveBatch archives up to BatchSize findings of an applying retirement,
// journals them in the same transaction (with the timeline entry the
// transition trigger writes), and marks the retirement active when no
// finding is left. A batch that runs again changes nothing it already did.
func (r *SourceRetirementRepository) ArchiveBatch(ctx context.Context, tenantID, id shared.ID, at time.Time) (*sourceretire.BatchResult, error) {
	res := &sourceretire.BatchResult{}
	err := r.db.Transaction(ctx, func(tx *sql.Tx) error {
		if err := setLocalStatementTimeout(ctx, tx, timeoutBatch); err != nil {
			return err
		}
		ret, err := lockRetirement(ctx, tx, tenantID, id, sourceretire.StateApplying)
		if err != nil || ret == nil {
			res.Finished = ret == nil && err == nil
			return err
		}
		actorType, actorID := actorOf(ret.RetiredBy)
		if err := setFindingTransition(ctx, tx, findingTransition{
			Source: "source_retire", Reason: "source_retired", ActorType: actorType, ActorID: actorID,
			Message: "Only a source that was retired reported it", Changes: map[string]any{"source_retirement_id": id.String()},
		}); err != nil {
			return err
		}
		with, err := sourceClassifySQL(ret.Selector.Kind)
		if err != nil {
			return err
		}
		args := sourceArgs(tenantID, ret.Selector, ret.Options)
		args = append(args, sourceretire.BatchSize)
		// Lock the batch with its current status (re-checked under the lock).
		ids, prior, err := pickArchiveBatch(ctx, tx, with, args)
		if err != nil {
			return err
		}
		if len(ids) > 0 {
			moved, err := tx.QueryContext(ctx, `WITH upd AS (
	UPDATE findings f SET status = 'resolved', resolution = 'source_retired', closure_reason = 'obsolete_source',
		verification = 'none', resolved_at = $3, resolved_by = $4, updated_at = NOW()
	FROM unnest($2::uuid[], $5::text[]) AS x(id, prior)
	WHERE f.tenant_id = $1 AND f.id = x.id AND f.status = x.prior
	RETURNING f.id, x.prior
), j AS (
	INSERT INTO source_retirement_findings (tenant_id, retirement_id, finding_id, prior_status, archived_at)
	SELECT $1, $6, upd.id, upd.prior, $3 FROM upd
	ON CONFLICT (tenant_id, retirement_id, finding_id) DO NOTHING
)
SELECT id::text FROM upd`, tenantID.String(), pq.Array(ids), at, nullableID(ret.RetiredBy), pq.Array(prior), id.String())
			if err != nil {
				return fmt.Errorf("archive findings: %w", err)
			}
			res.IDs, err = scanIDs(moved)
			if err != nil {
				return err
			}
			res.Moved = len(res.IDs)
		}
		// Done only when nothing is left to pick: a picked finding whose
		// status moved before the lock is left out of ids, so a short batch
		// does not prove the rest is done.
		res.Finished = len(ids) == 0
		state := sourceretire.StateApplying
		if res.Finished {
			state = sourceretire.StateActive
		}
		_, err = tx.ExecContext(ctx, `UPDATE source_retirements SET archived_count = archived_count + $3, state = $4,
			updated_at = NOW() WHERE tenant_id = $1 AND id = $2`, tenantID.String(), id.String(), res.Moved, string(state))
		return err
	})
	if err != nil {
		return nil, err
	}
	return res, nil
}

// pickArchiveBatch locks the next batch of findings to archive with their
// current status (re-checked under the lock).
func pickArchiveBatch(ctx context.Context, tx *sql.Tx, with string, args []any) (ids, prior []string, err error) {
	rows, err := tx.QueryContext(ctx, with+`
SELECT f.id::text, f.status FROM findings f
WHERE f.tenant_id = $1 AND f.status IN `+sourceRetireFromSQL+`
  AND f.id IN (SELECT id FROM c WHERE cls = 'archive' ORDER BY id LIMIT $8)
ORDER BY f.id FOR UPDATE OF f`, args...)
	if err != nil {
		return nil, nil, fmt.Errorf("pick findings to archive: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var fid, st string
		if err := rows.Scan(&fid, &st); err != nil {
			return nil, nil, err
		}
		ids, prior = append(ids, fid), append(prior, st)
	}
	return ids, prior, rows.Err()
}

// StartRestore makes the source usable again at once (the state leaves the
// live set, so ingest accepts it) and leaves the findings to RestoreBatch.
func (r *SourceRetirementRepository) StartRestore(ctx context.Context, tenantID, id shared.ID, by *shared.ID, reason string) (*sourceretire.Retirement, error) {
	out, err := scanSourceRetirement(r.db.QueryRowContext(ctx, `UPDATE source_retirements SET state = 'restoring',
		restored_by = $3, restore_reason = $4, updated_at = NOW()
		WHERE tenant_id = $1 AND id = $2 AND state IN ('applying', 'active')
		RETURNING `+sourceRetirementColumns, tenantID.String(), id.String(), nullableID(by), reason))
	if errors.Is(err, sql.ErrNoRows) {
		if _, gerr := r.Get(ctx, tenantID, id); gerr != nil {
			return nil, gerr
		}
		return nil, sourceretire.ErrNotRestorable
	}
	return out, err
}

// RestoreBatch restores up to BatchSize journalled findings to their prior
// status. A finding is restored only while it is still the closure the
// retirement made (resolved as source retired at the journalled time); one
// that a person or another source changed since is left as is and counted
// as changed. The retirement is restored when no journal row is left.
func (r *SourceRetirementRepository) RestoreBatch(ctx context.Context, tenantID, id shared.ID, at time.Time) (*sourceretire.BatchResult, error) {
	res := &sourceretire.BatchResult{}
	err := r.db.Transaction(ctx, func(tx *sql.Tx) error {
		if err := setLocalStatementTimeout(ctx, tx, timeoutBatch); err != nil {
			return err
		}
		ret, err := lockRetirement(ctx, tx, tenantID, id, sourceretire.StateRestoring)
		if err != nil || ret == nil {
			res.Finished = ret == nil && err == nil
			return err
		}
		actorType, actorID := actorOf(ret.RestoredBy)
		if err := setFindingTransition(ctx, tx, findingTransition{
			Source: "source_restore", Reason: "source_restored", ActorType: actorType, ActorID: actorID,
			Message: "The retired source that only reported it is used again", Changes: map[string]any{"source_retirement_id": id.String()},
		}); err != nil {
			return err
		}
		rows, err := tx.QueryContext(ctx, `SELECT finding_id::text FROM source_retirement_findings
			WHERE tenant_id = $1 AND retirement_id = $2 AND restored_at IS NULL
			ORDER BY finding_id LIMIT $3 FOR UPDATE`, tenantID.String(), id.String(), sourceretire.BatchSize)
		if err != nil {
			return fmt.Errorf("pick findings to restore: %w", err)
		}
		batch, err := scanIDs(rows)
		if err != nil {
			return err
		}
		if len(batch) > 0 {
			ids := make([]string, 0, len(batch))
			for _, b := range batch {
				ids = append(ids, b.String())
			}
			restored, err := tx.QueryContext(ctx, `WITH upd AS (
	UPDATE findings f SET status = j.prior_status, resolution = NULL, closure_reason = NULL, verification = NULL,
		resolved_at = NULL, resolved_by = NULL, updated_at = NOW()
	FROM source_retirement_findings j
	WHERE j.tenant_id = $1 AND j.retirement_id = $2 AND j.finding_id = ANY($3::uuid[])
	  AND f.tenant_id = $1 AND f.id = j.finding_id
	  AND f.status = 'resolved' AND f.closure_reason = 'obsolete_source' AND f.resolution = 'source_retired'
	  AND f.resolved_at = j.archived_at
	RETURNING f.id
), mark AS (
	UPDATE source_retirement_findings j SET restored_at = $4,
		restore_outcome = CASE WHEN j.finding_id IN (SELECT id FROM upd) THEN 'restored' ELSE 'changed' END
	WHERE j.tenant_id = $1 AND j.retirement_id = $2 AND j.finding_id = ANY($3::uuid[])
)
SELECT id::text FROM upd`, tenantID.String(), id.String(), pq.Array(ids), at)
			if err != nil {
				return fmt.Errorf("restore findings: %w", err)
			}
			res.IDs, err = scanIDs(restored)
			if err != nil {
				return err
			}
			res.Moved, res.Changed = len(res.IDs), len(batch)-len(res.IDs)
		}
		res.Finished = len(batch) < sourceretire.BatchSize
		state, restoredAt := sourceretire.StateRestoring, sql.NullTime{}
		if res.Finished {
			state, restoredAt = sourceretire.StateRestored, sql.NullTime{Time: at, Valid: true}
		}
		_, err = tx.ExecContext(ctx, `UPDATE source_retirements SET restored_count = restored_count + $3,
			changed_count = changed_count + $4, state = $5, restored_at = $6, updated_at = NOW()
			WHERE tenant_id = $1 AND id = $2`, tenantID.String(), id.String(), res.Moved, res.Changed, string(state), restoredAt)
		return err
	})
	if err != nil {
		return nil, err
	}
	return res, nil
}

// Live returns the selectors of the tenant's live retirements.
func (r *SourceRetirementRepository) Live(ctx context.Context, tenantID shared.ID) ([]sourceretire.Selector, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT kind, sensor_id, sender, tool FROM source_retirements
		WHERE tenant_id = $1 AND state IN ('applying', 'active')`, tenantID.String())
	if err != nil {
		return nil, fmt.Errorf("live source retirements: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := []sourceretire.Selector{}
	for rows.Next() {
		var (
			kind   string
			sensor sql.NullString
			sel    sourceretire.Selector
		)
		if err := rows.Scan(&kind, &sensor, &sel.Sender, &sel.Tool); err != nil {
			return nil, err
		}
		sel.Kind, sel.SensorID = sourceretire.Kind(kind), optionalID(sensor)
		out = append(out, sel)
	}
	return out, rows.Err()
}

// Pending lists retirements with batches left, of every tenant (the
// controller resumes them), least recently touched first.
func (r *SourceRetirementRepository) Pending(ctx context.Context, limit int) ([]sourceretire.PendingRef, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT tenant_id::text, id::text, state FROM source_retirements
		WHERE state IN ('applying', 'restoring') ORDER BY updated_at LIMIT $1`, limit)
	if err != nil {
		return nil, fmt.Errorf("pending source retirements: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := []sourceretire.PendingRef{}
	for rows.Next() {
		var t, id, st string
		if err := rows.Scan(&t, &id, &st); err != nil {
			return nil, err
		}
		ref := sourceretire.PendingRef{State: sourceretire.State(st)}
		ref.TenantID, _ = shared.IDFromString(t)
		ref.ID, _ = shared.IDFromString(id)
		out = append(out, ref)
	}
	return out, rows.Err()
}
