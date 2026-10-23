package postgres

// Receipts of uploads and sensor runs, the per-finding action log and the
// daily ingest fact (docs/rfcs/RFC-122-ingest-receipts.md). Every statement
// is scoped by tenant_id.

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/pkg/domain/ingestreceipt"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// IngestReceiptRepository stores receipts.
type IngestReceiptRepository struct {
	db *DB
}

// NewIngestReceiptRepository creates the repository.
func NewIngestReceiptRepository(db *DB) *IngestReceiptRepository {
	return &IngestReceiptRepository{db: db}
}

var _ ingestreceipt.Repository = (*IngestReceiptRepository)(nil)

// maxToolName is the width of tool_name and dash_ingest_day.tool.
const maxToolName = 100

// unknownTool is the fact key of an ingest that named no tool.
const unknownTool = "unknown"

// Record applies a delta in one transaction: the receipt (created on first
// use, its row locked by the upsert so concurrent batches of one run
// serialize), the action rows up to the cap, the counts the rows added, and
// the day's dash_ingest_day row.
func (r *IngestReceiptRepository) Record(ctx context.Context, d *ingestreceipt.Delta) (shared.ID, error) {
	if d == nil || d.TenantID.IsZero() {
		return shared.ID{}, fmt.Errorf("%w: receipt delta needs a tenant", shared.ErrValidation)
	}
	at := d.At
	if at.IsZero() {
		at = time.Now()
	}
	at = at.UTC()
	tool := clipTool(d.Tool)
	var id shared.ID
	err := r.db.Transaction(ctx, func(tx *sql.Tx) error {
		kind, ref, err := resolveReceiptSource(ctx, tx, d.TenantID, d.Source)
		if err != nil {
			return err
		}
		var rid string
		var recorded int
		err = tx.QueryRowContext(ctx, `
			INSERT INTO ingest_receipts (id, tenant_id, source_kind, source_ref, tool_name, status, created_at, updated_at)
			VALUES ($1, $2, $3, $4, NULLIF($5, ''), 'completed', $6, $6)
			ON CONFLICT (tenant_id, source_kind, source_ref) DO UPDATE
				SET updated_at = GREATEST(ingest_receipts.updated_at, EXCLUDED.updated_at),
					tool_name = COALESCE(ingest_receipts.tool_name, EXCLUDED.tool_name)
			RETURNING id::text, actions_recorded`,
			shared.NewID().String(), d.TenantID.String(), string(kind), ref, tool, at).Scan(&rid, &recorded)
		if err != nil {
			return fmt.Errorf("upsert receipt: %w", err)
		}
		if id, err = shared.IDFromString(rid); err != nil {
			return fmt.Errorf("receipt id: %w", err)
		}

		applied, err := insertReceiptActions(ctx, tx, d, id, at, recorded)
		if err != nil {
			return err
		}
		errs, err := json.Marshal(clipErrors(d.Errors))
		if err != nil {
			return fmt.Errorf("receipt errors: %w", err)
		}
		_, err = tx.ExecContext(ctx, `
			UPDATE ingest_receipts SET
				reports = reports + $3,
				findings_received = findings_received + $4,
				assets_created = assets_created + $5,
				assets_updated = assets_updated + $6,
				findings_created = findings_created + $7,
				findings_updated = findings_updated + $8,
				findings_reopened = findings_reopened + $9,
				findings_closed = findings_closed + $10,
				skipped = skipped + $11,
				findings_failed = findings_failed + $12,
				findings_suppressed = findings_suppressed + $13,
				actions_recorded = actions_recorded + $14,
				actions_truncated = actions_truncated OR $15,
				errors = `+mergeErrorsHead+`$16`+mergeErrorsTail+`,
				updated_at = GREATEST(updated_at, $17)
			WHERE tenant_id = $1 AND id = $2`,
			d.TenantID.String(), id.String(), d.Reports, d.Received, d.AssetsCreated, d.AssetsUpdated,
			applied.created, applied.still, applied.reopened, applied.closed, d.Skipped, d.Failed, d.Suppressed,
			applied.rows, applied.truncated, string(errs), at)
		if err != nil {
			return fmt.Errorf("update receipt counts: %w", err)
		}
		if err := recordCoverageDecision(ctx, tx, d, id, at); err != nil {
			return err
		}
		return upsertIngestFact(ctx, tx, d, kind, tool, at, applied)
	})
	if err != nil {
		return shared.ID{}, err
	}
	return id, nil
}

// recordCoverageDecision stores a command's coverage decision on the
// receipt (replacing an earlier evaluation of the same command) and sets the
// receipt's coverage and untouched count from all its decisions.
func recordCoverageDecision(ctx context.Context, tx *sql.Tx, d *ingestreceipt.Delta, receiptID shared.ID, at time.Time) error {
	if d.Coverage != ingestreceipt.CoverageFull || d.Source.CommandID == nil {
		return nil
	}
	untouched := 0
	if d.Untouched != nil {
		untouched = max(*d.Untouched, 0)
	}
	_, err := tx.ExecContext(ctx, `
		INSERT INTO ingest_receipt_coverage (tenant_id, receipt_id, command_id, note, untouched, decided_at)
		VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (receipt_id, command_id) DO UPDATE
			SET note = EXCLUDED.note, untouched = EXCLUDED.untouched, decided_at = EXCLUDED.decided_at`,
		d.TenantID.String(), receiptID.String(), d.Source.CommandID.String(), d.CoverageNote, untouched, at)
	if err != nil {
		return fmt.Errorf("record coverage decision: %w", err)
	}
	_, err = tx.ExecContext(ctx, `
		UPDATE ingest_receipts r SET
			coverage = 'full',
			coverage_note = $3,
			findings_untouched = (SELECT COALESCE(SUM(c.untouched), 0) FROM ingest_receipt_coverage c
				WHERE c.tenant_id = r.tenant_id AND c.receipt_id = r.id)
		WHERE r.tenant_id = $1 AND r.id = $2`, d.TenantID.String(), receiptID.String(), d.CoverageNote)
	if err != nil {
		return fmt.Errorf("update receipt coverage: %w", err)
	}
	return nil
}

// resolveReceiptSource returns the receipt key of a source: a command in a
// scan run counts toward the run's receipt.
func resolveReceiptSource(ctx context.Context, tx rowQuerier, tenantID shared.ID, s ingestreceipt.Source) (ingestreceipt.SourceKind, string, error) {
	if s.CommandID == nil {
		if !s.Kind.IsValid() || s.Ref == "" || len(s.Ref) > 128 {
			return "", "", fmt.Errorf("%w: invalid receipt source", shared.ErrValidation)
		}
		return s.Kind, s.Ref, nil
	}
	var run sql.NullString
	err := tx.QueryRowContext(ctx, `
		SELECT st.scan_run_id::text
		FROM commands c
		LEFT JOIN scan_run_steps st ON st.id = c.scan_run_step_id
		WHERE c.tenant_id = $1 AND c.id = $2`, tenantID.String(), s.CommandID.String()).Scan(&run)
	if errors.Is(err, sql.ErrNoRows) {
		return "", "", fmt.Errorf("%w: command of the receipt", shared.ErrNotFound)
	}
	if err != nil {
		return "", "", fmt.Errorf("resolve receipt command: %w", err)
	}
	if run.Valid && run.String != "" {
		return ingestreceipt.SourceScanRun, run.String, nil
	}
	return ingestreceipt.SourceCommand, s.CommandID.String(), nil
}

// appliedActions are the counts the action rows of one delta added.
type appliedActions struct {
	created, reopened, closed, still int
	rows                             int
	truncated                        bool
}

// insertReceiptActions writes the delta's action rows, the first action of
// a finding in a receipt winning (ON CONFLICT DO NOTHING, in the order of
// ingestreceipt.AllActions), at most MaxActionsPerReceipt rows per receipt.
// A count is the rows a list added; past the cap the rest of the list is
// counted from its length and the receipt is marked truncated.
func insertReceiptActions(ctx context.Context, tx *sql.Tx, d *ingestreceipt.Delta, receiptID shared.ID, at time.Time, recorded int) (appliedActions, error) {
	var out appliedActions
	remaining := ingestreceipt.MaxActionsPerReceipt - recorded
	insert := func(action ingestreceipt.Action, candidates int, match string, arg any) (int, error) {
		if candidates == 0 {
			return 0, nil
		}
		limit := min(candidates, max(remaining, 0))
		n := 0
		if limit > 0 {
			err := tx.QueryRowContext(ctx, `
				WITH ins AS (
					INSERT INTO finding_ingest_actions (tenant_id, receipt_id, finding_id, action, created_at)
					SELECT f.tenant_id, $2, f.id, $3, $4
					FROM findings f
					WHERE f.tenant_id = $1 AND `+match+`
					LIMIT $6
					ON CONFLICT (receipt_id, finding_id) DO NOTHING
					RETURNING 1
				)
				SELECT count(*) FROM ins`,
				d.TenantID.String(), receiptID.String(), string(action), at, arg, limit).Scan(&n)
			if err != nil {
				return 0, fmt.Errorf("record %s actions: %w", action, err)
			}
		}
		remaining -= n
		out.rows += n
		if candidates > limit {
			out.truncated = true
			return n + candidates - limit, nil
		}
		return n, nil
	}
	var err error
	if out.created, err = insert(ingestreceipt.ActionCreated, len(uniqueIDs(d.Created)), "f.id = ANY($5::uuid[])", idArray(d.Created)); err != nil {
		return out, err
	}
	if out.reopened, err = insert(ingestreceipt.ActionReopened, len(uniqueIDs(d.Reopened)), "f.id = ANY($5::uuid[])", idArray(d.Reopened)); err != nil {
		return out, err
	}
	if out.closed, err = insert(ingestreceipt.ActionClosed, len(uniqueIDs(d.Closed)), "f.id = ANY($5::uuid[])", idArray(d.Closed)); err != nil {
		return out, err
	}
	fps := nonEmptyUnique(d.StillDetected)
	if out.still, err = insert(ingestreceipt.ActionStillDetected, len(fps), "f.fingerprint = ANY($5::text[])", pq.Array(fps)); err != nil {
		return out, err
	}
	return out, nil
}

// upsertIngestFact adds the delta to the day's dash_ingest_day row.
func upsertIngestFact(ctx context.Context, tx *sql.Tx, d *ingestreceipt.Delta, kind ingestreceipt.SourceKind, tool string, at time.Time, a appliedActions) error {
	if d.Reports == 0 && d.Received == 0 && a.created == 0 && a.still == 0 && a.reopened == 0 &&
		a.closed == 0 && d.Skipped == 0 && d.Failed == 0 && d.Suppressed == 0 {
		return nil
	}
	if tool == "" {
		tool = unknownTool
	}
	_, err := tx.ExecContext(ctx, `
		INSERT INTO dash_ingest_day (tenant_id, day, source_kind, tool, reports, received, created,
			still_detected, reopened, closed, skipped, failed, suppressed)
		VALUES ($1, ($2::timestamptz AT TIME ZONE 'UTC')::date, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
		ON CONFLICT (tenant_id, day, source_kind, tool) DO UPDATE SET
			reports = dash_ingest_day.reports + EXCLUDED.reports,
			received = dash_ingest_day.received + EXCLUDED.received,
			created = dash_ingest_day.created + EXCLUDED.created,
			still_detected = dash_ingest_day.still_detected + EXCLUDED.still_detected,
			reopened = dash_ingest_day.reopened + EXCLUDED.reopened,
			closed = dash_ingest_day.closed + EXCLUDED.closed,
			skipped = dash_ingest_day.skipped + EXCLUDED.skipped,
			failed = dash_ingest_day.failed + EXCLUDED.failed,
			suppressed = dash_ingest_day.suppressed + EXCLUDED.suppressed`,
		d.TenantID.String(), at, kind.FactKind(), tool, d.Reports, d.Received, a.created, a.still,
		a.reopened, a.closed, d.Skipped, d.Failed, d.Suppressed)
	if err != nil {
		return fmt.Errorf("upsert ingest fact: %w", err)
	}
	return nil
}

// mergeErrorsHead and mergeErrorsTail wrap a JSON array parameter appended to
// errors, keeping the first MaxErrors (100) entries; each query puts its
// parameter number between them (string constants only).
const mergeErrorsHead = `(SELECT COALESCE(jsonb_agg(e.value ORDER BY e.ord), '[]'::jsonb)
		FROM (SELECT value, ord FROM jsonb_array_elements(errors || `
const mergeErrorsTail = `::jsonb) WITH ORDINALITY AS x(value, ord)
			ORDER BY ord LIMIT 100) e)`

// CreateUpload records the start of an upload: its receipt exists before
// anything is written, so every finding and asset it writes names an
// existing producer.
func (r *IngestReceiptRepository) CreateUpload(ctx context.Context, u *ingestreceipt.Upload) error {
	if u == nil || u.TenantID.IsZero() || u.ID.IsZero() {
		return fmt.Errorf("%w: upload receipt needs a tenant and an id", shared.ErrValidation)
	}
	var actor any
	if u.ActorUserID != nil {
		actor = u.ActorUserID.String()
	}
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO ingest_receipts (id, tenant_id, actor_user_id, source_kind, source_ref, format, filename_sha256, status)
		VALUES ($1, $2, $3, 'upload', $6, NULLIF($4, ''), NULLIF($5, ''), 'processing')`,
		u.ID.String(), u.TenantID.String(), actor, u.Format, u.FilenameSHA256, u.ID.String())
	if err != nil {
		return fmt.Errorf("create upload receipt: %w", err)
	}
	return nil
}

// FinishUpload stores what an upload adds when it is done (the file-level
// counts; the findings counts were recorded by its ingests).
func (r *IngestReceiptRepository) FinishUpload(ctx context.Context, tenantID, id shared.ID, res *ingestreceipt.UploadResult) error {
	if res == nil {
		return fmt.Errorf("%w: upload result", shared.ErrValidation)
	}
	errs, err := json.Marshal(clipErrors(res.Errors))
	if err != nil {
		return fmt.Errorf("receipt errors: %w", err)
	}
	var untouched any
	if res.Untouched != nil {
		untouched = *res.Untouched
	}
	status := res.Status
	if status == "" {
		status = ingestreceipt.StatusCompleted
	}
	out, err := r.db.ExecContext(ctx, `
		UPDATE ingest_receipts SET
			status = $3,
			format = COALESCE(NULLIF($4, ''), format),
			skipped = skipped + $5,
			components = components + $6,
			statements = statements + $7,
			vex_stored = vex_stored + $8,
			vex_closed = vex_closed + $9,
			coverage = CASE WHEN $10 = 'full' THEN 'full' ELSE coverage END,
			coverage_note = COALESCE(NULLIF($11, ''), coverage_note),
			findings_untouched = CASE WHEN $12::integer IS NULL THEN findings_untouched ELSE $12::integer END,
			errors = `+mergeErrorsHead+`$13`+mergeErrorsTail+`,
			finished_at = now(),
			updated_at = now()
		WHERE tenant_id = $1 AND id = $2 AND source_kind = 'upload'`,
		tenantID.String(), id.String(), status, res.Format, res.Skipped, res.Components, res.Statements,
		res.VEXStored, res.VEXRequested, res.Coverage, res.CoverageNote, untouched, string(errs))
	if err != nil {
		return fmt.Errorf("finish upload receipt: %w", err)
	}
	if n, _ := out.RowsAffected(); n == 0 {
		return shared.ErrNotFound
	}
	return nil
}

// Get returns a receipt of the tenant; another tenant's is ErrNotFound.
func (r *IngestReceiptRepository) Get(ctx context.Context, tenantID, id shared.ID) (*ingestreceipt.Receipt, error) {
	row := r.db.QueryRowContext(ctx, `SELECT `+receiptColumns+` FROM ingest_receipts WHERE tenant_id = $1 AND id = $2`,
		tenantID.String(), id.String())
	rec, err := scanReceipt(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, shared.ErrNotFound
	}
	return rec, err
}

const receiptColumns = `id::text, tenant_id::text, source_kind, source_ref, actor_user_id::text,
	COALESCE(tool_name, ''), COALESCE(format, ''), COALESCE(filename_sha256, ''), coverage, COALESCE(coverage_note, ''), status,
	reports, findings_received, assets_created, assets_updated, components, statements, vex_stored, vex_closed,
	findings_created, findings_updated, findings_reopened, findings_closed, findings_untouched,
	skipped, findings_failed, findings_suppressed, actions_recorded, actions_truncated, errors,
	created_at, updated_at, finished_at`

type receiptScanner interface{ Scan(...any) error }

func scanReceipt(s receiptScanner) (*ingestreceipt.Receipt, error) {
	var (
		rec              ingestreceipt.Receipt
		id, tenant, kind string
		actor            sql.NullString
		untouched        sql.NullInt64
		errs             []byte
		finished         sql.NullTime
	)
	err := s.Scan(&id, &tenant, &kind, &rec.SourceRef, &actor, &rec.ToolName, &rec.Format, &rec.FilenameSHA256, &rec.Coverage,
		&rec.CoverageNote, &rec.Status, &rec.Reports, &rec.Received, &rec.AssetsCreated, &rec.AssetsUpdated,
		&rec.Components, &rec.Statements, &rec.VEXStored, &rec.VEXRequested,
		&rec.Counts.Created, &rec.Counts.StillDetected, &rec.Counts.Reopened, &rec.Counts.Closed, &untouched,
		&rec.Counts.Skipped, &rec.Counts.Failed, &rec.Counts.Suppressed, &rec.ActionsRecorded, &rec.ActionsTruncated,
		&errs, &rec.CreatedAt, &rec.UpdatedAt, &finished)
	if err != nil {
		return nil, err
	}
	rec.ID, _ = shared.IDFromString(id)
	rec.TenantID, _ = shared.IDFromString(tenant)
	rec.SourceKind = ingestreceipt.SourceKind(kind)
	if actor.Valid {
		if a, err := shared.IDFromString(actor.String); err == nil {
			rec.ActorUserID = &a
		}
	}
	if untouched.Valid {
		v := int(untouched.Int64)
		rec.Counts.Untouched = &v
	}
	if finished.Valid {
		t := finished.Time
		rec.FinishedAt = &t
	}
	if len(errs) > 0 {
		if err := json.Unmarshal(errs, &rec.Errors); err != nil {
			return nil, fmt.Errorf("receipt errors: %w", err)
		}
	}
	return &rec, nil
}

// PurgeActionsForPlatform deletes up to limit action rows older than before (all
// tenants: a platform retention job). Returns the rows deleted.
func (r *IngestReceiptRepository) PurgeActionsForPlatform(ctx context.Context, before time.Time, limit int) (int64, error) {
	res, err := r.db.ExecContext(ctx, `
		DELETE FROM finding_ingest_actions
		WHERE ctid IN (SELECT ctid FROM finding_ingest_actions WHERE created_at < $1 LIMIT $2)`, before, limit)
	if err != nil {
		return 0, fmt.Errorf("purge receipt actions: %w", err)
	}
	return res.RowsAffected()
}

// PurgeRunReceiptsForPlatform deletes up to limit receipts of runs (never uploads: an
// upload receipt is the producer record of what it wrote) last updated
// before before. Their action rows go with them.
func (r *IngestReceiptRepository) PurgeRunReceiptsForPlatform(ctx context.Context, before time.Time, limit int) (int64, error) {
	res, err := r.db.ExecContext(ctx, `
		DELETE FROM ingest_receipts
		WHERE id IN (SELECT id FROM ingest_receipts WHERE source_kind <> 'upload' AND updated_at < $1 LIMIT $2)`, before, limit)
	if err != nil {
		return 0, fmt.Errorf("purge run receipts: %w", err)
	}
	return res.RowsAffected()
}

// PurgeFactsForPlatform deletes up to limit dash_ingest_day rows of days before before.
func (r *IngestReceiptRepository) PurgeFactsForPlatform(ctx context.Context, before time.Time, limit int) (int64, error) {
	res, err := r.db.ExecContext(ctx, `
		DELETE FROM dash_ingest_day
		WHERE ctid IN (SELECT ctid FROM dash_ingest_day WHERE day < ($1::timestamptz AT TIME ZONE 'UTC')::date LIMIT $2)`, before, limit)
	if err != nil {
		return 0, fmt.Errorf("purge ingest facts: %w", err)
	}
	return res.RowsAffected()
}

func clipTool(t string) string {
	if len(t) > maxToolName {
		return t[:maxToolName]
	}
	return t
}

func clipErrors(errs []ingestreceipt.ErrorEntry) []ingestreceipt.ErrorEntry {
	if errs == nil {
		return []ingestreceipt.ErrorEntry{}
	}
	if len(errs) > ingestreceipt.MaxErrors {
		return errs[:ingestreceipt.MaxErrors]
	}
	return errs
}

func uniqueIDs(ids []shared.ID) []shared.ID {
	seen := make(map[shared.ID]struct{}, len(ids))
	out := make([]shared.ID, 0, len(ids))
	for _, id := range ids {
		if id.IsZero() {
			continue
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		out = append(out, id)
	}
	return out
}

func idArray(ids []shared.ID) any {
	u := uniqueIDs(ids)
	s := make([]string, len(u))
	for i, id := range u {
		s[i] = id.String()
	}
	return pq.Array(s)
}

// nonEmptyUnique is the distinct non-empty strings of in, in order.
func nonEmptyUnique(in []string) []string {
	out := make([]string, 0, len(in))
	for _, s := range uniqueStrings(in) {
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}
