package postgres

// Scan freeze windows (docs/architecture/scan-zones.md, "Freeze windows";
// migration 001115). Whether a window is active is one SQL expression,
// freezeActiveSQL, used both by the repository (the trigger, the scheduler
// and the API) and by the command claim predicate (freezeHoldPredicate), so
// what the API reports and what dispatch enforces cannot drift apart.

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/pkg/domain/scanfreeze"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/stage"
)

// ScanFreezeWindowRepository implements scanfreeze.Repository. Every
// statement is tenant-scoped; a zone window's zone is the same tenant's by
// the composite foreign key.
type ScanFreezeWindowRepository struct {
	db *DB
}

// NewScanFreezeWindowRepository creates a ScanFreezeWindowRepository.
func NewScanFreezeWindowRepository(db *DB) *ScanFreezeWindowRepository {
	return &ScanFreezeWindowRepository{db: db}
}

var _ scanfreeze.Repository = (*ScanFreezeWindowRepository)(nil)

// freezeLocalSQL is the wall-clock time of the window aliased w at the
// instant at, in the window's time zone (a timestamp without time zone).
func freezeLocalSQL(w, at string) string {
	return "(" + at + " AT TIME ZONE " + w + ".timezone)"
}

// freezeActiveSQL is true when the enabled window aliased w is active at the
// instant at (a timestamptz expression).
//
// A weekly window compares local wall-clock time: on the day the clocks go
// forward a window over the skipped hour is shorter, on the day they go back
// a window over the repeated hour lasts both passes. A window whose end
// minute is not after its start minute runs past midnight: it is active from
// the start on a listed day, and until the end on the day after a listed day.
func freezeActiveSQL(w, at string) string {
	lt := freezeLocalSQL(w, at)
	lmin := "(EXTRACT(HOUR FROM " + lt + ")::int * 60 + EXTRACT(MINUTE FROM " + lt + ")::int)"
	ldow := "EXTRACT(ISODOW FROM " + lt + ")::int"
	pdow := "EXTRACT(ISODOW FROM " + lt + " - INTERVAL '1 day')::int"
	return `(` + w + `.enabled AND (
		(` + w + `.recurrence = 'once' AND ` + at + ` >= ` + w + `.starts_at AND ` + at + ` < ` + w + `.ends_at)
		OR (` + w + `.recurrence = 'weekly' AND (
			(` + w + `.start_minute < ` + w + `.end_minute
				AND ` + ldow + ` = ANY(` + w + `.days)
				AND ` + lmin + ` >= ` + w + `.start_minute AND ` + lmin + ` < ` + w + `.end_minute)
			OR (` + w + `.start_minute >= ` + w + `.end_minute AND (
				(` + ldow + ` = ANY(` + w + `.days) AND ` + lmin + ` >= ` + w + `.start_minute)
				OR (` + pdow + ` = ANY(` + w + `.days) AND ` + lmin + ` < ` + w + `.end_minute)))))))`
}

// freezeUntilSQL is the end of the occurrence of the window aliased w that
// is active at at (meaningful only where freezeActiveSQL holds). A weekly end
// that falls in the hour skipped when clocks go forward is read as standard
// time, so it can be up to an hour later than the wall clock reaches it.
func freezeUntilSQL(w, at string) string {
	lt := freezeLocalSQL(w, at)
	lmin := "(EXTRACT(HOUR FROM " + lt + ")::int * 60 + EXTRACT(MINUTE FROM " + lt + ")::int)"
	end := "make_interval(mins => " + w + ".end_minute)"
	return `(CASE
		WHEN ` + w + `.recurrence = 'once' THEN ` + w + `.ends_at
		WHEN ` + w + `.start_minute < ` + w + `.end_minute OR ` + lmin + ` < ` + w + `.end_minute
			THEN ((` + lt + `)::date + ` + end + `) AT TIME ZONE ` + w + `.timezone
		ELSE ((` + lt + `)::date + 1 + ` + end + `) AT TIME ZONE ` + w + `.timezone
	END)`
}

// freezeActiveWorkSQL is true for a command that is active scan work: a
// scan whose tool is not a passive (T0) tool of the stage catalog (a scan
// naming no tool counts as active), a validation job, or a connector scan.
// Everything else (collection, connector syncs, health checks, content
// refreshes) is not held by a freeze window.
var freezeActiveWorkSQL = func() string {
	quoted := make([]string, 0)
	for _, t := range stage.PassiveTools() {
		quoted = append(quoted, "'"+strings.ReplaceAll(t, "'", "''")+"'")
	}
	passive := "ARRAY[" + strings.Join(quoted, ", ") + "]::text[]"
	return `(commands.type IN ('validate', 'connector_scan')
		OR (commands.type = 'scan' AND (` + commandToolSQL + ` IS NULL
			OR NOT (lower(` + commandToolSQL + `) = ANY(` + passive + `)))))`
}()

// freezeHoldPredicate is the claim-time freeze gate: a command that is
// active scan work is not offered or claimable while an enabled window of
// its tenant, tenant-wide or of the command's zone, is active, unless the
// server stamped it with an audited override. It is part of the poll, the
// claim by id, the batch claim and the heartbeat doorbell.
var freezeHoldPredicate = `NOT (
		NOT commands.freeze_override
		AND ` + freezeActiveWorkSQL + `
		AND EXISTS (
			SELECT 1 FROM scan_freeze_windows fw
			WHERE fw.tenant_id = commands.tenant_id
			  AND (fw.scan_zone_id IS NULL OR fw.scan_zone_id = commands.scan_zone_id)
			  AND ` + freezeActiveSQL("fw", "NOW()") + `
		)
	)`

const scanFreezeColumns = `fw.id, fw.tenant_id, fw.scan_zone_id, fw.name, fw.description, fw.timezone,
	fw.recurrence, fw.starts_at, fw.ends_at, fw.days, fw.start_minute, fw.end_minute,
	fw.enabled, fw.created_by, fw.created_at, fw.updated_at`

// scanFreezeSelect reads windows with their end when active at $at.
func scanFreezeSelect(at string) string {
	return `SELECT ` + scanFreezeColumns + `,
		CASE WHEN ` + freezeActiveSQL("fw", at) + ` THEN ` + freezeUntilSQL("fw", at) + ` END
	FROM scan_freeze_windows fw`
}

// checkTimezone refuses a time zone the database does not know: the claim
// predicate evaluates it on every poll of the tenant.
func (r *ScanFreezeWindowRepository) checkTimezone(ctx context.Context, tz string) error {
	var ok bool
	if err := r.db.QueryRowContext(ctx,
		`SELECT EXISTS (SELECT 1 FROM pg_timezone_names WHERE name = $1)`, tz).Scan(&ok); err != nil {
		return fmt.Errorf("check time zone: %w", err)
	}
	if !ok {
		return shared.NewDomainError("INVALID_FREEZE_WINDOW", fmt.Sprintf("unknown timezone %q", tz), shared.ErrValidation)
	}
	return nil
}

func freezeDays(w *scanfreeze.Window) any {
	if w.Recurrence != scanfreeze.RecurrenceWeekly {
		return nil
	}
	days := make([]int64, len(w.Days))
	for i, d := range w.Days {
		days[i] = int64(d)
	}
	return pq.Array(days)
}

func freezeMinute(w *scanfreeze.Window, m int) sql.NullInt64 {
	if w.Recurrence != scanfreeze.RecurrenceWeekly {
		return sql.NullInt64{}
	}
	return sql.NullInt64{Int64: int64(m), Valid: true}
}

// Create inserts a window.
func (r *ScanFreezeWindowRepository) Create(ctx context.Context, w *scanfreeze.Window) error {
	if err := r.checkTimezone(ctx, w.Timezone); err != nil {
		return err
	}
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO scan_freeze_windows (id, tenant_id, scan_zone_id, name, description, timezone,
			recurrence, starts_at, ends_at, days, start_minute, end_minute, enabled, created_by, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)`,
		w.ID.String(), w.TenantID.String(), nullIDString(w.ScanZoneID), w.Name, w.Description, w.Timezone,
		string(w.Recurrence), nullTime(w.StartsAt), nullTime(w.EndsAt), freezeDays(w),
		freezeMinute(w, w.StartMinute), freezeMinute(w, w.EndMinute), w.Enabled,
		nullIDString(w.CreatedBy), w.CreatedAt, w.UpdatedAt)
	if err != nil {
		if isForeignKeyViolation(err) {
			// The zone is not the tenant's (or was deleted meanwhile).
			return scanfreeze.ErrZoneNotFound
		}
		return fmt.Errorf("create freeze window: %w", err)
	}
	return nil
}

// Update writes a window's settings; the zone never changes.
func (r *ScanFreezeWindowRepository) Update(ctx context.Context, w *scanfreeze.Window) error {
	if err := r.checkTimezone(ctx, w.Timezone); err != nil {
		return err
	}
	res, err := r.db.ExecContext(ctx, `
		UPDATE scan_freeze_windows
		SET name = $3, description = $4, timezone = $5, recurrence = $6, starts_at = $7, ends_at = $8,
		    days = $9, start_minute = $10, end_minute = $11, enabled = $12, updated_at = $13
		WHERE tenant_id = $1 AND id = $2`,
		w.TenantID.String(), w.ID.String(), w.Name, w.Description, w.Timezone, string(w.Recurrence),
		nullTime(w.StartsAt), nullTime(w.EndsAt), freezeDays(w),
		freezeMinute(w, w.StartMinute), freezeMinute(w, w.EndMinute), w.Enabled, w.UpdatedAt)
	if err != nil {
		return fmt.Errorf("update freeze window: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return scanfreeze.ErrNotFound
	}
	return nil
}

// Delete removes a window of the tenant.
func (r *ScanFreezeWindowRepository) Delete(ctx context.Context, tenantID, id shared.ID) error {
	res, err := r.db.ExecContext(ctx, `DELETE FROM scan_freeze_windows WHERE tenant_id = $1 AND id = $2`,
		tenantID.String(), id.String())
	if err != nil {
		return fmt.Errorf("delete freeze window: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return scanfreeze.ErrNotFound
	}
	return nil
}

// Count counts the tenant's windows.
func (r *ScanFreezeWindowRepository) Count(ctx context.Context, tenantID shared.ID) (int, error) {
	var n int
	if err := r.db.QueryRowContext(ctx, `SELECT count(*) FROM scan_freeze_windows WHERE tenant_id = $1`,
		tenantID.String()).Scan(&n); err != nil {
		return 0, fmt.Errorf("count freeze windows: %w", err)
	}
	return n, nil
}

// GetByID returns a window of the tenant.
func (r *ScanFreezeWindowRepository) GetByID(ctx context.Context, tenantID, id shared.ID) (*scanfreeze.Window, error) {
	row := r.db.QueryRowContext(ctx, scanFreezeSelect("NOW()")+` WHERE fw.tenant_id = $1 AND fw.id = $2`,
		tenantID.String(), id.String())
	w, err := scanFreezeWindow(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, scanfreeze.ErrNotFound
	}
	return w, err
}

// List returns the tenant's windows, ordered by name.
func (r *ScanFreezeWindowRepository) List(ctx context.Context, tenantID shared.ID, f scanfreeze.Filter) ([]*scanfreeze.Window, error) {
	q := scanFreezeSelect("NOW()") + ` WHERE fw.tenant_id = $1`
	args := []any{tenantID.String()}
	switch {
	case f.ScanZoneID != nil:
		q += ` AND fw.scan_zone_id = $2`
		args = append(args, f.ScanZoneID.String())
	case f.TenantWide:
		q += ` AND fw.scan_zone_id IS NULL`
	}
	q += ` ORDER BY lower(fw.name), fw.id LIMIT ` + fmt.Sprint(scanfreeze.MaxWindowsPerTenant*2)
	return r.query(ctx, q, args...)
}

// ActiveAt returns the windows active at at that apply to zoneIDs or to the
// whole tenant.
func (r *ScanFreezeWindowRepository) ActiveAt(ctx context.Context, tenantID shared.ID, zoneIDs []shared.ID, at time.Time) ([]*scanfreeze.Window, error) {
	ids := make([]string, len(zoneIDs))
	for i, id := range zoneIDs {
		ids[i] = id.String()
	}
	q := scanFreezeSelect("$3::timestamptz") + `
		WHERE fw.tenant_id = $1
		  AND (fw.scan_zone_id IS NULL OR fw.scan_zone_id = ANY($2::uuid[]))
		  AND ` + freezeActiveSQL("fw", "$3::timestamptz") + `
		ORDER BY fw.id`
	return r.query(ctx, q, tenantID.String(), pq.Array(ids), at.UTC())
}

func (r *ScanFreezeWindowRepository) query(ctx context.Context, q string, args ...any) ([]*scanfreeze.Window, error) {
	rows, err := r.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("list freeze windows: %w", err)
	}
	defer rows.Close()
	var out []*scanfreeze.Window
	for rows.Next() {
		w, err := scanFreezeWindow(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, w)
	}
	return out, rows.Err()
}

type freezeRowScanner interface {
	Scan(dest ...any) error
}

func scanFreezeWindow(row freezeRowScanner) (*scanfreeze.Window, error) {
	var (
		w                 scanfreeze.Window
		id, tenantID      string
		zoneID, createdBy sql.NullString
		recurrence        string
		startsAt, endsAt  sql.NullTime
		days              pq.Int64Array
		startMin, endMin  sql.NullInt64
		activeUntil       sql.NullTime
	)
	if err := row.Scan(&id, &tenantID, &zoneID, &w.Name, &w.Description, &w.Timezone,
		&recurrence, &startsAt, &endsAt, &days, &startMin, &endMin,
		&w.Enabled, &createdBy, &w.CreatedAt, &w.UpdatedAt, &activeUntil); err != nil {
		return nil, err
	}
	var err error
	if w.ID, err = shared.IDFromString(id); err != nil {
		return nil, fmt.Errorf("freeze window id: %w", err)
	}
	if w.TenantID, err = shared.IDFromString(tenantID); err != nil {
		return nil, fmt.Errorf("freeze window tenant id: %w", err)
	}
	if zoneID.Valid {
		if zid, err := shared.IDFromString(zoneID.String); err == nil {
			w.ScanZoneID = &zid
		}
	}
	if createdBy.Valid {
		if uid, err := shared.IDFromString(createdBy.String); err == nil {
			w.CreatedBy = &uid
		}
	}
	w.Recurrence = scanfreeze.Recurrence(recurrence)
	if startsAt.Valid {
		t := startsAt.Time.UTC()
		w.StartsAt = &t
	}
	if endsAt.Valid {
		t := endsAt.Time.UTC()
		w.EndsAt = &t
	}
	for _, d := range days {
		w.Days = append(w.Days, int(d))
	}
	w.StartMinute, w.EndMinute = int(startMin.Int64), int(endMin.Int64)
	if activeUntil.Valid {
		t := activeUntil.Time.UTC()
		w.ActiveUntil = &t
	}
	return &w, nil
}
