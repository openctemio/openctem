package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/openctemio/api/pkg/domain/ioc"
	"github.com/openctemio/api/pkg/domain/shared"
)

// IOCRepository implements ioc.Repository using PostgreSQL.
//
// Tables: iocs, ioc_matches (migration 000156).
type IOCRepository struct {
	db *DB
}

// NewIOCRepository wires the repo.
func NewIOCRepository(db *DB) *IOCRepository {
	return &IOCRepository{db: db}
}

const iocSelectColumns = `
	id, tenant_id, ioc_type, value, value_normalized,
	source_finding_id, source, active, confidence,
	first_seen_at, last_seen_at, created_at, updated_at
`

// Create inserts a new indicator. On conflict (tenant, type,
// normalized) it refreshes last_seen_at so a re-import bumps freshness
// without producing duplicates.
func (r *IOCRepository) Create(ctx context.Context, ind *ioc.Indicator) error {
	var sourceFindingID any
	if ind.SourceFindingID != nil {
		sourceFindingID = ind.SourceFindingID.String()
	}
	var sourceStr any
	if ind.Source != "" {
		sourceStr = string(ind.Source)
	}
	const q = `
		INSERT INTO iocs (
			id, tenant_id, ioc_type, value, value_normalized,
			source_finding_id, source, active, confidence,
			first_seen_at, last_seen_at, created_at, updated_at
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
		ON CONFLICT (tenant_id, ioc_type, value_normalized)
		DO UPDATE SET
			last_seen_at = EXCLUDED.last_seen_at,
			active       = TRUE,
			updated_at   = EXCLUDED.updated_at
	`
	_, err := r.db.ExecContext(ctx, q,
		ind.ID.String(),
		ind.TenantID.String(),
		string(ind.Type),
		ind.Value,
		ind.Normalized,
		sourceFindingID,
		sourceStr,
		ind.Active,
		ind.Confidence,
		ind.FirstSeenAt,
		ind.LastSeenAt,
		ind.CreatedAt,
		ind.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("insert ioc: %w", err)
	}
	return nil
}

// GetByID loads one indicator, tenant-scoped.
func (r *IOCRepository) GetByID(ctx context.Context, tenantID, id shared.ID) (*ioc.Indicator, error) {
	q := `SELECT ` + iocSelectColumns + ` FROM iocs WHERE tenant_id = $1 AND id = $2`
	row := r.db.QueryRowContext(ctx, q, tenantID.String(), id.String())
	return scanIndicator(row)
}

// FindActiveByValues bulk-matches a set of (type, normalized) pairs.
// One query, index-backed — the correlator's hot path.
func (r *IOCRepository) FindActiveByValues(ctx context.Context, tenantID shared.ID, candidates []ioc.Candidate) ([]*ioc.Indicator, error) {
	if len(candidates) == 0 {
		return nil, nil
	}

	// Parameters: $1 = tenant_id, then pairs of (type, normalized)
	// for each candidate; built via a VALUES list the planner can
	// hash-join against the unique index on
	// (tenant_id, ioc_type, value_normalized).
	args := make([]any, 0, 1+2*len(candidates))
	args = append(args, tenantID.String())

	placeholders := make([]string, 0, len(candidates))
	for i, c := range candidates {
		placeholders = append(placeholders, fmt.Sprintf("($%d,$%d)", 2+2*i, 3+2*i))
		args = append(args, string(c.Type), c.Normalized)
	}
	q := fmt.Sprintf(`
		SELECT %s FROM iocs
		WHERE tenant_id = $1
		  AND active = TRUE
		  AND (ioc_type, value_normalized) IN (VALUES %s)
	`, iocSelectColumns, strings.Join(placeholders, ","))

	rows, err := r.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("ioc lookup: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var out []*ioc.Indicator
	for rows.Next() {
		ind, err := scanIndicator(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, ind)
	}
	return out, rows.Err()
}

// RecordMatch inserts an ioc_matches row. Idempotent when
// telemetry_event_id is present — the unique partial index swallows
// retries.
func (r *IOCRepository) RecordMatch(ctx context.Context, m ioc.Match) error {
	var eventID any
	if m.TelemetryEventID != nil {
		eventID = m.TelemetryEventID.String()
	}
	var findingID any
	if m.FindingID != nil {
		findingID = m.FindingID.String()
	}
	const q = `
		INSERT INTO ioc_matches (id, tenant_id, ioc_id, telemetry_event_id, finding_id, reopened, matched_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7)
		ON CONFLICT DO NOTHING
	`
	_, err := r.db.ExecContext(ctx, q,
		m.ID.String(),
		m.TenantID.String(),
		m.IOCID.String(),
		eventID,
		findingID,
		m.Reopened,
		m.MatchedAt,
	)
	if err != nil {
		return fmt.Errorf("record ioc match: %w", err)
	}
	return nil
}

// ListByTenant paginates active + inactive indicators for the UI.
func (r *IOCRepository) ListByTenant(ctx context.Context, tenantID shared.ID, limit, offset int) ([]*ioc.Indicator, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	if offset < 0 {
		offset = 0
	}
	q := `SELECT ` + iocSelectColumns + `
		FROM iocs WHERE tenant_id = $1
		ORDER BY last_seen_at DESC LIMIT $2 OFFSET $3`
	rows, err := r.db.QueryContext(ctx, q, tenantID.String(), limit, offset)
	if err != nil {
		return nil, fmt.Errorf("list iocs: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var out []*ioc.Indicator
	for rows.Next() {
		ind, err := scanIndicator(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, ind)
	}
	return out, rows.Err()
}

// Deactivate flips active=false. Soft-delete preserves history.
func (r *IOCRepository) Deactivate(ctx context.Context, tenantID, id shared.ID) error {
	const q = `UPDATE iocs SET active = FALSE, updated_at = NOW() WHERE tenant_id = $1 AND id = $2`
	res, err := r.db.ExecContext(ctx, q, tenantID.String(), id.String())
	if err != nil {
		return fmt.Errorf("deactivate ioc: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return shared.ErrNotFound
	}
	return nil
}

// rowScanner is the shared signature of *sql.Row and *sql.Rows.
type iocRowScanner interface {
	Scan(dest ...any) error
}

func scanIndicator(sc iocRowScanner) (*ioc.Indicator, error) {
	var (
		ind             ioc.Indicator
		id              string
		tenantID        string
		iocType         string
		sourceFindingID sql.NullString
		source          sql.NullString
	)
	err := sc.Scan(
		&id,
		&tenantID,
		&iocType,
		&ind.Value,
		&ind.Normalized,
		&sourceFindingID,
		&source,
		&ind.Active,
		&ind.Confidence,
		&ind.FirstSeenAt,
		&ind.LastSeenAt,
		&ind.CreatedAt,
		&ind.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, shared.ErrNotFound
		}
		return nil, fmt.Errorf("scan ioc: %w", err)
	}
	ind.ID, err = shared.IDFromString(id)
	if err != nil {
		return nil, fmt.Errorf("parse id: %w", err)
	}
	ind.TenantID, err = shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("parse tenant_id: %w", err)
	}
	ind.Type = ioc.Type(iocType)
	if sourceFindingID.Valid {
		fid, err := shared.IDFromString(sourceFindingID.String)
		if err != nil {
			return nil, fmt.Errorf("parse source_finding_id: %w", err)
		}
		ind.SourceFindingID = &fid
	}
	if source.Valid {
		ind.Source = ioc.Source(source.String)
	}
	return &ind, nil
}
