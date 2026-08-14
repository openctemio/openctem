package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/openctemio/api/pkg/domain/ctemid"
	"github.com/openctemio/api/pkg/domain/shared"
)

// CTEMIDRepository implements ctemid.Repository using PostgreSQL. The catalog is
// tenant-agnostic reference data, so no query is tenant-scoped.
type CTEMIDRepository struct {
	db *DB
}

// NewCTEMIDRepository creates a new CTEMIDRepository.
func NewCTEMIDRepository(db *DB) *CTEMIDRepository {
	return &CTEMIDRepository{db: db}
}

// UpsertBatch inserts or updates catalog entries keyed by ctem_id. Idempotent.
func (r *CTEMIDRepository) UpsertBatch(ctx context.Context, entries []*ctemid.CTEMID) error {
	if len(entries) == 0 {
		return nil
	}

	const cols = 9 // id, ctem_id, category, title, description, severity, source_url, published_at, raw
	valueStrings := make([]string, 0, len(entries))
	args := make([]any, 0, len(entries)*cols)
	for i, e := range entries {
		base := i * cols
		valueStrings = append(valueStrings, fmt.Sprintf(
			"($%d,$%d,$%d,$%d,$%d,$%d,$%d,$%d,$%d)",
			base+1, base+2, base+3, base+4, base+5, base+6, base+7, base+8, base+9,
		))
		var publishedAt any
		if e.PublishedAt() != nil {
			publishedAt = *e.PublishedAt()
		}
		raw := e.Raw()
		if len(raw) == 0 {
			raw = []byte("{}")
		}
		args = append(args,
			e.ID().String(),
			e.CTEMID(),
			e.Category().String(),
			e.Title(),
			e.Description(),
			e.Severity(),
			e.SourceURL(),
			publishedAt,
			raw,
		)
	}

	query := `
		INSERT INTO ctem_id_catalog
			(id, ctem_id, category, title, description, severity, source_url, published_at, raw)
		VALUES ` + strings.Join(valueStrings, ",") + `
		ON CONFLICT (ctem_id) DO UPDATE SET
			category     = EXCLUDED.category,
			title        = EXCLUDED.title,
			description  = EXCLUDED.description,
			severity     = EXCLUDED.severity,
			source_url   = EXCLUDED.source_url,
			published_at = EXCLUDED.published_at,
			raw          = EXCLUDED.raw,
			updated_at   = now()
	`

	if _, err := r.db.ExecContext(ctx, query, args...); err != nil {
		return fmt.Errorf("failed to upsert ctem-id catalog: %w", err)
	}
	return nil
}

// List returns catalog entries, optionally filtered by category.
func (r *CTEMIDRepository) List(ctx context.Context, category *string, limit, offset int) ([]*ctemid.CTEMID, int, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	if offset < 0 {
		offset = 0
	}

	args := []any{}
	where := ""
	if category != nil && *category != "" {
		args = append(args, *category)
		where = "WHERE category = $1"
	}

	countQuery := "SELECT COUNT(*) FROM ctem_id_catalog " + where
	var total int
	if err := r.db.QueryRowContext(ctx, countQuery, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("failed to count ctem-id catalog: %w", err)
	}

	args = append(args, limit, offset)
	listQuery := fmt.Sprintf(`
		SELECT id, ctem_id, category, title, description, severity, source_url, published_at, raw, created_at, updated_at
		FROM ctem_id_catalog
		%s
		ORDER BY published_at DESC NULLS LAST, ctem_id
		LIMIT $%d OFFSET $%d
	`, where, len(args)-1, len(args))

	rows, err := r.db.QueryContext(ctx, listQuery, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list ctem-id catalog: %w", err)
	}
	defer func() { _ = rows.Close() }()

	// Cap the capacity hint so an over-large limit can't drive an excessive
	// allocation (defense-in-depth; the handler bounds limit to MaxPerPage).
	capHint := limit
	if capHint < 0 || capHint > 1000 {
		capHint = 100
	}
	entries := make([]*ctemid.CTEMID, 0, capHint)
	for rows.Next() {
		entry, err := scanCTEMID(rows)
		if err != nil {
			return nil, 0, err
		}
		entries = append(entries, entry)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("failed to iterate ctem-id catalog: %w", err)
	}
	return entries, total, nil
}

// GetByCTEMID returns a single catalog entry by its external id.
func (r *CTEMIDRepository) GetByCTEMID(ctx context.Context, id string) (*ctemid.CTEMID, error) {
	query := `
		SELECT id, ctem_id, category, title, description, severity, source_url, published_at, raw, created_at, updated_at
		FROM ctem_id_catalog
		WHERE ctem_id = $1
	`
	entry, err := scanCTEMID(r.db.QueryRowContext(ctx, query, id))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ctemid.ErrCTEMIDNotFound
		}
		return nil, err
	}
	return entry, nil
}

// Count returns the total number of catalog entries.
func (r *CTEMIDRepository) Count(ctx context.Context) (int, error) {
	var n int
	if err := r.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM ctem_id_catalog").Scan(&n); err != nil {
		return 0, fmt.Errorf("failed to count ctem-id catalog: %w", err)
	}
	return n, nil
}

// rowScanner is satisfied by both *sql.Row and *sql.Rows.
type ctemidRowScanner interface {
	Scan(dest ...any) error
}

func scanCTEMID(s ctemidRowScanner) (*ctemid.CTEMID, error) {
	var (
		idStr       string
		ctemIDStr   string
		category    string
		title       string
		description string
		severity    string
		sourceURL   string
		publishedAt sql.NullTime
		raw         []byte
		createdAt   time.Time
		updatedAt   time.Time
	)
	if err := s.Scan(&idStr, &ctemIDStr, &category, &title, &description, &severity, &sourceURL, &publishedAt, &raw, &createdAt, &updatedAt); err != nil {
		return nil, err
	}

	id, err := shared.IDFromString(idStr)
	if err != nil {
		return nil, fmt.Errorf("invalid ctem-id catalog id: %w", err)
	}
	var pub *time.Time
	if publishedAt.Valid {
		t := publishedAt.Time
		pub = &t
	}
	return ctemid.Reconstitute(
		id,
		ctemIDStr,
		ctemid.Category(category),
		title,
		description,
		severity,
		sourceURL,
		pub,
		raw,
		createdAt,
		updatedAt,
	), nil
}
