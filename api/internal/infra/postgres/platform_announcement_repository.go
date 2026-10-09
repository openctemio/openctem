package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// PlatformAnnouncement is one notice from the platform operator (RFC-022).
// Platform-level: it has no tenant and holds plain text only.
type PlatformAnnouncement struct {
	ID        string
	Message   string
	Severity  string
	StartsAt  time.Time
	EndsAt    *time.Time
	CreatedBy string
	CreatedAt time.Time
}

// PlatformAnnouncementRepository stores announcements.
type PlatformAnnouncementRepository struct{ db *DB }

// NewPlatformAnnouncementRepository creates the repository.
func NewPlatformAnnouncementRepository(db *DB) *PlatformAnnouncementRepository {
	return &PlatformAnnouncementRepository{db: db}
}

const platformAnnouncementCols = `id::text, message, severity, starts_at, ends_at, COALESCE(created_by::text, ''), created_at`

func scanAnnouncements(rows *sql.Rows) ([]PlatformAnnouncement, error) {
	defer func() { _ = rows.Close() }()
	var out []PlatformAnnouncement
	for rows.Next() {
		var (
			a    PlatformAnnouncement
			ends sql.NullTime
		)
		if err := rows.Scan(&a.ID, &a.Message, &a.Severity, &a.StartsAt, &ends, &a.CreatedBy, &a.CreatedAt); err != nil {
			return nil, err
		}
		if ends.Valid {
			t := ends.Time
			a.EndsAt = &t
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// List returns the newest announcements, past ones included (at most limit).
func (r *PlatformAnnouncementRepository) List(ctx context.Context, limit int) ([]PlatformAnnouncement, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT `+platformAnnouncementCols+`
		FROM platform_announcements ORDER BY created_at DESC, id LIMIT $1`, limit)
	if err != nil {
		return nil, fmt.Errorf("list announcements: %w", err)
	}
	return scanAnnouncements(rows)
}

// Active returns the announcements shown at now (started, not ended),
// maintenance first, then newest (at most limit).
func (r *PlatformAnnouncementRepository) Active(ctx context.Context, now time.Time, limit int) ([]PlatformAnnouncement, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT `+platformAnnouncementCols+`
		FROM platform_announcements
		WHERE starts_at <= $1 AND (ends_at IS NULL OR ends_at > $1)
		ORDER BY (severity = 'maintenance') DESC, (severity = 'warning') DESC, starts_at DESC, id
		LIMIT $2`, now, limit)
	if err != nil {
		return nil, fmt.Errorf("active announcements: %w", err)
	}
	return scanAnnouncements(rows)
}

// Create stores an announcement and returns its id.
func (r *PlatformAnnouncementRepository) Create(ctx context.Context, a PlatformAnnouncement) (string, error) {
	var createdBy any
	if a.CreatedBy != "" {
		createdBy = a.CreatedBy
	}
	var id string
	err := r.db.QueryRowContext(ctx, `
		INSERT INTO platform_announcements (message, severity, starts_at, ends_at, created_by)
		VALUES ($1, $2, $3, $4, $5) RETURNING id::text`,
		a.Message, a.Severity, a.StartsAt, a.EndsAt, createdBy).Scan(&id)
	if err != nil {
		return "", fmt.Errorf("create announcement: %w", err)
	}
	return id, nil
}

// End ends an announcement now (it stays in the history; one that had not
// started is canceled: its window closes before it opens). shared.ErrNotFound
// when there is no such announcement, shared.ErrConflict when it already
// ended.
func (r *PlatformAnnouncementRepository) End(ctx context.Context, id shared.ID, now time.Time) error {
	var ended bool
	err := r.db.QueryRowContext(ctx, `
		UPDATE platform_announcements
		SET starts_at = LEAST(starts_at, $2 - interval '1 second'), ends_at = $2, updated_at = $2
		WHERE id = $1 AND (ends_at IS NULL OR ends_at > $2)
		RETURNING true`, id.String(), now).Scan(&ended)
	if errors.Is(err, sql.ErrNoRows) {
		var exists bool
		if qerr := r.db.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM platform_announcements WHERE id = $1)`, id.String()).Scan(&exists); qerr != nil {
			return fmt.Errorf("end announcement: %w", qerr)
		}
		if !exists {
			return fmt.Errorf("%w: announcement", shared.ErrNotFound)
		}
		return fmt.Errorf("%w: the announcement already ended", shared.ErrConflict)
	}
	if err != nil {
		return fmt.Errorf("end announcement: %w", err)
	}
	return nil
}
