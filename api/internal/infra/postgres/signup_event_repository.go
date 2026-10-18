package postgres

// Sign-up events and the burst thresholds setting
// (docs/architecture/signup-activity.md). signup_events is a platform table:
// only the platform console reads it, never a tenant route.

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/signupevent"
)

// SignupEventRepository stores sign-up events.
type SignupEventRepository struct {
	db *DB
}

// NewSignupEventRepository creates the repository.
func NewSignupEventRepository(db *DB) *SignupEventRepository {
	return &SignupEventRepository{db: db}
}

var (
	_ signupevent.Repository      = (*SignupEventRepository)(nil)
	_ signupevent.ThresholdsStore = (*SignupEventRepository)(nil)
)

// Insert stores one event.
func (r *SignupEventRepository) Insert(ctx context.Context, e signupevent.Record) error {
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO signup_events (kind, source, email_domain, ip_prefix, tenant_id, user_id, occurred_at)
		VALUES ($1, $2, NULLIF($3, ''), NULLIF($4, '')::cidr, $5, $6, $7)`,
		string(e.Kind), string(e.Source), e.EmailDomain, e.IPPrefix, nullID(e.TenantID), nullID(e.UserID), e.OccurredAt)
	if err != nil {
		return fmt.Errorf("insert sign-up event: %w", err)
	}
	return nil
}

// List returns a page of events, newest first, and the total.
func (r *SignupEventRepository) List(ctx context.Context, f signupevent.Filter) ([]signupevent.Record, int64, error) {
	var since any
	if !f.Since.IsZero() {
		since = f.Since
	}
	const where = `WHERE ($1 = '' OR kind = $1) AND ($2::timestamptz IS NULL OR occurred_at >= $2)`
	var total int64
	if err := r.db.QueryRowContext(ctx, `SELECT count(*) FROM signup_events `+where, string(f.Kind), since).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count sign-up events: %w", err)
	}
	rows, err := r.db.QueryContext(ctx, `
		SELECT id, kind, source, COALESCE(email_domain, ''), COALESCE(ip_prefix::text, ''),
		       tenant_id, user_id, occurred_at
		FROM signup_events `+where+`
		ORDER BY occurred_at DESC, id DESC
		LIMIT $3 OFFSET $4`, string(f.Kind), since, f.Limit, f.Offset)
	if err != nil {
		return nil, 0, fmt.Errorf("list sign-up events: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := make([]signupevent.Record, 0, f.Limit)
	for rows.Next() {
		var (
			e              signupevent.Record
			kind, source   string
			tenant, userID sql.NullString
		)
		if err := rows.Scan(&e.ID, &kind, &source, &e.EmailDomain, &e.IPPrefix, &tenant, &userID, &e.OccurredAt); err != nil {
			return nil, 0, fmt.Errorf("scan sign-up event: %w", err)
		}
		e.Kind, e.Source = signupevent.Kind(kind), signupevent.Source(source)
		if tenant.Valid {
			if id, err := shared.IDFromString(tenant.String); err == nil {
				e.TenantID = &id
			}
		}
		if userID.Valid {
			if id, err := shared.IDFromString(userID.String); err == nil {
				e.UserID = &id
			}
		}
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("list sign-up events: %w", err)
	}
	return out, total, nil
}

// Daily returns the events per kind per UTC day since since.
func (r *SignupEventRepository) Daily(ctx context.Context, since time.Time) ([]signupevent.DailyCount, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT date_trunc('day', occurred_at AT TIME ZONE 'UTC') AS day, kind, count(*)
		FROM signup_events
		WHERE occurred_at >= $1
		GROUP BY 1, 2
		ORDER BY 1, 2`, since)
	if err != nil {
		return nil, fmt.Errorf("daily sign-up events: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []signupevent.DailyCount
	for rows.Next() {
		var (
			c    signupevent.DailyCount
			kind string
		)
		if err := rows.Scan(&c.Day, &kind, &c.Count); err != nil {
			return nil, fmt.Errorf("scan daily sign-up events: %w", err)
		}
		c.Day = time.Date(c.Day.Year(), c.Day.Month(), c.Day.Day(), 0, 0, 0, 0, time.UTC)
		c.Kind = signupevent.Kind(kind)
		out = append(out, c)
	}
	return out, rows.Err()
}

// purgeBatch bounds one delete statement of the retention sweep.
const purgeBatch = 5000

// Purge deletes events older than before, in batches.
func (r *SignupEventRepository) Purge(ctx context.Context, before time.Time) (int64, error) {
	var total int64
	for {
		res, err := r.db.ExecContext(ctx, `
			DELETE FROM signup_events
			WHERE id IN (SELECT id FROM signup_events WHERE occurred_at < $1 ORDER BY occurred_at LIMIT $2)`,
			before, purgeBatch)
		if err != nil {
			return total, fmt.Errorf("purge sign-up events: %w", err)
		}
		n, err := res.RowsAffected()
		if err != nil {
			return total, fmt.Errorf("purge sign-up events: %w", err)
		}
		total += n
		if n < purgeBatch {
			return total, nil
		}
	}
}

// GetBurstThresholds returns the stored thresholds, or
// signupevent.ErrThresholdsNotFound.
func (r *SignupEventRepository) GetBurstThresholds(ctx context.Context) (signupevent.BurstThresholds, int, error) {
	var (
		raw     []byte
		version int
	)
	err := r.db.QueryRowContext(ctx, `SELECT value, version FROM platform_settings WHERE key = $1`,
		signupevent.ThresholdsSettingKey).Scan(&raw, &version)
	if errors.Is(err, sql.ErrNoRows) {
		return signupevent.BurstThresholds{}, 0, signupevent.ErrThresholdsNotFound
	}
	if err != nil {
		return signupevent.BurstThresholds{}, 0, fmt.Errorf("get sign-up burst thresholds: %w", err)
	}
	var t signupevent.BurstThresholds
	if err := json.Unmarshal(raw, &t); err != nil {
		return signupevent.BurstThresholds{}, 0, errors.New("decode sign-up burst thresholds: invalid value")
	}
	t = t.Normalize()
	if err := t.Validate(); err != nil {
		return signupevent.BurstThresholds{}, 0, errors.New("decode sign-up burst thresholds: invalid value")
	}
	return t, version, nil
}

// SetBurstThresholds stores the thresholds when the stored version is
// expectedVersion (0: nothing stored yet) and returns the new version.
func (r *SignupEventRepository) SetBurstThresholds(ctx context.Context, t signupevent.BurstThresholds, expectedVersion int, by string, at time.Time) (int, error) {
	raw, err := json.Marshal(t)
	if err != nil {
		return 0, err
	}
	var version int
	if expectedVersion == 0 {
		err = r.db.QueryRowContext(ctx, `
			INSERT INTO platform_settings (key, value, version, source, updated_by, updated_at)
			VALUES ($1, $2, 1, 'console', $3, $4)
			ON CONFLICT (key) DO NOTHING
			RETURNING version`, signupevent.ThresholdsSettingKey, raw, by, at).Scan(&version)
	} else {
		err = r.db.QueryRowContext(ctx, `
			UPDATE platform_settings
			   SET value = $2, version = version + 1, source = 'console', updated_by = $3, updated_at = $4
			 WHERE key = $1 AND version = $5
			RETURNING version`, signupevent.ThresholdsSettingKey, raw, by, at, expectedVersion).Scan(&version)
	}
	if errors.Is(err, sql.ErrNoRows) {
		return 0, signupevent.ErrVersionConflict
	}
	if err != nil {
		return 0, fmt.Errorf("set sign-up burst thresholds: %w", err)
	}
	return version, nil
}
