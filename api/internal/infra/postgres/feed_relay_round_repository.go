package postgres

// Feed relay rounds (docs/rfcs/RFC-142-feed-relay.md). Platform-wide feed
// bookkeeping: the table has no tenant column and holds no tenant data. A
// round is read and closed only together with the sensor it was issued to.

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/feedrelay"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// FeedRelayRoundRepository implements feedrelay.Repository.
type FeedRelayRoundRepository struct{ db *DB }

var _ feedrelay.Repository = (*FeedRelayRoundRepository)(nil)

// NewFeedRelayRoundRepository creates the repository.
func NewFeedRelayRoundRepository(db *DB) *FeedRelayRoundRepository {
	return &FeedRelayRoundRepository{db: db}
}

const feedRelayRoundColumns = `id, sensor_id, feed, phase, status, origins, files, report, error_code, created_at, expires_at, delivered_at`

// Create inserts a round.
func (r *FeedRelayRoundRepository) Create(ctx context.Context, rd *feedrelay.Round) error {
	origins, err := json.Marshal(nonNilStrings(rd.Origins))
	if err != nil {
		return err
	}
	files := rd.Files
	if files == nil {
		files = []feedrelay.File{}
	}
	fb, err := json.Marshal(files)
	if err != nil {
		return err
	}
	var report []byte
	if rd.Report != nil {
		if report, err = json.Marshal(rd.Report); err != nil {
			return err
		}
	}
	_, err = r.db.ExecContext(ctx, `
		INSERT INTO feed_relay_rounds (id, sensor_id, feed, phase, status, origins, files, report, error_code, created_at, expires_at, delivered_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`,
		rd.ID.String(), rd.SensorID.String(), rd.Feed, rd.Phase, rd.Status, origins, fb, nullBytes(report),
		rd.ErrorCode, rd.CreatedAt, rd.ExpiresAt, rd.DeliveredAt)
	if err != nil {
		return fmt.Errorf("create feed relay round: %w", err)
	}
	return nil
}

// GetForSensor returns the round when it was issued to that sensor.
func (r *FeedRelayRoundRepository) GetForSensor(ctx context.Context, id, sensorID shared.ID) (*feedrelay.Round, error) {
	row := r.db.QueryRowContext(ctx, `SELECT `+feedRelayRoundColumns+` FROM feed_relay_rounds WHERE id = $1 AND sensor_id = $2`,
		id.String(), sensorID.String())
	rd, err := scanFeedRelayRound(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, feedrelay.ErrNotFound
	}
	return rd, err
}

// NextOpen returns the sensor's oldest open, unexpired round, or nil.
func (r *FeedRelayRoundRepository) NextOpen(ctx context.Context, sensorID shared.ID, now time.Time) (*feedrelay.Round, error) {
	row := r.db.QueryRowContext(ctx, `SELECT `+feedRelayRoundColumns+` FROM feed_relay_rounds
		WHERE sensor_id = $1 AND status = 'open' AND expires_at > $2 ORDER BY created_at LIMIT 1`, sensorID.String(), now)
	return optionalRound(scanFeedRelayRound(row))
}

// Latest returns the newest round of a feed, or nil.
func (r *FeedRelayRoundRepository) Latest(ctx context.Context, feed string) (*feedrelay.Round, error) {
	row := r.db.QueryRowContext(ctx, `SELECT `+feedRelayRoundColumns+` FROM feed_relay_rounds
		WHERE feed = $1 ORDER BY created_at DESC LIMIT 1`, feed)
	return optionalRound(scanFeedRelayRound(row))
}

// LatestOfPhase returns the newest round of a feed in a phase, or nil.
func (r *FeedRelayRoundRepository) LatestOfPhase(ctx context.Context, feed, phase string) (*feedrelay.Round, error) {
	row := r.db.QueryRowContext(ctx, `SELECT `+feedRelayRoundColumns+` FROM feed_relay_rounds
		WHERE feed = $1 AND phase = $2 ORDER BY created_at DESC LIMIT 1`, feed, phase)
	return optionalRound(scanFeedRelayRound(row))
}

// Finish closes an open round of that sensor.
func (r *FeedRelayRoundRepository) Finish(ctx context.Context, id, sensorID shared.ID, status string, rep *feedrelay.Report, at time.Time) (bool, error) {
	var report []byte
	if rep != nil {
		b, err := json.Marshal(rep)
		if err != nil {
			return false, err
		}
		report = b
	}
	res, err := r.db.ExecContext(ctx, `UPDATE feed_relay_rounds SET status = $3, report = $4, delivered_at = $5
		WHERE id = $1 AND sensor_id = $2 AND status = 'open'`, id.String(), sensorID.String(), status, nullBytes(report), at)
	if err != nil {
		return false, fmt.Errorf("finish feed relay round: %w", err)
	}
	n, err := res.RowsAffected()
	return n == 1, err
}

// ExpireOpen marks open rounds past their expiry expired.
func (r *FeedRelayRoundRepository) ExpireOpen(ctx context.Context, now time.Time) (int, error) {
	res, err := r.db.ExecContext(ctx, `UPDATE feed_relay_rounds SET status = 'expired' WHERE status = 'open' AND expires_at <= $1`, now)
	if err != nil {
		return 0, fmt.Errorf("expire feed relay rounds: %w", err)
	}
	n, err := res.RowsAffected()
	return int(n), err
}

// DeleteBefore removes rounds created before t.
func (r *FeedRelayRoundRepository) DeleteBefore(ctx context.Context, t time.Time) (int, error) {
	res, err := r.db.ExecContext(ctx, `DELETE FROM feed_relay_rounds WHERE created_at < $1`, t)
	if err != nil {
		return 0, fmt.Errorf("delete feed relay rounds: %w", err)
	}
	n, err := res.RowsAffected()
	return int(n), err
}

func optionalRound(rd *feedrelay.Round, err error) (*feedrelay.Round, error) {
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return rd, err
}

func scanFeedRelayRound(row interface{ Scan(dest ...any) error }) (*feedrelay.Round, error) {
	var (
		rd                     feedrelay.Round
		id, sensorID           string
		origins, files, report []byte
		delivered              sql.NullTime
	)
	if err := row.Scan(&id, &sensorID, &rd.Feed, &rd.Phase, &rd.Status, &origins, &files, &report, &rd.ErrorCode,
		&rd.CreatedAt, &rd.ExpiresAt, &delivered); err != nil {
		return nil, err
	}
	var err error
	if rd.ID, err = shared.IDFromString(id); err != nil {
		return nil, err
	}
	if rd.SensorID, err = shared.IDFromString(sensorID); err != nil {
		return nil, err
	}
	if err := json.Unmarshal(origins, &rd.Origins); err != nil {
		return nil, err
	}
	if err := json.Unmarshal(files, &rd.Files); err != nil {
		return nil, err
	}
	if len(report) > 0 {
		rd.Report = &feedrelay.Report{}
		if err := json.Unmarshal(report, rd.Report); err != nil {
			return nil, err
		}
	}
	if delivered.Valid {
		t := delivered.Time
		rd.DeliveredAt = &t
	}
	return &rd, nil
}
