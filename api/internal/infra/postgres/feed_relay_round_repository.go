package postgres

// Feed relay rounds and spool (docs/rfcs/RFC-142-feed-relay.md).
// Platform-wide feed bookkeeping: the tables have no tenant column and hold
// no tenant data. A round is uploaded to and closed only by the designated
// sensor that claimed it.

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/pkg/domain/feedrelay"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// FeedRelayRoundRepository implements feedrelay.Repository and
// feedrelay.Spool.
type FeedRelayRoundRepository struct{ db *DB }

var (
	_ feedrelay.Repository = (*FeedRelayRoundRepository)(nil)
	_ feedrelay.Spool      = (*FeedRelayRoundRepository)(nil)
)

// NewFeedRelayRoundRepository creates the repository.
func NewFeedRelayRoundRepository(db *DB) *FeedRelayRoundRepository {
	return &FeedRelayRoundRepository{db: db}
}

const feedRelayRoundColumns = `id, sensor_id, claimed_at, feed, phase, status, origins, files, report, delivered_bytes,
	error_code, error_detail, created_at, expires_at, delivered_at`

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
		INSERT INTO feed_relay_rounds (id, sensor_id, claimed_at, feed, phase, status, origins, files, report,
			error_code, error_detail, created_at, expires_at, delivered_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)`,
		rd.ID.String(), nullID(rd.SensorID), rd.ClaimedAt, rd.Feed, rd.Phase, rd.Status, origins, fb, nullBytes(report),
		rd.ErrorCode, rd.ErrorDetail, rd.CreatedAt, rd.ExpiresAt, rd.DeliveredAt)
	if err != nil {
		return fmt.Errorf("create feed relay round: %w", err)
	}
	return nil
}

// GetForSensor returns the round when that sensor claimed it.
func (r *FeedRelayRoundRepository) GetForSensor(ctx context.Context, id, sensorID shared.ID) (*feedrelay.Round, error) {
	row := r.db.QueryRowContext(ctx, `SELECT `+feedRelayRoundColumns+` FROM feed_relay_rounds WHERE id = $1 AND sensor_id = $2`,
		id.String(), sensorID.String())
	rd, err := scanFeedRelayRound(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, feedrelay.ErrNotFound
	}
	return rd, err
}

// Claim gives the caller the oldest open round it may claim. The caller's
// own claim keeps its time (re-serving it does not refresh the claim, so a
// relay that never uploads cannot hold a round forever).
func (r *FeedRelayRoundRepository) Claim(ctx context.Context, rule feedrelay.ClaimRule) (*feedrelay.Round, error) {
	designated := make([]string, 0, len(rule.Designated))
	for _, id := range rule.Designated {
		designated = append(designated, id.String())
	}
	row := r.db.QueryRowContext(ctx, `
		UPDATE feed_relay_rounds r
		SET claimed_at = CASE WHEN r.sensor_id = $1 THEN r.claimed_at ELSE $2 END,
		    sensor_id = $1
		WHERE r.id = (
			SELECT id FROM feed_relay_rounds
			WHERE status = 'open' AND expires_at > $2
			  AND (sensor_id IS NULL OR sensor_id = $1 OR NOT (sensor_id = ANY($3::uuid[]))
			       OR (claimed_at < $4 AND delivered_bytes = 0))
			ORDER BY (sensor_id = $1) DESC NULLS LAST, created_at
			LIMIT 1
			FOR UPDATE SKIP LOCKED)
		RETURNING `+feedRelayRoundColumns,
		rule.SensorID.String(), rule.Now, pq.Array(designated), rule.StaleBefore)
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

// Fail closes an open round as failed.
func (r *FeedRelayRoundRepository) Fail(ctx context.Context, id shared.ID, code, detail string, at time.Time) error {
	_, err := r.db.ExecContext(ctx, `UPDATE feed_relay_rounds SET status = 'failed', error_code = $2, error_detail = $3,
		delivered_at = $4 WHERE id = $1 AND status = 'open'`, id.String(), code, detail, at)
	if err != nil {
		return fmt.Errorf("fail feed relay round: %w", err)
	}
	return nil
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

// Activity returns what each sensor delivered recently.
func (r *FeedRelayRoundRepository) Activity(ctx context.Context, sensorIDs []shared.ID, since time.Time) (map[shared.ID]feedrelay.SensorActivity, error) {
	out := map[shared.ID]feedrelay.SensorActivity{}
	if len(sensorIDs) == 0 {
		return out, nil
	}
	ids := make([]string, 0, len(sensorIDs))
	for _, id := range sensorIDs {
		ids = append(ids, id.String())
	}
	rows, err := r.db.QueryContext(ctx, `
		SELECT sensor_id, max(delivered_at), COALESCE(sum(delivered_bytes) FILTER (WHERE delivered_at >= $2), 0)
		FROM feed_relay_rounds
		WHERE sensor_id = ANY($1::uuid[]) AND delivered_at IS NOT NULL
		GROUP BY sensor_id`, pq.Array(ids), since)
	if err != nil {
		return nil, fmt.Errorf("feed relay activity: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var (
			sid   string
			last  sql.NullTime
			bytes int64
		)
		if err := rows.Scan(&sid, &last, &bytes); err != nil {
			return nil, err
		}
		id, err := shared.IDFromString(sid)
		if err != nil {
			return nil, err
		}
		a := feedrelay.SensorActivity{Bytes: bytes}
		if last.Valid {
			t := last.Time
			a.LastDeliveredAt = &t
		}
		out[id] = a
	}
	return out, rows.Err()
}

// BootstrapSensor returns the sensor whose completed pairing started with
// that instance enrollment token.
func (r *FeedRelayRoundRepository) BootstrapSensor(ctx context.Context, tokenID shared.ID) (*shared.ID, error) {
	var sid string
	err := r.db.QueryRowContext(ctx, `SELECT sensor_id FROM sensor_pairings
		WHERE instance_token_id = $1 AND tenant_id IS NULL AND sensor_id IS NOT NULL AND status IN ('approved', 'completed')
		LIMIT 1`, tokenID.String()).Scan(&sid)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("feed relay bootstrap sensor: %w", err)
	}
	id, err := shared.IDFromString(sid)
	if err != nil {
		return nil, err
	}
	return &id, nil
}

// Store writes a verified upload into the spool (see feedrelay.Spool).
func (r *FeedRelayRoundRepository) Store(ctx context.Context, u feedrelay.Upload) error {
	size := int64(len(u.Data))
	quotaHit := false
	err := r.db.Transaction(ctx, func(tx *sql.Tx) error {
		var delivered int64
		err := tx.QueryRowContext(ctx, `SELECT delivered_bytes FROM feed_relay_rounds
			WHERE id = $1 AND sensor_id = $2 AND feed = $3 AND status = 'open' AND expires_at > $4 FOR UPDATE`,
			u.RoundID.String(), u.SensorID.String(), u.Feed, u.Now).Scan(&delivered)
		if errors.Is(err, sql.ErrNoRows) {
			return feedrelay.ErrRoundClosed
		}
		if err != nil {
			return err
		}
		var prevSHA string
		err = tx.QueryRowContext(ctx, `SELECT sha256 FROM feed_relay_files WHERE feed = $1 AND name = $2 AND round_id = $3`,
			u.Feed, u.Name, u.RoundID.String()).Scan(&prevSHA)
		switch {
		case err == nil && prevSHA == u.SHA256:
			return nil // the same file again (a retried upload): nothing to do
		case err == nil:
			return feedrelay.ErrDuplicate
		case !errors.Is(err, sql.ErrNoRows):
			return err
		}
		if delivered+size > u.RoundBudget {
			return feedrelay.ErrRoundFull
		}
		var others int64
		if err := tx.QueryRowContext(ctx, `SELECT COALESCE(sum(size), 0) FROM feed_relay_files WHERE NOT (feed = $1 AND name = $2)`,
			u.Feed, u.Name).Scan(&others); err != nil {
			return err
		}
		if others+size > u.SpoolQuota {
			quotaHit = true
			return feedrelay.ErrSpoolFull
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO feed_relay_files (feed, name, sha256, size, data, round_id, received_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7)
			ON CONFLICT (feed, name) DO UPDATE SET sha256 = EXCLUDED.sha256, size = EXCLUDED.size, data = EXCLUDED.data,
				round_id = EXCLUDED.round_id, received_at = EXCLUDED.received_at`,
			u.Feed, u.Name, u.SHA256, size, u.Data, u.RoundID.String(), u.Now); err != nil {
			return fmt.Errorf("store feed relay file: %w", err)
		}
		_, err = tx.ExecContext(ctx, `UPDATE feed_relay_rounds SET delivered_bytes = delivered_bytes + $2 WHERE id = $1`,
			u.RoundID.String(), size)
		return err
	})
	if quotaHit {
		_, _ = r.db.ExecContext(ctx, `UPDATE feed_relay_rounds SET error_code = $2 WHERE id = $1 AND status = 'open'`,
			u.RoundID.String(), feedrelay.CodeSpoolFull)
	}
	return err
}

// List returns a feed's spool files (no bytes).
func (r *FeedRelayRoundRepository) List(ctx context.Context, feed string) ([]feedrelay.SpoolFile, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT name, sha256, size FROM feed_relay_files WHERE feed = $1 ORDER BY name`, feed)
	if err != nil {
		return nil, fmt.Errorf("list feed relay files: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []feedrelay.SpoolFile
	for rows.Next() {
		var f feedrelay.SpoolFile
		if err := rows.Scan(&f.Name, &f.SHA256, &f.Size); err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

// Read returns one spool file's bytes.
func (r *FeedRelayRoundRepository) Read(ctx context.Context, feed, name string) ([]byte, error) {
	var b []byte
	err := r.db.QueryRowContext(ctx, `SELECT data FROM feed_relay_files WHERE feed = $1 AND name = $2`, feed, name).Scan(&b)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, feedrelay.ErrNotFound
	}
	return b, err
}

// Prune deletes a feed's files keep does not name.
func (r *FeedRelayRoundRepository) Prune(ctx context.Context, feed string, keep []string) (int, error) {
	res, err := r.db.ExecContext(ctx, `DELETE FROM feed_relay_files WHERE feed = $1 AND NOT (name = ANY($2::text[]))`,
		feed, pq.Array(nonNilStrings(keep)))
	if err != nil {
		return 0, fmt.Errorf("prune feed relay files: %w", err)
	}
	n, err := res.RowsAffected()
	return int(n), err
}

// Clear deletes every spool file.
func (r *FeedRelayRoundRepository) Clear(ctx context.Context) (int, error) {
	res, err := r.db.ExecContext(ctx, `DELETE FROM feed_relay_files`)
	if err != nil {
		return 0, fmt.Errorf("clear feed relay files: %w", err)
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
		id                     string
		sensorID               sql.NullString
		claimed, delivered     sql.NullTime
		origins, files, report []byte
	)
	if err := row.Scan(&id, &sensorID, &claimed, &rd.Feed, &rd.Phase, &rd.Status, &origins, &files, &report,
		&rd.DeliveredBytes, &rd.ErrorCode, &rd.ErrorDetail, &rd.CreatedAt, &rd.ExpiresAt, &delivered); err != nil {
		return nil, err
	}
	var err error
	if rd.ID, err = shared.IDFromString(id); err != nil {
		return nil, err
	}
	if sensorID.Valid {
		sid, err := shared.IDFromString(sensorID.String)
		if err != nil {
			return nil, err
		}
		rd.SensorID = &sid
	}
	if claimed.Valid {
		t := claimed.Time
		rd.ClaimedAt = &t
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
