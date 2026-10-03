package postgres

import (
	"context"
	"fmt"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// SensorHeartbeatHistoryRepository stores the per-sensor heartbeat history
// (sensor_heartbeat_history, migration 000263).
type SensorHeartbeatHistoryRepository struct {
	db *DB
}

var _ sensor.HeartbeatHistoryRepository = (*SensorHeartbeatHistoryRepository)(nil)

// NewSensorHeartbeatHistoryRepository creates the repository.
func NewSensorHeartbeatHistoryRepository(db *DB) *SensorHeartbeatHistoryRepository {
	return &SensorHeartbeatHistoryRepository{db: db}
}

// RecordHeartbeat adds one heartbeat to its bucket (one upsert).
func (r *SensorHeartbeatHistoryRepository) RecordHeartbeat(ctx context.Context, s sensor.HeartbeatSample) error {
	s = s.Clamped()
	gapBeats := 0
	if s.Gap > 0 {
		gapBeats = 1
	}
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO sensor_heartbeat_history AS h
		    (sensor_id, tenant_id, bucket_start, beats, gap_beats, sum_gap_seconds,
		     max_gap_seconds, max_interval_seconds, max_lag_ms, failures)
		VALUES ($1, $2, $3, 1, $4, $5, $5, $6, $7, $8)
		ON CONFLICT (sensor_id, bucket_start) DO UPDATE SET
		    beats = h.beats + 1,
		    gap_beats = h.gap_beats + EXCLUDED.gap_beats,
		    sum_gap_seconds = h.sum_gap_seconds + EXCLUDED.sum_gap_seconds,
		    max_gap_seconds = GREATEST(h.max_gap_seconds, EXCLUDED.max_gap_seconds),
		    max_interval_seconds = GREATEST(h.max_interval_seconds, EXCLUDED.max_interval_seconds),
		    max_lag_ms = GREATEST(h.max_lag_ms, EXCLUDED.max_lag_ms),
		    failures = h.failures + EXCLUDED.failures
		WHERE h.tenant_id = EXCLUDED.tenant_id`,
		s.SensorID.String(), s.TenantID.String(), sensor.HeartbeatBucketStart(s.At),
		gapBeats, s.Gap.Seconds(), s.Interval.Seconds(), s.LagMillis, s.Failures)
	if err != nil {
		return fmt.Errorf("failed to record heartbeat history: %w", err)
	}
	return nil
}

// HeartbeatHistory returns one tenant sensor's buckets since since, oldest
// first.
func (r *SensorHeartbeatHistoryRepository) HeartbeatHistory(ctx context.Context, tenantID, sensorID shared.ID, since time.Time) ([]sensor.HeartbeatBucket, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT bucket_start, beats, gap_beats, sum_gap_seconds, max_gap_seconds,
		       max_interval_seconds, max_lag_ms, failures
		FROM sensor_heartbeat_history
		WHERE tenant_id = $1 AND sensor_id = $2 AND bucket_start >= $3
		ORDER BY bucket_start
		LIMIT 200`,
		tenantID.String(), sensorID.String(), sensor.HeartbeatBucketStart(since))
	if err != nil {
		return nil, fmt.Errorf("failed to read heartbeat history: %w", err)
	}
	defer rows.Close()
	out := make([]sensor.HeartbeatBucket, 0, 96)
	for rows.Next() {
		var b sensor.HeartbeatBucket
		var gapBeats int
		var sumGap float64
		if err := rows.Scan(&b.Start, &b.Beats, &gapBeats, &sumGap, &b.MaxGapSeconds,
			&b.IntervalSeconds, &b.MaxLagMillis, &b.Failures); err != nil {
			return nil, fmt.Errorf("failed to scan heartbeat history: %w", err)
		}
		if gapBeats > 0 {
			b.AvgGapSeconds = sumGap / float64(gapBeats)
		}
		b.Start = b.Start.UTC()
		out = append(out, b)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to iterate heartbeat history: %w", err)
	}
	return out, nil
}

// DeleteHeartbeatHistoryBefore removes up to limit buckets that started
// before before (the retention sweep, all tenants).
func (r *SensorHeartbeatHistoryRepository) DeleteHeartbeatHistoryBefore(ctx context.Context, before time.Time, limit int) (int64, error) {
	if limit <= 0 {
		limit = 5000
	}
	res, err := r.db.ExecContext(ctx, `
		DELETE FROM sensor_heartbeat_history
		WHERE (sensor_id, bucket_start) IN (
			SELECT sensor_id, bucket_start FROM sensor_heartbeat_history
			WHERE bucket_start < $1
			ORDER BY bucket_start
			LIMIT $2
		)`, before, limit)
	if err != nil {
		return 0, fmt.Errorf("failed to delete old heartbeat history: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("failed to read rows affected: %w", err)
	}
	return n, nil
}
