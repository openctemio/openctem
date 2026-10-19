package postgres

// Heartbeat soft state on the Postgres side (docs/architecture/sensors.md,
// "Heartbeat soft state"): the batched checkpoint, the batched heartbeat
// history, and the overlay of the liveness store on sensor rows.

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// livenessOverlayTimeout bounds the store read that overlays a page of rows.
const livenessOverlayTimeout = 500 * time.Millisecond

var _ sensor.LivenessCheckpointer = (*SensorRepository)(nil)

// SetLivenessOverlay makes the reads (GetByID, GetByTenantAndID, List)
// overlay the liveness store's entry on each row: the later last-seen and
// deadline win (sensor.LivenessSnapshot.Deadline). Used when liveness lives
// in the store; a store that cannot be read leaves the rows as stored (the
// last checkpoint), never fails the read.
func (r *SensorRepository) SetLivenessOverlay(s sensor.LivenessStore) { r.liveness = s }

// overlayOne wraps a single-row read.
func (r *SensorRepository) overlayOne(ctx context.Context) func(*sensor.Sensor, error) (*sensor.Sensor, error) {
	return func(a *sensor.Sensor, err error) (*sensor.Sensor, error) {
		if err == nil && a != nil {
			r.overlayLiveness(ctx, []*sensor.Sensor{a})
		}
		return a, err
	}
}

// overlayLiveness applies the store entries to rows, one store round trip.
func (r *SensorRepository) overlayLiveness(ctx context.Context, rows []*sensor.Sensor) {
	if r.liveness == nil || len(rows) == 0 {
		return
	}
	keys := make([]sensor.LivenessKey, 0, len(rows))
	for _, a := range rows {
		if a != nil {
			keys = append(keys, sensor.LivenessKeyOf(a.TenantID, a.ID))
		}
	}
	octx, cancel := context.WithTimeout(ctx, livenessOverlayTimeout)
	defer cancel()
	snaps, err := r.liveness.Snapshots(octx, keys)
	if err != nil {
		return
	}
	for _, a := range rows {
		if a == nil {
			continue
		}
		if snap, ok := snaps[a.ID]; ok {
			a.OverlayLiveness(snap)
		}
	}
}

func livenessJSON(v any) (sql.NullString, error) {
	if v == nil {
		return sql.NullString{}, nil
	}
	raw, err := json.Marshal(v)
	if err != nil {
		return sql.NullString{}, err
	}
	if string(raw) == "null" {
		return sql.NullString{}, nil
	}
	return sql.NullString{String: string(raw), Valid: true}, nil
}

// CheckpointLiveness writes many sensors' liveness and load in one
// statement (arrays, so no bind-parameter limit). A row is written only
// while the sensor is active, of the tenant the checkpoint names, and not
// seen later than the checkpoint (two replicas flushing out of order cannot
// move last_seen_at back). Health is never written here: a checkpoint only
// comes from a steady, online sensor.
func (r *SensorRepository) CheckpointLiveness(ctx context.Context, rows []sensor.LivenessCheckpoint) (int64, error) {
	if len(rows) == 0 {
		return 0, nil
	}
	n := len(rows)
	var (
		ids, tenants                    = make([]string, 0, n), make([]sql.NullString, 0, n)
		seen, due, used                 = make([]time.Time, 0, n), make([]time.Time, 0, n), make([]sql.NullTime, 0, n)
		ivs                             = make([]int32, 0, n)
		cpu, mem, dr, dw, nr, nt, score = make([]float64, 0, n), make([]float64, 0, n), make([]float64, 0, n),
			make([]float64, 0, n), make([]float64, 0, n), make([]float64, 0, n), make([]float64, 0, n)
		res, capa, queue, outbox, control = make([]sql.NullString, 0, n), make([]sql.NullString, 0, n),
			make([]sql.NullString, 0, n), make([]sql.NullString, 0, n), make([]sql.NullString, 0, n)
	)
	for _, c := range rows {
		ids = append(ids, c.SensorID.String())
		var t sql.NullString
		if c.TenantID != nil {
			t = sql.NullString{String: c.TenantID.String(), Valid: true}
		}
		tenants = append(tenants, t)
		seen = append(seen, c.SeenAt.UTC())
		d := c.DueAt
		if d.Before(c.SeenAt) {
			d = c.SeenAt
		}
		due = append(due, d.UTC())
		var u sql.NullTime
		if !c.KeyUsedAt.IsZero() {
			u = sql.NullTime{Time: c.KeyUsedAt.UTC(), Valid: true}
		}
		used = append(used, u)
		ivs = append(ivs, heartbeatIntervalSeconds(c.Interval))
		l := c.Load
		cpu, mem, dr, dw = append(cpu, l.CPUPercent), append(mem, l.MemoryPercent), append(dr, l.DiskReadMBPS), append(dw, l.DiskWriteMBPS)
		nr, nt, score = append(nr, l.NetworkRxMBPS), append(nt, l.NetworkTxMBPS), append(score, l.LoadScore)
		var lr, lc, lq sql.NullString
		if l.Load != nil {
			var err error
			if l.Load.Resources != nil {
				if lr, err = livenessJSON(l.Load.Resources); err != nil {
					return 0, fmt.Errorf("checkpoint: %w", err)
				}
			}
			if l.Load.Capacity != nil {
				if lc, err = livenessJSON(l.Load.Capacity); err != nil {
					return 0, fmt.Errorf("checkpoint: %w", err)
				}
			}
			if l.Load.Queue != nil {
				if lq, err = livenessJSON(l.Load.Queue); err != nil {
					return 0, fmt.Errorf("checkpoint: %w", err)
				}
			}
		}
		res, capa, queue = append(res, lr), append(capa, lc), append(queue, lq)
		var ob, ct sql.NullString
		var err error
		if l.Outbox != nil {
			if ob, err = livenessJSON(l.Outbox); err != nil {
				return 0, fmt.Errorf("checkpoint: %w", err)
			}
		}
		if l.Control != nil {
			if ct, err = livenessJSON(l.Control); err != nil {
				return 0, fmt.Errorf("checkpoint: %w", err)
			}
		}
		outbox, control = append(outbox, ob), append(control, ct)
	}
	result, err := r.db.ExecContext(ctx, `
		UPDATE sensors s
		SET last_seen_at = v.seen,
		    heartbeat_due_at = v.due,
		    heartbeat_interval_seconds = v.iv,
		    cpu_percent = v.cpu, memory_percent = v.mem,
		    disk_read_mbps = v.dr, disk_write_mbps = v.dw,
		    network_rx_mbps = v.nr, network_tx_mbps = v.nt,
		    load_score = v.score,
		    metrics_updated_at = v.seen,
		    reported_resources = COALESCE(v.res::jsonb, s.reported_resources),
		    reported_capacity = COALESCE(v.capa::jsonb, s.reported_capacity),
		    reported_queue = COALESCE(v.queue::jsonb, s.reported_queue),
		    load_reported_at = CASE WHEN v.res IS NULL AND v.capa IS NULL AND v.queue IS NULL
		        THEN s.load_reported_at ELSE v.seen END,
		    outbox_stats = COALESCE(v.outbox::jsonb, s.outbox_stats),
		    outbox_reported_at = CASE WHEN v.outbox IS NULL THEN s.outbox_reported_at ELSE v.seen END,
		    reported_control = COALESCE(v.control::jsonb, s.reported_control),
		    control_reported_at = CASE WHEN v.control IS NULL THEN s.control_reported_at ELSE v.seen END,
		    api_key_last_used_at = GREATEST(s.api_key_last_used_at, v.used),
		    updated_at = NOW()
		FROM unnest($1::uuid[], $2::uuid[], $3::timestamptz[], $4::timestamptz[], $5::int[],
		            $6::float8[], $7::float8[], $8::float8[], $9::float8[], $10::float8[], $11::float8[], $12::float8[],
		            $13::text[], $14::text[], $15::text[], $16::text[], $17::text[], $18::timestamptz[])
		     AS v(id, tenant, seen, due, iv, cpu, mem, dr, dw, nr, nt, score, res, capa, queue, outbox, control, used)
		WHERE s.id = v.id
		  AND s.tenant_id IS NOT DISTINCT FROM v.tenant
		  AND s.status = 'active'
		  AND (s.last_seen_at IS NULL OR s.last_seen_at < v.seen)`,
		pq.Array(ids), pq.Array(tenants), pq.Array(seen), pq.Array(due), pq.Array(ivs),
		pq.Array(cpu), pq.Array(mem), pq.Array(dr), pq.Array(dw), pq.Array(nr), pq.Array(nt), pq.Array(score),
		pq.Array(res), pq.Array(capa), pq.Array(queue), pq.Array(outbox), pq.Array(control), pq.Array(used))
	if err != nil {
		return 0, fmt.Errorf("failed to checkpoint sensor liveness: %w", err)
	}
	return result.RowsAffected()
}

// RecordHeartbeatBatch adds many heartbeat aggregates to their buckets in
// one statement (sensor.HeartbeatBatchRecorder). Additive: two replicas
// flushing the same bucket both count.
func (r *SensorHeartbeatHistoryRepository) RecordHeartbeatBatch(ctx context.Context, rows []sensor.HeartbeatAggregate) error {
	if len(rows) == 0 {
		return nil
	}
	n := len(rows)
	ids, tenants := make([]string, 0, n), make([]string, 0, n)
	buckets := make([]time.Time, 0, n)
	beats, gapBeats := make([]int64, 0, n), make([]int64, 0, n)
	sumGap, maxGap, maxIv := make([]float64, 0, n), make([]float64, 0, n), make([]float64, 0, n)
	maxLag, failures := make([]int64, 0, n), make([]int64, 0, n)
	for _, a := range rows {
		ids, tenants = append(ids, a.SensorID.String()), append(tenants, a.TenantID.String())
		buckets = append(buckets, a.BucketStart.UTC())
		beats, gapBeats = append(beats, a.Beats), append(gapBeats, a.GapBeats)
		sumGap, maxGap, maxIv = append(sumGap, a.SumGapSeconds), append(maxGap, a.MaxGapSeconds), append(maxIv, a.MaxIntervalSeconds)
		maxLag, failures = append(maxLag, a.MaxLagMillis), append(failures, a.Failures)
	}
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO sensor_heartbeat_history AS h
		    (sensor_id, tenant_id, bucket_start, beats, gap_beats, sum_gap_seconds,
		     max_gap_seconds, max_interval_seconds, max_lag_ms, failures)
		SELECT v.sid, v.tid, v.bucket, v.beats, v.gaps, v.sum_gap, v.max_gap, v.max_iv, v.max_lag, v.failures
		FROM unnest($1::uuid[], $2::uuid[], $3::timestamptz[], $4::bigint[], $5::bigint[],
		            $6::float8[], $7::float8[], $8::float8[], $9::bigint[], $10::bigint[])
		     AS v(sid, tid, bucket, beats, gaps, sum_gap, max_gap, max_iv, max_lag, failures)
		ON CONFLICT (sensor_id, bucket_start) DO UPDATE SET
		    beats = h.beats + EXCLUDED.beats,
		    gap_beats = h.gap_beats + EXCLUDED.gap_beats,
		    sum_gap_seconds = h.sum_gap_seconds + EXCLUDED.sum_gap_seconds,
		    max_gap_seconds = GREATEST(h.max_gap_seconds, EXCLUDED.max_gap_seconds),
		    max_interval_seconds = GREATEST(h.max_interval_seconds, EXCLUDED.max_interval_seconds),
		    max_lag_ms = GREATEST(h.max_lag_ms, EXCLUDED.max_lag_ms),
		    failures = h.failures + EXCLUDED.failures
		WHERE h.tenant_id = EXCLUDED.tenant_id`,
		pq.Array(ids), pq.Array(tenants), pq.Array(buckets), pq.Array(beats), pq.Array(gapBeats),
		pq.Array(sumGap), pq.Array(maxGap), pq.Array(maxIv), pq.Array(maxLag), pq.Array(failures))
	if err != nil {
		return fmt.Errorf("failed to record heartbeat history batch: %w", err)
	}
	return nil
}

// ExpireLeasesHeldBy ends the leases of every command sensorID holds
// (acknowledged or running, tenant or shared jobs), so the job-recovery
// controller re-queues them on its next pass through its usual path. Used
// when the health controller convicts the sensor offline.
func (r *CommandRepository) ExpireLeasesHeldBy(ctx context.Context, sensorID shared.ID) (int64, error) {
	res, err := r.db.ExecContext(ctx, `
		UPDATE commands
		SET lease_expires_at = NOW()
		WHERE sensor_id = $1
		  AND status IN ('acknowledged', 'running')
		  AND lease_expires_at > NOW()`, sensorID.String())
	if err != nil {
		return 0, fmt.Errorf("failed to expire the leases of sensor: %w", err)
	}
	return res.RowsAffected()
}
