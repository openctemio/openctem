package postgres

// Heartbeat deadline, control report and the health controller's ladder
// writes (docs/rfcs/RFC-035-sensor-control-plane-under-load.md §5.5, §5.6;
// pkg/domain/sensor/liveness.go).

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"math"
	"slices"
	"time"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// sensorDispatchableHealthSQL is the stored health that may be handed new
// work: online, or late (past its deadline but not yet stale). Stale and
// offline sensors get none (sensor.SensorHealth.IsDispatchable).
const sensorDispatchableHealthSQL = "('online', 'late')"

var _ sensor.LivenessRepository = (*SensorRepository)(nil)

// heartbeatIntervalSeconds is the interval column value for a heartbeat:
// whole seconds inside the ladder's bounds.
func heartbeatIntervalSeconds(d time.Duration) int32 {
	s := math.Round(sensor.ClampHeartbeatInterval(d).Seconds())
	return int32(max(s, 1)) // bounded to [1, 300] by ClampHeartbeatInterval
}

// controlArg is the reported_control parameter: NULL (keep the stored one)
// when the heartbeat carried none.
func controlArg(c *sensor.ControlReport) (sql.NullString, error) {
	if c == nil {
		return sql.NullString{}, nil
	}
	raw, err := json.Marshal(c)
	if err != nil {
		return sql.NullString{}, fmt.Errorf("failed to marshal sensor control report: %w", err)
	}
	return sql.NullString{String: string(raw), Valid: true}, nil
}

// scanControl builds the stored control report; a report that does not
// decode is dropped (logged), never fatal to reading the sensor.
func scanControl(id shared.ID, raw []byte, at sql.NullTime) *sensor.ControlReport {
	if len(raw) == 0 {
		return nil
	}
	var c sensor.ControlReport
	if err := json.Unmarshal(raw, &c); err != nil {
		log.Printf("[DEBUG] failed to unmarshal sensor control report (id=%s): %v", id, err)
		return nil
	}
	if at.Valid {
		t := at.Time
		c.ReportedAt = &t
	}
	return &c
}

// ListLivenessCandidates returns every sensor the health controller watches
// (health online, late or stale) with its deadline, and the database's now.
func (r *SensorRepository) ListLivenessCandidates(ctx context.Context) (time.Time, []sensor.LivenessCandidate, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT id, health, last_seen_at, heartbeat_due_at, heartbeat_interval_seconds, NOW()
		FROM sensors
		WHERE health IN ('online', 'late', 'stale')`)
	if err != nil {
		return time.Time{}, nil, fmt.Errorf("failed to list sensor deadlines: %w", err)
	}
	defer rows.Close()

	var (
		now  time.Time
		out  []sensor.LivenessCandidate
		seen bool
	)
	for rows.Next() {
		var (
			id       string
			health   string
			lastSeen sql.NullTime
			due      sql.NullTime
			interval sql.NullInt32
			dbNow    time.Time
		)
		if err := rows.Scan(&id, &health, &lastSeen, &due, &interval, &dbNow); err != nil {
			return time.Time{}, nil, fmt.Errorf("failed to scan sensor deadline: %w", err)
		}
		if !seen {
			now, seen = dbNow, true
		}
		sid, err := shared.IDFromString(id)
		if err != nil {
			continue
		}
		c := sensor.LivenessCandidate{ID: sid, Health: sensor.SensorHealth(health)}
		if lastSeen.Valid {
			t := lastSeen.Time
			c.Deadline.LastSeenAt = &t
		}
		if due.Valid {
			t := due.Time
			c.Deadline.DueAt = &t
		}
		if interval.Valid {
			c.Deadline.Interval = time.Duration(interval.Int32) * time.Second
		}
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		return time.Time{}, nil, fmt.Errorf("failed to iterate sensor deadlines: %w", err)
	}
	if !seen {
		if err := r.db.QueryRowContext(ctx, `SELECT NOW()`).Scan(&now); err != nil {
			return time.Time{}, nil, fmt.Errorf("failed to read database time: %w", err)
		}
	}
	return now, out, nil
}

// ApplyLiveness moves sensors to health. A sensor moves only if its health
// is still online, late or stale and its last_seen_at is the one the
// controller read: any request in between (which sets health back to online)
// wins. Moving to offline stamps last_offline_at.
func (r *SensorRepository) ApplyLiveness(ctx context.Context, health sensor.SensorHealth, candidates []sensor.LivenessCandidate) ([]shared.ID, error) {
	return r.applyLiveness(ctx, health, candidates, liveHealths)
}

// liveHealths are the stored healths the ladder walks.
var liveHealths = []sensor.SensorHealth{sensor.SensorHealthOnline, sensor.SensorHealthLate, sensor.SensorHealthStale}

// applyLiveness is ApplyLiveness restricted to sensors whose health is one
// of from.
func (r *SensorRepository) applyLiveness(ctx context.Context, health sensor.SensorHealth, candidates []sensor.LivenessCandidate, from []sensor.SensorHealth) ([]shared.ID, error) {
	if len(candidates) == 0 {
		return nil, nil
	}
	if health != sensor.SensorHealthLate && health != sensor.SensorHealthStale && health != sensor.SensorHealthOffline {
		return nil, fmt.Errorf("%w: the ladder moves sensors to late, stale or offline, not %q", shared.ErrValidation, health)
	}
	ids := make([]string, 0, len(candidates))
	seen := make([]sql.NullString, 0, len(candidates))
	for _, c := range candidates {
		ids = append(ids, c.ID.String())
		var t sql.NullString
		if c.Deadline.LastSeenAt != nil {
			t = sql.NullString{String: c.Deadline.LastSeenAt.UTC().Format(time.RFC3339Nano), Valid: true}
		}
		seen = append(seen, t)
	}
	rows, err := r.db.QueryContext(ctx, `
		UPDATE sensors s
		SET health = $1,
		    last_offline_at = CASE WHEN $1 = 'offline' THEN NOW() ELSE s.last_offline_at END,
		    updated_at = NOW()
		FROM unnest($2::uuid[], $3::timestamptz[]) AS c(id, seen)
		WHERE s.id = c.id
		  AND s.health = ANY($4::text[])
		  AND s.health <> $1
		  AND s.last_seen_at IS NOT DISTINCT FROM c.seen
		RETURNING s.id`,
		string(health), pq.Array(ids), pq.Array(seen), pq.Array(healthStrings(from)))
	if err != nil {
		return nil, fmt.Errorf("failed to move sensors to %s: %w", health, err)
	}
	defer rows.Close()

	var moved []shared.ID
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("failed to scan moved sensor id: %w", err)
		}
		if sid, err := shared.IDFromString(id); err == nil {
			moved = append(moved, sid)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to iterate moved sensors: %w", err)
	}
	return moved, nil
}

func healthStrings(hs []sensor.SensorHealth) []string {
	out := make([]string, len(hs))
	for i, h := range hs {
		out[i] = string(h)
	}
	return out
}

// convictOffline marks offline the sensors whose health is one of from, that
// the ladder puts past its offline step, and that were last seen more than
// minAge ago (never seen counts as long ago). It is the ladder without the
// health controller's platform-health guard and notifications: the
// controller is what convicts in normal operation (it moves a sensor to late
// and stale first); these are the backstops behind MarkStaleSensorsOffline
// and MarkStaleAsOffline.
func (r *SensorRepository) convictOffline(ctx context.Context, from []sensor.SensorHealth, minAge time.Duration) ([]shared.ID, error) {
	now, candidates, err := r.ListLivenessCandidates(ctx)
	if err != nil {
		return nil, err
	}
	due := make([]sensor.LivenessCandidate, 0, len(candidates))
	for _, c := range candidates {
		if !slices.Contains(from, c.Health) {
			continue
		}
		if sensor.Ladder(now, c.Deadline).State != sensor.SensorHealthOffline {
			continue
		}
		if seen := c.Deadline.LastSeenAt; seen != nil && now.Sub(*seen) <= minAge {
			continue
		}
		due = append(due, c)
	}
	return r.applyLiveness(ctx, sensor.SensorHealthOffline, due, from)
}
