package postgres

// Sensor activity (docs/architecture/sensors.md "Activity"): the
// sensor_events table (migration 000255) and the merged timeline read over
// sensor_events, commands and audit_logs.

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/lib/pq"

	"github.com/openctemio/api/pkg/domain/audit"
	"github.com/openctemio/api/pkg/domain/sensor"
	"github.com/openctemio/api/pkg/domain/shared"
)

// SensorEventRepository implements sensor.EventRepository and
// sensor.ActivityReader.
type SensorEventRepository struct {
	db *DB
}

// NewSensorEventRepository creates a SensorEventRepository.
func NewSensorEventRepository(db *DB) *SensorEventRepository {
	return &SensorEventRepository{db: db}
}

var (
	_ sensor.EventRepository = (*SensorEventRepository)(nil)
	_ sensor.ActivityReader  = (*SensorEventRepository)(nil)
)

// Record writes an event under the limits, in one statement. When the latest
// event of the sensor in the same category (status or updates) is the same
// event (same type, and same summary unless the type alone decides) and was
// seen within the coalescing window, it is bumped instead (repeat_count,
// last_at): identical consecutive events fold into one row. Otherwise a row
// is inserted, unless the sensor already wrote MaxPerHour rows of that
// category in the hour before the event: a flapping sensor fills its status
// budget without crowding out its updates.
func (r *SensorEventRepository) Record(ctx context.Context, e sensor.Event, limits sensor.EventLimits) (sensor.EventWriteResult, error) {
	details := e.Details
	if details == nil {
		details = map[string]any{}
	}
	raw, err := json.Marshal(details)
	if err != nil {
		return "", fmt.Errorf("marshal sensor event details: %w", err)
	}
	if e.At.IsZero() {
		e.At = time.Now()
	}
	window := limits.CoalesceWindow
	if window <= 0 {
		window = sensor.DefaultEventLimits().CoalesceWindow
	}
	maxPerHour := limits.MaxPerHour
	if maxPerHour <= 0 {
		maxPerHour = sensor.DefaultEventLimits().MaxPerHour
	}
	sameCategory := sensor.EventTypesIn([]sensor.ActivityCategory{e.Type.Category()})
	categoryTypes := make([]string, 0, len(sameCategory))
	for _, t := range sameCategory {
		categoryTypes = append(categoryTypes, string(t))
	}

	const query = `
		WITH latest AS (
			SELECT id, type, summary, COALESCE(last_at, at) AS seen
			FROM sensor_events
			WHERE tenant_id = $2 AND sensor_id = $3 AND type = ANY($11::text[])
			  AND at <= $6::timestamptz
			ORDER BY at DESC, id DESC
			LIMIT 1
		), recent AS (
			SELECT id FROM latest
			WHERE type = $4 AND ($8 = '' OR summary = $8)
			  AND seen >= $6::timestamptz - make_interval(secs => $9::double precision)
		), bumped AS (
			UPDATE sensor_events
			SET repeat_count = repeat_count + 1,
			    last_at = GREATEST(COALESCE(last_at, at), $6::timestamptz)
			WHERE id IN (SELECT id FROM recent)
			RETURNING id
		), inserted AS (
			INSERT INTO sensor_events (id, tenant_id, sensor_id, type, at, summary, details)
			SELECT $1, $2, $3, $4, $6, $5, $7::jsonb
			WHERE NOT EXISTS (SELECT 1 FROM bumped)
			  AND (SELECT COUNT(*) FROM sensor_events
			       WHERE tenant_id = $2 AND sensor_id = $3 AND type = ANY($11::text[])
			         AND at > $6::timestamptz - INTERVAL '1 hour') < $10
			RETURNING id
		)
		SELECT (SELECT COUNT(*) FROM bumped), (SELECT COUNT(*) FROM inserted)`
	var bumped, inserted int
	err = r.db.QueryRowContext(ctx, query,
		e.ID.String(), e.TenantID.String(), e.SensorID.String(), string(e.Type),
		truncateRunes(e.Summary, 500), e.At, string(raw), truncateRunes(e.CoalesceSummary(), 500),
		window.Seconds(), maxPerHour, pq.Array(categoryTypes),
	).Scan(&bumped, &inserted)

	if err != nil {
		return "", fmt.Errorf("record sensor event: %w", err)
	}
	switch {
	case bumped > 0:
		return sensor.EventCoalesced, nil
	case inserted > 0:
		return sensor.EventInserted, nil
	default:
		return sensor.EventDropped, nil
	}
}

// DeleteOlderThan removes up to limit events older than before.
func (r *SensorEventRepository) DeleteOlderThan(ctx context.Context, before time.Time, limit int) (int64, error) {
	if limit <= 0 {
		limit = 5000
	}
	const query = `
		DELETE FROM sensor_events
		WHERE id IN (SELECT id FROM sensor_events WHERE at < $1 ORDER BY at LIMIT $2)`
	res, err := r.db.ExecContext(ctx, query, before, limit)
	if err != nil {
		return 0, fmt.Errorf("delete old sensor events: %w", err)
	}
	n, _ := res.RowsAffected()
	return n, nil
}

// activityQuery merges the three sources newest first. Each source is cut
// at the cursor and limited on its own (so each uses its index), then the
// union is ordered and limited again. Keys compare in the C collation so
// the database and the cursor agree on the order of equal timestamps.
//
// Parameters: $1 tenant, $2 sensor, $3 event types, $4 cursor time (NULL:
// first page), $5 cursor key, $6 limit, $7 include jobs, $8 include audit,
// $9 audit people rows, $10 audit status rows, $11 connect/disconnect
// actions (with their historical spelling), $12 audit resource types,
// $13 connected actions.
const activityQuery = `
	WITH ev AS (
		SELECT e.at, ('e:' || e.id::text) COLLATE "C" AS key, 'sensor'::text AS source, e.type::text AS type,
		       e.summary::text AS summary, e.details, e.repeat_count, e.last_at,
		       NULL::text AS action, NULL::text AS actor, NULL::text AS result
		FROM sensor_events e
		WHERE e.tenant_id = $1 AND e.sensor_id = $2 AND e.type = ANY($3::text[])
		  AND ($4::timestamptz IS NULL OR e.at < $4 OR (e.at = $4 AND ('e:' || e.id::text) COLLATE "C" < $5::text COLLATE "C"))
		ORDER BY e.at DESC, key DESC
		LIMIT $6
	), jb AS (
		SELECT j.* FROM (
			SELECT c.acknowledged_at AS at, ('j:' || c.id::text || ':claim') COLLATE "C" AS key, 'job'::text AS source,
			       'job_claimed'::text AS type,
			       ('Claimed ' || c.type || ' job')::text AS summary,
			       jsonb_strip_nulls(jsonb_build_object('command_id', c.id, 'command_type', c.type, 'status', c.status,
			                          'tool', COALESCE(c.payload->>'scanner', c.payload->>'tool'))) AS details,
			       1 AS repeat_count, NULL::timestamptz AS last_at,
			       NULL::text AS action, NULL::text AS actor, NULL::text AS result
			FROM commands c
			WHERE c.tenant_id = $1 AND c.sensor_id = $2 AND c.acknowledged_at IS NOT NULL
			UNION ALL
			SELECT c.completed_at, ('j:' || c.id::text || ':done') COLLATE "C",  'job',
			       CASE c.status WHEN 'failed' THEN 'job_failed' WHEN 'canceled' THEN 'job_canceled'
			                     WHEN 'expired' THEN 'job_expired' ELSE 'job_completed' END,
			       (CASE c.status WHEN 'failed' THEN 'Failed ' WHEN 'canceled' THEN 'Canceled '
			                      WHEN 'expired' THEN 'Expired ' ELSE 'Completed ' END || c.type || ' job')::text,
			       jsonb_strip_nulls(jsonb_build_object('command_id', c.id, 'command_type', c.type, 'status', c.status,
			                          'tool', COALESCE(c.payload->>'scanner', c.payload->>'tool'),
			                          'error', LEFT(c.error_message, 500),
			                          'duration_seconds', CASE WHEN COALESCE(c.started_at, c.acknowledged_at) IS NOT NULL
			                              THEN GREATEST(0, FLOOR(EXTRACT(EPOCH FROM c.completed_at - COALESCE(c.started_at, c.acknowledged_at))))::bigint END)),
			       1, NULL::timestamptz, NULL::text, NULL::text, NULL::text
			FROM commands c
			WHERE c.tenant_id = $1 AND c.sensor_id = $2 AND c.completed_at IS NOT NULL
		) j
		WHERE $7::boolean
		  AND ($4::timestamptz IS NULL OR j.at < $4 OR (j.at = $4 AND j.key < $5::text COLLATE "C"))
		ORDER BY j.at DESC, j.key DESC
		LIMIT $6
	), au AS (
		SELECT a.logged_at AS at, ('a:' || a.id::text) COLLATE "C" AS key, 'audit'::text AS source,
		       CASE WHEN a.action = ANY($13::text[]) THEN 'online'
		            WHEN a.action = ANY($11::text[]) THEN 'offline'
		            ELSE 'audit' END AS type,
		       COALESCE(NULLIF(a.message, ''), a.action)::text AS summary,
		       jsonb_strip_nulls(jsonb_build_object('changes', a.changes, 'message', a.message)) AS details,
		       1 AS repeat_count, NULL::timestamptz AS last_at,
		       a.action::text AS action, COALESCE(NULLIF(a.actor_email, ''), 'system')::text AS actor, a.result::text AS result
		FROM audit_logs a
		WHERE $8::boolean
		  AND a.tenant_id = $1 AND a.resource_type = ANY($12::text[]) AND a.resource_id = $2::text
		  AND (($9::boolean AND NOT (a.action = ANY($11::text[])))
		       OR ($10::boolean AND a.action = ANY($11::text[])))
		  -- A connect/disconnect the server also wrote as an online/offline
		  -- event appears once, as the event.
		  AND NOT (a.action = ANY($11::text[]) AND EXISTS (
		        SELECT 1 FROM sensor_events e
		        WHERE e.tenant_id = $1 AND e.sensor_id = $2
		          AND e.type = CASE WHEN a.action = ANY($13::text[]) THEN 'online' ELSE 'offline' END
		          AND a.logged_at BETWEEN e.at - INTERVAL '30 seconds' AND COALESCE(e.last_at, e.at) + INTERVAL '30 seconds'))
		  AND ($4::timestamptz IS NULL OR a.logged_at < $4 OR (a.logged_at = $4 AND ('a:' || a.id::text) COLLATE "C" < $5::text COLLATE "C"))
		ORDER BY a.logged_at DESC, key DESC
		LIMIT $6
	)
	SELECT at, key, source, type, summary, details, repeat_count, last_at, action, actor, result
	FROM (SELECT * FROM ev UNION ALL SELECT * FROM jb UNION ALL SELECT * FROM au) t
	ORDER BY at DESC, key DESC
	LIMIT $6`

// ListActivity returns up to q.Limit+1 timeline items after q.After.
func (r *SensorEventRepository) ListActivity(ctx context.Context, q sensor.ActivityQuery) ([]sensor.ActivityItem, error) {
	if q.TenantID.IsZero() || q.SensorID.IsZero() {
		return nil, fmt.Errorf("%w: tenant and sensor are required", shared.ErrValidation)
	}
	limit := q.Limit
	if limit <= 0 {
		limit = 30
	}

	types := sensor.EventTypesIn(q.Categories)
	typeNames := make([]string, 0, len(types))
	for _, t := range types {
		typeNames = append(typeNames, string(t))
	}
	connected := actionNames(audit.WithHistoricalActions([]audit.Action{audit.ActionSensorConnected}))
	connDisc := actionNames(audit.WithHistoricalActions([]audit.Action{audit.ActionSensorConnected, audit.ActionSensorDisconnected}))
	resourceTypes := make([]string, 0, 2)
	for _, t := range audit.WithHistoricalResourceTypes([]audit.ResourceType{audit.ResourceTypeSensor}) {
		resourceTypes = append(resourceTypes, t.String())
	}

	var cursorAt sql.NullTime
	cursorKey := ""
	if q.After != nil {
		cursorAt = sql.NullTime{Time: q.After.At, Valid: true}
		cursorKey = q.After.Key
	}

	rows, err := r.db.QueryContext(ctx, activityQuery,
		q.TenantID.String(), q.SensorID.String(), pq.Array(typeNames),
		cursorAt, cursorKey, limit+1,
		q.Has(sensor.CategoryJobs), q.IncludeAudit,
		q.Has(sensor.CategoryPeople), q.Has(sensor.CategoryStatus),
		pq.Array(connDisc), pq.Array(resourceTypes), pq.Array(connected),
	)
	if err != nil {
		return nil, fmt.Errorf("list sensor activity: %w", err)
	}
	defer rows.Close()

	items := make([]sensor.ActivityItem, 0, limit+1)
	for rows.Next() {
		var (
			it                    sensor.ActivityItem
			details               []byte
			lastAt                sql.NullTime
			action, actor, result sql.NullString
		)
		if err := rows.Scan(&it.At, &it.Key, &it.Source, &it.Type, &it.Summary, &details, &it.RepeatCount,
			&lastAt, &action, &actor, &result); err != nil {
			return nil, fmt.Errorf("scan sensor activity: %w", err)
		}
		if len(details) > 0 {
			if err := json.Unmarshal(details, &it.Details); err != nil {
				it.Details = map[string]any{}
			}
		}
		if it.Details == nil {
			it.Details = map[string]any{}
		}
		if lastAt.Valid {
			t := lastAt.Time
			it.LastAt = &t
		}
		it.Category = activityCategory(it.Source, it.Type)
		if action.Valid {
			it.Action = string(audit.Action(action.String).Canonical())
			it.Details["action"] = it.Action
		}
		it.Actor, it.Result = actor.String, result.String
		items = append(items, it)
	}
	return items, rows.Err()
}

func activityCategory(source, typ string) sensor.ActivityCategory {
	switch source {
	case sensor.ActivitySourceJob:
		return sensor.CategoryJobs
	case sensor.ActivitySourceAudit:
		if typ == string(sensor.EventOnline) || typ == string(sensor.EventOffline) {
			return sensor.CategoryStatus
		}
		return sensor.CategoryPeople
	default:
		return sensor.EventType(typ).Category()
	}
}

func actionNames(actions []audit.Action) []string {
	out := make([]string, 0, len(actions))
	for _, a := range actions {
		out = append(out, a.String())
	}
	return out
}

// truncateRunes cuts s to at most n runes.
func truncateRunes(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n])
}
