package postgres

import (
	"strconv"

	"github.com/openctemio/openctem/server/pkg/domain/sensor"
)

// stoppedClaimingSQL is true when pending tenant task "commands" could be
// claimed by an organization sensor of its tenant (active, checking in, in
// its zone, with its tool, not refused, with its features) that said with
// its latest heartbeats that it takes no new jobs because of its local
// store: disk low, storage over quota or results not yet delivered
// (sensor.StoppedClaiming, the placement reason stopped_claiming).
//
// A run nobody picked up for that reason is still ended (the sensor may
// stay full for hours), but its message names the cause instead of the
// generic "check that a sensor with this scanner is online": the sensor is
// online and has the scanner. Only the tenant's own sensors are read, and
// the predicate says only whether one exists.
func stoppedClaimingSQL() string {
	// sensor.localStoreFreshFor in SQL: a stored report older than this,
	// relative to the latest heartbeat, no longer describes the sensor.
	clamped := `(CASE WHEN COALESCE(qs.heartbeat_interval_seconds, 0) <= 0 THEN ` + secondsSQL(sensor.DefaultHeartbeatInterval.Seconds()) + `
		WHEN qs.heartbeat_interval_seconds < ` + secondsSQL(sensor.MinHeartbeatInterval.Seconds()) + ` THEN ` + secondsSQL(sensor.MinHeartbeatInterval.Seconds()) + `
		WHEN qs.heartbeat_interval_seconds > ` + secondsSQL(sensor.MaxHeartbeatInterval.Seconds()) + ` THEN ` + secondsSQL(sensor.MaxHeartbeatInterval.Seconds()) + `
		ELSE qs.heartbeat_interval_seconds END)`
	fresh := `GREATEST(3 * ` + clamped + `, ` + secondsSQL(sensor.LocalStoreFreshFloor().Seconds()) + `)`
	return `(NOT COALESCE(commands.is_platform_job, FALSE) AND EXISTS (
			SELECT 1 FROM sensors qs
			WHERE qs.tenant_id = commands.tenant_id
			  AND qs.scope = 'organization' AND qs.status = 'active'
			  AND qs.health IN ` + sensorDispatchableHealthSQL + ` AND qs.last_seen_at IS NOT NULL
			  AND ` + zoneClaimPredicate("qs.id") + `
			  AND ` + toolClaimPredicate("qs.id") + `
			  AND ` + refusedByPredicate("qs.id") + `
			  AND ` + featureClaimPredicate("qs.id") + `
			  AND jsonb_typeof(qs.reported_local_store->'stop_claiming') = 'boolean'
			  AND (qs.reported_local_store->>'stop_claiming')::boolean
			  AND qs.local_store_reported_at IS NOT NULL
			  AND qs.local_store_reported_at >= qs.last_seen_at - make_interval(secs => ` + fresh + `)))`
}

func secondsSQL(s float64) string { return strconv.Itoa(int(s)) }

// stoppedClaimingHint ends the message of a run nobody picked up because
// the sensor that could run it stopped taking new jobs (no quote: it is
// placed in an SQL literal).
const stoppedClaimingHint = "the sensor that can run it is online but stopped taking new work " +
	"(low disk, full local storage or results not yet delivered): free space on the sensor host; the sensor page says which"
