package postgres

// Short and long work on one sensor (docs/architecture/job-dispatch.md,
// "Fair order").
//
// The poll used to order an organization's pending commands by priority
// class (with aging) and age alone. A batch of long jobs queued first (a
// vulnerability scan of every host, about half an hour each) then held every
// slot of a sensor until the whole batch had run, and a discovery run queued
// an hour later (DNS, RDAP and ASN lookups of a few seconds each) waited the
// hours that took: aging lifts both to the same class, and the older batch
// wins every tie (prod 2026-11-04: 4 h 41 min before the first lookup ran).
//
// Each claiming sensor now splits its candidates into two lanes by the
// time a job is expected to take on that sensor: its targets at the
// sensor's measured speed for the tool (the load report's targets per
// minute), "short" up to shortJobSeconds, "long" otherwise or when the
// speed is unknown. The lanes share the sensor's time: while short jobs used
// no more of it than long jobs in the last laneShareWindowSeconds, short
// jobs go first (lifted to the highest class aging gives, never into
// critical); once they used more, long jobs go first within each class.
// Short work therefore starts at the next free slot however long the queue
// of long work is, and long work keeps at least half of the sensor's time
// however much short work arrives. Without a fresh load report every job is
// "long" and the order is the previous one.
//
// The lanes only reorder the commands a sensor may claim: the predicates
// (tenant, routing, pin, zone, tool, capabilities, features, refusals,
// hosts), the holds after the query and the slot cap are unchanged. Every
// read is scoped to the claiming sensor's own tenant ($1) and the sensor
// itself ($2): another organization's commands or sensors never count.

import (
	"fmt"
	"strconv"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/sensor"
)

const (
	// shortJobSeconds is the longest a job may be expected to take on the
	// claiming sensor and still be short work.
	shortJobSeconds = 300
	// laneShareWindowSeconds is the window over which the lanes' use of a
	// sensor's time is compared.
	laneShareWindowSeconds = 3600
)

// laneSensorCTE is the claiming sensor's per-tool speeds: its load report's
// per_tool when the report is fresh, else NULL (every job then long). One
// row always, also for a sensor that is not the tenant's.
var laneSensorCTE = `lane_sensor AS (
			SELECT (SELECT CASE WHEN ls.load_reported_at > NOW() - INTERVAL '` +
	strconv.Itoa(int(sensor.LoadReportFreshness/time.Second)) + ` seconds'
			                    THEN ls.reported_capacity->'per_tool' END
			        FROM sensors ls WHERE ls.id = $2 AND ls.tenant_id = $1) AS per_tool
		)`

// shortJobSQL is true when command alias c is expected to take at most
// shortJobSeconds on the claiming sensor (lane_sensor.per_tool): its targets
// at the measured targets per minute of its tool. NULL speed, a speed that
// is not a positive number, or no tool: false. The nested CASE keeps the
// cast behind the type check.
func shortJobSQL(c string) string {
	speed := `lane_sensor.per_tool->(` + commandToolSQLOf(c) + `)->'throughput_targets_per_min'`
	targets := `GREATEST(CASE WHEN jsonb_typeof(` + c + `.payload->'targets') = 'array'
			THEN jsonb_array_length(` + c + `.payload->'targets') ELSE 1 END, 1)`
	return `COALESCE((CASE WHEN jsonb_typeof(` + speed + `) = 'number' THEN
			CASE WHEN (` + speed + `)::text::float8 > 0
			     THEN 60.0 * ` + targets + ` / (` + speed + `)::text::float8 END END) <= ` +
		strconv.Itoa(shortJobSeconds) + `, FALSE)`
}

// laneBusySeconds is the seconds of the window command alias b held the
// claiming sensor: from its claim (or the window's start) to its end (or
// now, while held).
func laneBusySeconds(b string) string {
	return `EXTRACT(EPOCH FROM (
			CASE WHEN ` + b + `.status IN ('acknowledged', 'running') THEN NOW() ELSE COALESCE(` + b + `.completed_at, NOW()) END
			- GREATEST(` + b + `.acknowledged_at, NOW() - INTERVAL '` + strconv.Itoa(laneShareWindowSeconds) + ` seconds')))`
}

// laneBusyCTE is the time short and long scan jobs held the claiming sensor
// in the last laneShareWindowSeconds: jobs that ended or were claimed in the
// window (idx_commands_sensor_activity), plus jobs it still holds that it
// claimed before the window.
var laneBusyCTE = fmt.Sprintf(`lane_busy AS (
			SELECT COALESCE(SUM(sec) FILTER (WHERE short), 0) AS short_s,
			       COALESCE(SUM(sec) FILTER (WHERE NOT short), 0) AS long_s
			FROM (
				SELECT %[1]s AS short, %[2]s AS sec
				FROM commands b CROSS JOIN lane_sensor
				WHERE b.tenant_id = $1 AND b.sensor_id = $2 AND b.type = 'scan'
				  AND b.acknowledged_at IS NOT NULL
				  AND COALESCE(b.completed_at, b.acknowledged_at) > NOW() - INTERVAL '%[3]d seconds'
				UNION ALL
				SELECT %[1]s, %[2]s
				FROM commands b CROSS JOIN lane_sensor
				WHERE b.tenant_id = $1 AND b.sensor_id = $2 AND b.type = 'scan'
				  AND b.status IN ('acknowledged', 'running')
				  AND b.completed_at IS NULL
				  AND b.acknowledged_at <= NOW() - INTERVAL '%[3]d seconds'
			) used
			WHERE sec > 0
		)`, shortJobSQL("b"), laneBusySeconds("b"), laneShareWindowSeconds)

// noLaneCTEs stand in for laneSensorCTE and laneBusyCTE on a poll without a
// sensor identity: no speeds, so every job is long.
const noLaneCTEs = `lane_sensor AS (SELECT NULL::jsonb AS per_tool),
		lane_busy AS (SELECT 0::float8 AS short_s, 0::float8 AS long_s)`

// runHeldCTE counts, for every run among the candidates, the commands of it
// the tenant's sensors hold now. The round-robin across runs starts a run at
// that count, so a run that already has jobs running yields to one that has
// none; ranking the pending commands alone made it first-come-first-served
// whenever a claim takes one command at a time.
const runHeldCTE = `run_held AS (
			SELECT r.c_run, (SELECT count(*) FROM commands h
			                 WHERE h.tenant_id = $1 AND h.payload->>'scan_run_id' = r.c_run
			                   AND h.status IN ('acknowledged', 'running'))::int AS n
			FROM (SELECT DISTINCT c_run FROM cand) r
		)`
