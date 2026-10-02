package postgres

// Sensor load and capacity (docs/rfcs/RFC-030-scan-work-distribution.md §5.8):
// the server-side count of the commands a sensor holds, the free slots
// dispatch may use, and the load report the sensor sends on its heartbeat.

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/openctemio/api/pkg/domain/sensor"
	"github.com/openctemio/api/pkg/domain/shared"
)

// sensorActiveCommandsSQL is the number of commands the sensor aliased alias
// holds right now (acknowledged or running): the capacity truth (RFC-030 D5).
// sensors.current_jobs was never written (B1) and is no longer read.
// idx_commands_sensor bounds it to the sensor's own commands.
func sensorActiveCommandsSQL(alias string) string {
	return `(SELECT count(*) FROM commands ac
		WHERE ac.sensor_id = ` + alias + `.id AND ac.status IN ('acknowledged', 'running'))::int`
}

// loadReportFreshSQL is true when the alias's load report is recent enough
// for dispatch (sensor.LoadReportFreshness).
func loadReportFreshSQL(alias string) string {
	return fmt.Sprintf("(%s.load_reported_at > NOW() - INTERVAL '%d seconds')",
		alias, int(sensor.LoadReportFreshness/time.Second))
}

// sensorFreeSlotsSQL is how many more jobs dispatch may hand the sensor:
// effective capacity minus the commands it holds, and no more than the free
// slots a fresh load report gives. The same rule as Sensor.FreeSlots; the
// report can only lower it. A sensor without a capacity limit counts one.
func sensorFreeSlotsSQL(alias string) string {
	return `(CASE WHEN COALESCE(` + alias + `.effective_max_jobs, 0) <= 0 THEN 1 ELSE GREATEST(0, LEAST(
		` + alias + `.effective_max_jobs - ` + sensorActiveCommandsSQL(alias) + `,
		CASE WHEN ` + loadReportFreshSQL(alias) + `
		      AND jsonb_typeof(` + alias + `.reported_capacity->'slots_total') = 'number'
		      AND (` + alias + `.reported_capacity->>'slots_total')::int > 0
		      AND jsonb_typeof(` + alias + `.reported_capacity->'slots_free') = 'number'
		     THEN (` + alias + `.reported_capacity->>'slots_free')::int
		     ELSE ` + alias + `.effective_max_jobs END)) END)`
}

// sensorToolThroughputSQL is the targets per minute the alias's fresh load
// report gives for the tool bound to toolParam; NULL when unknown.
func sensorToolThroughputSQL(alias, toolParam string) string {
	return `(CASE WHEN ` + loadReportFreshSQL(alias) + `
		      AND jsonb_typeof(` + alias + `.reported_capacity->'per_tool'->` + toolParam + `::text->'throughput_targets_per_min') = 'number'
		     THEN (` + alias + `.reported_capacity->'per_tool'->` + toolParam + `::text->>'throughput_targets_per_min')::float8 END)`
}

// loadReportArgs are the UPDATE arguments of a load report; a NULL argument
// leaves its column as it is.
type loadReportArgs struct {
	resources sql.NullString
	capacity  sql.NullString
	queue     sql.NullString
	present   bool
}

func loadReportArgsOf(l *sensor.LoadReport) (loadReportArgs, error) {
	var a loadReportArgs
	if l.IsEmpty() {
		return a, nil
	}
	marshal := func(v any) (sql.NullString, error) {
		raw, err := json.Marshal(v)
		if err != nil {
			return sql.NullString{}, fmt.Errorf("failed to marshal sensor load report: %w", err)
		}
		return sql.NullString{String: string(raw), Valid: true}, nil
	}
	var err error
	if l.Resources != nil {
		if a.resources, err = marshal(l.Resources); err != nil {
			return a, err
		}
	}
	if l.Capacity != nil {
		if a.capacity, err = marshal(l.Capacity); err != nil {
			return a, err
		}
	}
	if l.Queue != nil {
		if a.queue, err = marshal(l.Queue); err != nil {
			return a, err
		}
	}
	a.present = true
	return a, nil
}

// scanLoadReport builds the stored load report from its columns. A part that
// does not decode is dropped (logged), never fatal to reading the sensor.
func scanLoadReport(id shared.ID, resources, capacity, queue []byte, at sql.NullTime) sensor.LoadReport {
	var l sensor.LoadReport
	if len(resources) > 0 {
		var r sensor.ReportedResources
		if err := json.Unmarshal(resources, &r); err != nil {
			log.Printf("[DEBUG] failed to unmarshal sensor reported resources (id=%s): %v", id, err)
		} else {
			l.Resources = &r
		}
	}
	if len(capacity) > 0 {
		var c sensor.ReportedCapacity
		if err := json.Unmarshal(capacity, &c); err != nil {
			log.Printf("[DEBUG] failed to unmarshal sensor reported capacity (id=%s): %v", id, err)
		} else {
			l.Capacity = &c
		}
	}
	if len(queue) > 0 {
		var q sensor.ReportedQueue
		if err := json.Unmarshal(queue, &q); err != nil {
			log.Printf("[DEBUG] failed to unmarshal sensor reported queue (id=%s): %v", id, err)
		} else {
			l.Queue = &q
		}
	}
	if at.Valid {
		t := at.Time
		l.ReportedAt = &t
	}
	return l
}
