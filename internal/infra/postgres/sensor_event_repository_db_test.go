package postgres

// sensor_events (migration 000255) and the merged sensor timeline: coalescing
// of identical consecutive events, the hourly cap, retention, and the read
// over events, commands and audit rows (including rows written before the
// agent -> sensor rename), paginated by cursor and scoped to the tenant.

import (
	"context"
	"database/sql"
	"fmt"
	"testing"
	"time"

	"github.com/openctemio/api/pkg/domain/sensor"
	"github.com/openctemio/api/pkg/domain/shared"
)

func eventAt(tid, sid shared.ID, typ sensor.EventType, at time.Time, summary string) sensor.Event {
	return sensor.NewEvent(tid, sid, typ, at, summary, map[string]any{"k": "v"})
}

func countEvents(ctx context.Context, t *testing.T, db *sql.DB, sid shared.ID) (rows, repeats int) {
	t.Helper()
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*), COALESCE(SUM(repeat_count), 0) FROM sensor_events WHERE sensor_id = $1`,
		sid.String()).Scan(&rows, &repeats); err != nil {
		t.Fatal(err)
	}
	return rows, repeats
}

func TestSensorEvents_CoalesceAndCap_DB(t *testing.T) {
	db := openSensorDB(t)
	ctx := context.Background()
	repo := NewSensorEventRepository(&DB{DB: db})
	tid := seedTestTenant(ctx, t, db)
	sid := seedSensor(ctx, t, db, tid, "online", nil, "nuclei", 0)
	limits := sensor.EventLimits{CoalesceWindow: 10 * time.Minute, MaxPerHour: 5}
	base := time.Now().Add(-2 * time.Hour).Truncate(time.Second)

	record := func(e sensor.Event, want sensor.EventWriteResult) {
		t.Helper()
		got, err := repo.Record(ctx, e, limits)
		if err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Fatalf("%s at %s: %s, want %s", e.Type, e.At.Format(time.TimeOnly), got, want)
		}
	}

	// A crash loop: restarts with different downtimes fold into one row
	// (status events fold on the type alone).
	record(eventAt(tid, sid, sensor.EventRestarted, base, "restarted (down 5s)"), sensor.EventInserted)
	record(eventAt(tid, sid, sensor.EventRestarted, base.Add(time.Minute), "restarted (down 7s)"), sensor.EventCoalesced)
	record(eventAt(tid, sid, sensor.EventRestarted, base.Add(2*time.Minute), "restarted (down 9s)"), sensor.EventCoalesced)
	if rows, reps := countEvents(ctx, t, db, sid); rows != 1 || reps != 3 {
		t.Fatalf("crash loop: %d rows, %d occurrences", rows, reps)
	}
	// Outside the window (measured from the last occurrence): a new row.
	record(eventAt(tid, sid, sensor.EventRestarted, base.Add(13*time.Minute), "restarted"), sensor.EventInserted)

	// Alternating online/offline is not consecutive: each is a row, until the
	// hourly status budget (5) is spent.
	record(eventAt(tid, sid, sensor.EventOffline, base.Add(14*time.Minute), "offline"), sensor.EventInserted)
	record(eventAt(tid, sid, sensor.EventOnline, base.Add(15*time.Minute), "online"), sensor.EventInserted)
	record(eventAt(tid, sid, sensor.EventOffline, base.Add(16*time.Minute), "offline"), sensor.EventInserted)
	record(eventAt(tid, sid, sensor.EventOnline, base.Add(17*time.Minute), "online"), sensor.EventDropped)

	// The updates budget is separate, and updates fold only when the summary
	// is the same.
	record(eventAt(tid, sid, sensor.EventVersionChanged, base.Add(18*time.Minute), "v0.4.1 -> v0.4.2"), sensor.EventInserted)
	record(eventAt(tid, sid, sensor.EventVersionChanged, base.Add(19*time.Minute), "v0.4.1 -> v0.4.2"), sensor.EventCoalesced)
	record(eventAt(tid, sid, sensor.EventVersionChanged, base.Add(20*time.Minute), "v0.4.2 -> v0.5.0"), sensor.EventInserted)

	var lastAt sql.NullTime
	var repeat int
	if err := db.QueryRowContext(ctx, `SELECT repeat_count, last_at FROM sensor_events WHERE sensor_id = $1 AND type = 'restarted' ORDER BY at LIMIT 1`,
		sid.String()).Scan(&repeat, &lastAt); err != nil {
		t.Fatal(err)
	}
	if repeat != 3 || !lastAt.Valid || !lastAt.Time.Equal(base.Add(2*time.Minute)) {
		t.Errorf("coalesced row: repeat %d last_at %v", repeat, lastAt)
	}

	// Retention removes what is older than the cutoff.
	n, err := repo.DeleteOlderThan(ctx, base.Add(15*time.Minute), 100)
	if err != nil {
		t.Fatal(err)
	}
	if n != 3 { // the crash-loop row, the second restart, the first offline
		t.Errorf("retention deleted %d rows, want 3", n)
	}
}

func TestSensorActivity_MergedTimeline_DB(t *testing.T) {
	db := openSensorDB(t)
	ctx := context.Background()
	repo := NewSensorEventRepository(&DB{DB: db})
	tid := seedTestTenant(ctx, t, db)
	sid := seedSensor(ctx, t, db, tid, "online", nil, "nuclei", 0)
	otherTenant := seedTestTenant(ctx, t, db)
	t.Cleanup(func() {
		for _, id := range []shared.ID{tid, otherTenant} {
			_, _ = db.ExecContext(context.Background(), `DELETE FROM commands WHERE tenant_id = $1`, id.String())
			_, _ = db.ExecContext(context.Background(), `DELETE FROM audit_logs WHERE tenant_id = $1`, id.String())
		}
	})
	base := time.Now().Add(-3 * time.Hour).Truncate(time.Second)
	at := func(m int) time.Time { return base.Add(time.Duration(m) * time.Minute) }
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := db.ExecContext(ctx, q, args...); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	audit := func(m int, action, resourceType, actor string) {
		exec(`INSERT INTO audit_logs (id, tenant_id, actor_email, action, resource_type, resource_id, resource_name, result, severity, message, logged_at)
		      VALUES ($1, $2, NULLIF($3, ''), $4, $5, $6, 'probe', 'success', 'low', $7, $8)`,
			shared.NewID().String(), tid.String(), actor, action, resourceType, sid.String(), "msg "+action, at(m))
	}

	// Historical rows written before the rename, and current ones.
	audit(1, "agent.created", "agent", "admin@it.test")
	audit(2, "agent.connected", "agent", "system")
	audit(30, "sensor.updated", "sensor", "admin@it.test")
	// A connect the server also wrote as an online event: shown once.
	audit(40, "sensor.connected", "sensor", "system")
	for _, e := range []sensor.Event{
		eventAt(tid, sid, sensor.EventOnline, at(40), "Came online"),
		eventAt(tid, sid, sensor.EventVersionChanged, at(41), "version"),
		eventAt(tid, sid, sensor.EventProtocolChanged, at(42), "protocol"),
	} {
		if _, err := repo.Record(ctx, e, sensor.DefaultEventLimits()); err != nil {
			t.Fatal(err)
		}
	}
	// A job claimed at 50, failed at 55; one still pending (no item).
	cmd := shared.NewID()
	exec(`INSERT INTO commands (id, tenant_id, sensor_id, type, status, error_message, acknowledged_at, started_at, completed_at, payload)
	      VALUES ($1, $2, $3, 'scan', 'failed', 'nuclei exited 2', $4, $4, $5, '{"scanner":"nuclei"}')`,
		cmd.String(), tid.String(), sid.String(), at(50), at(55))
	exec(`INSERT INTO commands (id, tenant_id, sensor_id, type, status) VALUES ($1, $2, $3, 'scan', 'pending')`,
		shared.NewID().String(), tid.String(), sid.String())
	// Another tenant's rows about the same sensor id never appear.
	exec(`INSERT INTO audit_logs (id, tenant_id, actor_email, action, resource_type, resource_id, result, severity, logged_at)
	      VALUES ($1, $2, 'x@other.test', 'sensor.updated', 'sensor', $3, 'success', 'low', $4)`,
		shared.NewID().String(), otherTenant.String(), sid.String(), at(60))

	all := sensor.AllCategories()
	list := func(q sensor.ActivityQuery) []sensor.ActivityItem {
		t.Helper()
		items, err := repo.ListActivity(ctx, q)
		if err != nil {
			t.Fatal(err)
		}
		return items
	}
	keys := func(items []sensor.ActivityItem) string {
		s := ""
		for _, it := range items {
			s += fmt.Sprintf("%s/%s ", it.Category, it.Type)
		}
		return s
	}

	// Administrator view: everything, newest first.
	full := list(sensor.ActivityQuery{TenantID: tid, SensorID: sid, Categories: all, IncludeAudit: true, Limit: 50})
	want := "jobs/job_failed jobs/job_claimed updates/protocol_changed updates/version_changed status/online people/audit status/online people/audit "
	if got := keys(full); got != want {
		t.Fatalf("timeline:\n got %s\nwant %s", got, want)
	}
	// The historical rows come back under their current names.
	hist := full[len(full)-1]
	if hist.Action != "sensor.created" || hist.Actor != "admin@it.test" || hist.Source != sensor.ActivitySourceAudit {
		t.Errorf("historical row %+v", hist)
	}
	if conn := full[len(full)-2]; conn.Source != sensor.ActivitySourceAudit || conn.Action != "sensor.connected" || conn.Actor != "system" {
		t.Errorf("historical connect %+v", conn)
	}
	failed := full[0]
	if failed.Details["error"] != "nuclei exited 2" || failed.Details["tool"] != "nuclei" ||
		failed.Details["duration_seconds"] != float64(300) || failed.Details["command_id"] != cmd.String() {
		t.Errorf("job item %+v", failed.Details)
	}

	// Without audit:read, no audit row at all.
	member := list(sensor.ActivityQuery{TenantID: tid, SensorID: sid, Categories: all, IncludeAudit: false, Limit: 50})
	for _, it := range member {
		if it.Source == sensor.ActivitySourceAudit {
			t.Errorf("member saw an audit item %+v", it)
		}
	}
	if len(member) != 5 {
		t.Errorf("member timeline: %s", keys(member))
	}

	// Category filters.
	if got := keys(list(sensor.ActivityQuery{TenantID: tid, SensorID: sid, Categories: []sensor.ActivityCategory{sensor.CategoryPeople}, IncludeAudit: true, Limit: 50})); got != "people/audit people/audit " {
		t.Errorf("people: %s", got)
	}
	if got := keys(list(sensor.ActivityQuery{TenantID: tid, SensorID: sid, Categories: []sensor.ActivityCategory{sensor.CategoryStatus}, IncludeAudit: true, Limit: 50})); got != "status/online status/online " {
		t.Errorf("status: %s", got)
	}

	// Pages of 3 walk the whole timeline without gaps or repeats.
	var walked []sensor.ActivityItem
	var cursor *sensor.ActivityCursor
	for i := 0; i < 10; i++ {
		page := list(sensor.ActivityQuery{TenantID: tid, SensorID: sid, Categories: all, IncludeAudit: true, Limit: 3, After: cursor})
		if len(page) > 3 {
			last := page[2]
			walked = append(walked, page[:3]...)
			c, err := sensor.ParseActivityCursor(sensor.ActivityCursor{At: last.At, Key: last.Key}.Encode())
			if err != nil {
				t.Fatal(err)
			}
			cursor = c
			continue
		}
		walked = append(walked, page...)
		break
	}
	if keys(walked) != want {
		t.Errorf("paged walk:\n got %s\nwant %s", keys(walked), want)
	}

	// Another tenant asking for this sensor id gets nothing of it.
	if got := list(sensor.ActivityQuery{TenantID: otherTenant, SensorID: sid, Categories: all, IncludeAudit: true, Limit: 50}); len(got) != 1 ||
		got[0].Actor != "x@other.test" {
		t.Errorf("other tenant: %s", keys(got))
	}
}
