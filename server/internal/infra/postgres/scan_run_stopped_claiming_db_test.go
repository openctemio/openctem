package postgres

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/openctem/server/pkg/domain/shared"
)

// A run nobody picked up because the tenant's sensor stopped taking new
// work (its local store is full: the live case was a host disk under 15 %
// free) says so instead of "check that a sensor with this scanner is
// online": the sensor is online and has the scanner. A stale report, and
// another tenant's sensor, never change the message.
func TestAbortUnclaimedRuns_NamesStoppedClaiming(t *testing.T) {
	ctx := context.Background()
	db := openSensorDB(t)
	repo := NewScanRunRepository(&DB{DB: db})

	type tc struct {
		run    shared.ID
		want   string
		reason string
	}
	var cases []tc
	seed := func(reason, want string, store func(tenant shared.ID)) {
		t.Helper()
		tenant := seedTestTenant(ctx, t, db)
		scanID := seedRetryScan(ctx, t, db, tenant, 0)
		run := seedActiveRun(ctx, t, db, tenant, scanID, "manual", 2*time.Hour)
		seedRunCommand(ctx, t, db, tenant, run, "pending", false, 0)
		store(tenant)
		cases = append(cases, tc{run: run, want: want, reason: reason})
	}
	stopped := func(tenant shared.ID, reportedAgo time.Duration) {
		t.Helper()
		id := seedZoneSensor(ctx, t, db, &tenant, "full-"+tenant.String()[:8], zoneSensorOpts{})
		if _, err := db.ExecContext(ctx, `
			UPDATE sensors SET reported_local_store = '{"level":"high","stop_claiming":true,"reason":"11 % of the volume free, below 15 %"}'::jsonb,
			       local_store_reported_at = last_seen_at - make_interval(secs => $2)
			WHERE id = $1`, id.String(), int(reportedAgo.Seconds())); err != nil {
			t.Fatal(err)
		}
	}

	seed("fresh stop_claiming report", "stopped taking new work", func(tenant shared.ID) { stopped(tenant, time.Minute) })
	seed("stale report", "check that a sensor", func(tenant shared.ID) { stopped(tenant, time.Hour) })
	seed("sensor claims normally", "check that a sensor", func(tenant shared.ID) {
		seedZoneSensor(ctx, t, db, &tenant, "ok-"+tenant.String()[:8], zoneSensorOpts{})
	})
	// Cross-tenant: the full sensor belongs to another organization.
	seed("another tenant's sensor stopped", "check that a sensor", func(shared.ID) {
		stopped(seedTestTenant(ctx, t, db), time.Minute)
	})

	if _, err := repo.AbortUnclaimedRuns(ctx, 4*time.Hour, time.Hour); err != nil {
		t.Fatal(err)
	}
	for _, c := range cases {
		status, msg := runStatus(ctx, t, db, c.run)
		if status != "failed" {
			t.Errorf("%s: run %s, want failed", c.reason, status)
			continue
		}
		if !strings.Contains(msg.String, c.want) {
			t.Errorf("%s: message %q, want it to contain %q", c.reason, msg.String, c.want)
		}
		if c.want != "stopped taking new work" && strings.Contains(msg.String, "stopped taking new work") {
			t.Errorf("%s: message %q names a stop it has no evidence of", c.reason, msg.String)
		}
	}
}
