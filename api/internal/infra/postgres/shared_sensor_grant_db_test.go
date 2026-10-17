package postgres

import (
	"context"
	"database/sql"
	"slices"
	"testing"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// A shared sensor serves many organizations, so its grant is least
// privilege whatever writes it: never tenant credentials, never unsolicited
// (push) results, never intrusive (T2) probes, public targets only, and no
// remote binary update. Before, the sensors insert trigger gave such a row
// legacy-broad with credentials, push ingest and tier 2. The clamp holds for
// the default grant and for a later grant edit, and a sensor cannot become
// shared after it was created. Requires DATABASE_URL.
func TestSharedSensorGrant_LeastPrivilege(t *testing.T) {
	sqlDB := openSensorDB(t)
	ctx := context.Background()
	tenant := seedTestTenant(ctx, t, sqlDB)

	// The default grant of a new shared sensor.
	created := seedZoneSensor(ctx, t, sqlDB, &tenant, "shared-new", zoneSensorOpts{platform: true})
	assertSharedGrant(ctx, t, sqlDB, created, "default grant")

	// A later edit cannot widen it.
	if _, err := sqlDB.ExecContext(ctx, `
		UPDATE sensor_grants
		SET allow_credentials = TRUE, allow_push_ingest = TRUE, tier_ceiling = 2,
		    target_network = 'any', remote_actions = ARRAY['update', 'diagnostics'],
		    profile = 'legacy-broad', version = version + 1
		WHERE sensor_id = $1`, created.String()); err != nil {
		t.Fatal(err)
	}
	assertSharedGrant(ctx, t, sqlDB, created, "after a widening edit")

	// A sensor's scope is fixed at creation: an organization sensor with a
	// broad grant cannot be turned into a shared one.
	flipped := seedZoneSensor(ctx, t, sqlDB, &tenant, "flipped", zoneSensorOpts{})
	if _, err := sqlDB.ExecContext(ctx, `UPDATE sensors SET scope = 'instance', tenant_id = NULL WHERE id = $1`,
		flipped.String()); err == nil {
		t.Fatal("an organization sensor became a shared sensor")
	}

	// Organization sensors keep what their administrators grant them.
	org := seedZoneSensor(ctx, t, sqlDB, &tenant, "org", zoneSensorOpts{})
	if _, err := sqlDB.ExecContext(ctx, `
		UPDATE sensor_grants SET allow_credentials = TRUE, tier_ceiling = 2 WHERE sensor_id = $1`,
		org.String()); err != nil {
		t.Fatal(err)
	}
	var creds bool
	var tier int
	if err := sqlDB.QueryRowContext(ctx, `SELECT allow_credentials, tier_ceiling FROM sensor_grants WHERE sensor_id = $1`,
		org.String()).Scan(&creds, &tier); err != nil {
		t.Fatal(err)
	}
	if !creds || tier != 2 {
		t.Errorf("organization sensor grant was narrowed: credentials=%v tier=%d", creds, tier)
	}
}

func assertSharedGrant(ctx context.Context, t *testing.T, db *sql.DB, sensorID shared.ID, when string) {
	t.Helper()
	var (
		profile, network string
		creds, push      bool
		tier             int
		actions          []string
	)
	err := db.QueryRowContext(ctx, `
		SELECT profile, target_network, allow_credentials, allow_push_ingest, tier_ceiling, remote_actions
		FROM sensor_grants WHERE sensor_id = $1`, sensorID.String()).
		Scan(&profile, &network, &creds, &push, &tier, pq.Array(&actions))
	if err != nil {
		t.Fatalf("%s: read grant: %v", when, err)
	}
	if creds || push || tier > 1 || network != "public" || slices.Contains(actions, "update") || profile == "legacy-broad" {
		t.Errorf("%s: shared sensor grant profile=%s network=%s credentials=%v push=%v tier=%d actions=%v; "+
			"want no credentials, no push, tier <= 1, public targets, no update, not legacy-broad",
			when, profile, network, creds, push, tier, actions)
	}
}

// A shared sensor's grant covers scan, validate and retest only: no limit
// (NULL) becomes exactly those, any other list its intersection with them.
// An organization sensor keeps the job types its administrators set.
// Requires DATABASE_URL.
func TestSharedSensorGrant_JobTypesClamped(t *testing.T) {
	sqlDB := openSensorDB(t)
	ctx := context.Background()
	tenant := seedTestTenant(ctx, t, sqlDB)
	sharedID := seedZoneSensor(ctx, t, sqlDB, &tenant, "shared-jobs", zoneSensorOpts{platform: true})
	org := seedZoneSensor(ctx, t, sqlDB, &tenant, "org-jobs", zoneSensorOpts{})

	jobTypes := func(id string) []string {
		t.Helper()
		var out []string
		var raw pq.StringArray
		if err := sqlDB.QueryRowContext(ctx, `SELECT job_types FROM sensor_grants WHERE sensor_id = $1`, id).Scan(&raw); err != nil {
			t.Fatal(err)
		}
		if raw == nil {
			return nil
		}
		out = append(out, raw...)
		return out
	}
	set := func(id string, v any) {
		t.Helper()
		if _, err := sqlDB.ExecContext(ctx, `UPDATE sensor_grants SET job_types = $2, version = version + 1 WHERE sensor_id = $1`, id, v); err != nil {
			t.Fatal(err)
		}
	}

	set(sharedID.String(), nil)
	if got := jobTypes(sharedID.String()); !slices.Equal(got, []string{"retest", "scan", "validate"}) {
		t.Errorf("shared, no limit: %v", got)
	}
	set(sharedID.String(), pq.Array([]string{"collect", "connector_sync", "scan"}))
	if got := jobTypes(sharedID.String()); !slices.Equal(got, []string{"scan"}) {
		t.Errorf("shared, collect+connector_sync+scan: %v", got)
	}
	set(sharedID.String(), pq.Array([]string{"collect"}))
	if got := jobTypes(sharedID.String()); len(got) != 0 {
		t.Errorf("shared, collect only: %v, want empty", got)
	}

	set(org.String(), pq.Array([]string{"collect", "connector_sync", "scan"}))
	if got := jobTypes(org.String()); !slices.Equal(got, []string{"collect", "connector_sync", "scan"}) {
		t.Errorf("organization sensor job types narrowed: %v", got)
	}
	set(org.String(), nil)
	if got := jobTypes(org.String()); got != nil {
		t.Errorf("organization sensor no-limit changed: %v", got)
	}
}
