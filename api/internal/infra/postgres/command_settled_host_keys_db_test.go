package postgres

import (
	"context"
	"database/sql"
	"slices"
	"testing"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/pkg/domain/command"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// A running command frees each host as its targets settle (research/130):
// the holder's heartbeat names the keys it released, and a pending command
// on those hosts is offered and claimable before the holder ends. Only
// keys of the holder itself, reported by the sensor that holds it, count;
// a claim starts over with every host held. Requires DATABASE_URL.

func settledKeys(ctx context.Context, t *testing.T, db *sql.DB, id shared.ID) []string {
	t.Helper()
	var keys []string
	if err := db.QueryRowContext(ctx, `SELECT settled_host_keys FROM commands WHERE id = $1`, id.String()).Scan(pq.Array(&keys)); err != nil {
		t.Fatal(err)
	}
	return keys
}

func TestCommandHostKeys_ReleasedPerTarget(t *testing.T) {
	sqlDB := openSensorDB(t)
	ctx := context.Background()
	cmds := NewCommandRepository(&DB{DB: sqlDB})
	tenant := seedTestTenant(ctx, t, sqlDB)
	a := seedZoneSensor(ctx, t, sqlDB, &tenant, "a", zoneSensorOpts{tools: []string{"httpx"}})
	b := seedZoneSensor(ctx, t, sqlDB, &tenant, "b", zoneSensorOpts{tools: []string{"httpx"}})
	ha, hb, hc := "a-"+uniqueTestHostSuffix(), "b-"+uniqueTestHostSuffix(), "c-"+uniqueTestHostSuffix()

	httpx := createHostChunk(ctx, t, cmds, tenant, ha, hb, hc)
	if ok, err := cmds.ClaimForSensor(ctx, tenant, httpx, a.String()); err != nil || !ok {
		t.Fatalf("httpx not claimed: %v %v", ok, err)
	}
	onA := createHostChunk(ctx, t, cmds, tenant, ha)
	onB := createHostChunk(ctx, t, cmds, tenant, hb)
	if got := polledIDs(ctx, t, cmds, tenant, b); got[onA] || got[onB] {
		t.Fatalf("offered %v while httpx holds every host", got)
	}

	report := func(sensor shared.ID, keys ...string) {
		t.Helper()
		if _, err := cmds.RecordProgress(ctx, tenant, sensor, map[string]command.Progress{
			httpx.String(): {Done: 1, Total: 3, ReleasedKeys: keys},
		}); err != nil {
			t.Fatal(err)
		}
	}
	// Another sensor of the tenant cannot free httpx's hosts; nor can a
	// key the command never held be recorded.
	report(b, hb)
	if keys := settledKeys(ctx, t, sqlDB, httpx); keys != nil {
		t.Fatalf("a sensor that does not hold httpx released %v", keys)
	}
	report(a, ha, "not-a-key-of-this-command", "")
	if keys := settledKeys(ctx, t, sqlDB, httpx); !slices.Equal(keys, []string{ha}) {
		t.Fatalf("settled = %v, want [%s]", keys, ha)
	}

	got := polledIDs(ctx, t, cmds, tenant, b)
	if !got[onA] || got[onB] {
		t.Fatalf("offered %v: want the command on the settled host only", got)
	}
	assertPollParity(ctx, t, cmds, tenant, b, nil, len(got))
	if ok, err := cmds.ClaimForSensor(ctx, tenant, onB, b.String()); err != nil || ok {
		t.Fatalf("claimed a command on a host httpx still holds: %v %v", ok, err)
	}
	if ok, err := cmds.ClaimForSensor(ctx, tenant, onA, b.String()); err != nil || !ok {
		t.Fatalf("command on the settled host not claimed: %v %v", ok, err)
	}

	// Released keys only grow within the claim.
	report(a, hb)
	if keys := settledKeys(ctx, t, sqlDB, httpx); len(keys) != 2 {
		t.Fatalf("settled = %v, want both reports", keys)
	}

	// httpx is re-queued and claimed again: it holds every host again.
	if _, err := sqlDB.ExecContext(ctx, `UPDATE commands SET status = 'pending', sensor_id = NULL WHERE id = $1`, httpx.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := sqlDB.ExecContext(ctx, `UPDATE commands SET status = 'completed' WHERE id = $1`, onA.String()); err != nil {
		t.Fatal(err)
	}
	if ok, err := cmds.ClaimForSensor(ctx, tenant, httpx, a.String()); err != nil || !ok {
		t.Fatalf("httpx not claimed again: %v %v", ok, err)
	}
	if keys := settledKeys(ctx, t, sqlDB, httpx); keys != nil {
		t.Fatalf("a new claim kept the released hosts %v", keys)
	}
	if polledIDs(ctx, t, cmds, tenant, b)[onB] {
		t.Fatal("a re-claimed command does not hold its hosts again")
	}
}

// A range holder that released the bucket's range key frees an address job
// of that bucket; one that released only other keys does not.
func TestCommandHostKeys_ReleasedRangeBucket(t *testing.T) {
	sqlDB := openSensorDB(t)
	ctx := context.Background()
	cmds := NewCommandRepository(&DB{DB: sqlDB})
	tenant := seedTestTenant(ctx, t, sqlDB)
	a := seedZoneSensor(ctx, t, sqlDB, &tenant, "a", zoneSensorOpts{tools: []string{"httpx"}})
	b := seedZoneSensor(ctx, t, sqlDB, &tenant, "b", zoneSensorOpts{tools: []string{"httpx"}})

	ranges := createHostChunk(ctx, t, cmds, tenant, "net:192.0.2.0/24", "net:198.18.0.0/24")
	if ok, err := cmds.ClaimForSensor(ctx, tenant, ranges, a.String()); err != nil || !ok {
		t.Fatalf("range chunk not claimed: %v %v", ok, err)
	}
	addr := createHostChunk(ctx, t, cmds, tenant, "192.0.2.9", "in:192.0.2.0/24")
	if _, err := cmds.RecordProgress(ctx, tenant, a, map[string]command.Progress{
		ranges.String(): {Done: 1, Total: 2, ReleasedKeys: []string{"net:198.18.0.0/24"}},
	}); err != nil {
		t.Fatal(err)
	}
	if polledIDs(ctx, t, cmds, tenant, b)[addr] {
		t.Fatal("an address job was offered while the range of its bucket is held")
	}
	if _, err := cmds.RecordProgress(ctx, tenant, a, map[string]command.Progress{
		ranges.String(): {Done: 2, Total: 2, ReleasedKeys: []string{"net:192.0.2.0/24"}},
	}); err != nil {
		t.Fatal(err)
	}
	if !polledIDs(ctx, t, cmds, tenant, b)[addr] {
		t.Fatal("the address job was not offered once the range of its bucket was released")
	}
}

// get_next_platform_job applies the same holder rule.
func TestGetNextPlatformJob_HonoursReleasedHosts(t *testing.T) {
	db := openPlatformJobDB(t)
	ctx := context.Background()
	tenant := seedTestTenant(ctx, t, db)
	sensorID := seedJobSensor(ctx, t, db, tenant)

	withIsolatedPlatformQueue(ctx, t, db, []shared.ID{tenant}, func(tx *sql.Tx) error {
		insert := func(status string, platform bool, settled []string, keys ...string) shared.ID {
			t.Helper()
			id := shared.NewID()
			if _, err := tx.ExecContext(ctx, `
				INSERT INTO commands (id, tenant_id, type, priority, payload, status, is_platform_job, queue_priority, queued_at, host_keys, settled_host_keys)
				VALUES ($1, $2, 'scan', 'normal', '{"scanner":"naabu"}'::jsonb, $3, $4, 1, NOW(), $5, $6)`,
				id.String(), tenant.String(), status, platform, pq.Array(keys), pq.Array(settled)); err != nil {
				t.Fatalf("seed command: %v", err)
			}
			return id
		}
		insert("running", false, []string{"a.example.com"}, "a.example.com", "b.example.com")
		onB := insert("pending", true, nil, "b.example.com")
		if got, err := claimPlatformJobTx(ctx, tx, sensorID, nil, []string{"naabu"}); err != nil || !got.IsZero() {
			t.Fatalf("claimed %s (%v) on a host still held", got, err)
		}
		onA := insert("pending", true, nil, "a.example.com")
		if got, err := claimPlatformJobTx(ctx, tx, sensorID, nil, []string{"naabu"}); err != nil || got != onA {
			t.Fatalf("claimed %s (%v), want the job on the released host %s", got, err, onA)
		}
		_ = onB
		return nil
	})
}

// uniqueTestHostSuffix makes a host name no other test names.
func uniqueTestHostSuffix() string { return shared.NewID().String() + ".example.test" }
