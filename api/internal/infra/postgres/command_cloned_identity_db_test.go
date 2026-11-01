package postgres

import (
	"context"
	"database/sql"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// A sensor flagged as a cloned identity (two hosts use one key) gets no new
// work on any lease-granting path, and the heartbeat doorbell stops ringing
// for it; a sensor of the same tenant without the flag still gets the work,
// and clearing the flag (re-pair) gives the sensor work again. Requires
// DATABASE_URL (CI applies every migration first).

func setIdentityCloned(ctx context.Context, t *testing.T, db *sql.DB, sensor shared.ID, cloned bool) {
	t.Helper()
	q := `UPDATE sensors SET identity_cloned_at = NOW() WHERE id = $1`
	if !cloned {
		q = `UPDATE sensors SET identity_cloned_at = NULL WHERE id = $1`
	}
	if _, err := db.ExecContext(ctx, q, sensor.String()); err != nil {
		t.Fatalf("set identity_cloned_at: %v", err)
	}
}

func TestClaim_ClonedIdentityGetsNoNewWork(t *testing.T) {
	sqlDB := openSensorDB(t)
	ctx := context.Background()
	repo := NewCommandRepository(&DB{DB: sqlDB})
	tenant := seedTestTenant(ctx, t, sqlDB)

	cloned := seedZoneSensor(ctx, t, sqlDB, &tenant, "cloned", zoneSensorOpts{tools: []string{"nuclei"}})
	healthy := seedZoneSensor(ctx, t, sqlDB, &tenant, "healthy", zoneSensorOpts{tools: []string{"nuclei"}})
	pool := createZoneCommand(ctx, t, repo, tenant, nil, nil, "nuclei")       // unzoned pool
	pinned := createZoneCommand(ctx, t, repo, tenant, nil, &cloned, "nuclei") // addressed to the cloned sensor

	// Before the flag: the poll and the doorbell offer both commands.
	assertPollParity(ctx, t, repo, tenant, cloned, nil, 2)

	setIdentityCloned(ctx, t, sqlDB, cloned, true)

	// Poll and doorbell: nothing, not even the command addressed to it.
	assertPollParity(ctx, t, repo, tenant, cloned, nil, 0)
	// Claim-N and claim by id: nothing is leased.
	got, err := repo.ClaimManyForSensor(ctx, tenant, cloned, nil, []shared.ID{pool, pinned})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("a cloned identity claimed %v, want nothing", got)
	}
	ok, err := repo.ClaimForSensor(ctx, tenant, pinned, cloned.String())
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("a cloned identity claimed its pinned command by id")
	}

	// Another sensor of the organization still takes the pool command.
	assertPollParity(ctx, t, repo, tenant, healthy, nil, 1)

	// Clearing the flag (re-pair, key regeneration) gives the work back.
	setIdentityCloned(ctx, t, sqlDB, cloned, false)
	ok, err = repo.ClaimForSensor(ctx, tenant, pinned, cloned.String())
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("after the flag was cleared the sensor could not claim its command")
	}
}

func TestSharedClaim_ClonedIdentityGetsNoNewWork(t *testing.T) {
	db := openPlatformJobDB(t)
	ctx := context.Background()
	repo := NewCommandRepository(&DB{DB: db})
	tool := uniqueTool()
	tenant := seedTestTenant(ctx, t, db)

	job := seedSharedJob(ctx, t, db, tenant, sharedJobSeed{tool: tool, platform: true})
	s := seedSharedSensor(ctx, t, db, sharedSensorSeed{tools: []string{tool}})
	if got := offered(ctx, t, repo, s, nil, job); len(got) != 1 {
		t.Fatalf("before the flag: offered %v, want the shared job", got)
	}

	setIdentityCloned(ctx, t, db, s, true)
	if got := offered(ctx, t, repo, s, nil, job); len(got) != 0 {
		t.Fatalf("a cloned shared sensor was offered %v, want nothing", got)
	}

	setIdentityCloned(ctx, t, db, s, false)
	if got := offered(ctx, t, repo, s, nil, job); len(got) != 1 {
		t.Fatalf("after the flag was cleared: offered %v, want the shared job", got)
	}
}
