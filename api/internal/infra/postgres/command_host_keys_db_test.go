package postgres

import (
	"context"
	"encoding/json"
	"sync"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/command"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Platform-side per-host politeness (research/49 §3.12.3) against a real
// schema: while one sensor holds a chunk, no chunk of the tenant that shares
// one of its hosts is offered or claimable, by id or in a batch, even by two
// sensors racing; a finish or an expired lease frees the hosts; another
// tenant's work on the same host never holds this tenant back; commands
// without host keys are unaffected. Requires DATABASE_URL.

func createHostChunk(ctx context.Context, t *testing.T, repo *CommandRepository, tenant shared.ID, hosts ...string) shared.ID {
	t.Helper()
	raw, _ := json.Marshal(map[string]any{"scanner": "httpx", "preferred_tool": "httpx", "targets": hosts})
	cmd, err := command.NewCommand(tenant, command.CommandTypeScan, command.CommandPriorityNormal, raw)
	if err != nil {
		t.Fatal(err)
	}
	cmd.HostKeys = hosts
	if err := repo.Create(ctx, cmd); err != nil {
		t.Fatal(err)
	}
	return cmd.ID
}

func TestCommandHostKeys_OneSensorPerHost(t *testing.T) {
	sqlDB := openSensorDB(t)
	ctx := context.Background()
	cmds := NewCommandRepository(&DB{DB: sqlDB})
	tenant := seedTestTenant(ctx, t, sqlDB)
	other := seedTestTenant(ctx, t, sqlDB)
	a := seedZoneSensor(ctx, t, sqlDB, &tenant, "a", zoneSensorOpts{tools: []string{"httpx"}})
	b := seedZoneSensor(ctx, t, sqlDB, &tenant, "b", zoneSensorOpts{tools: []string{"httpx"}})
	o := seedZoneSensor(ctx, t, sqlDB, &other, "o", zoneSensorOpts{tools: []string{"httpx"}})

	first := createHostChunk(ctx, t, cmds, tenant, "x.example.com")
	shared1 := createHostChunk(ctx, t, cmds, tenant, "x.example.com", "y.example.com")
	free := createHostChunk(ctx, t, cmds, tenant, "z.example.com")
	noKeys := createZoneCommand(ctx, t, cmds, tenant, nil, nil, "httpx")
	// Another tenant runs the same host: it never holds this tenant back.
	theirs := createHostChunk(ctx, t, cmds, other, "x.example.com")
	if ok, err := cmds.ClaimForSensor(ctx, other, theirs, o.String()); err != nil || !ok {
		t.Fatalf("other tenant claim: %v %v", ok, err)
	}

	if ok, err := cmds.ClaimForSensor(ctx, tenant, first, a.String()); err != nil || !ok {
		t.Fatalf("first chunk not claimed: %v %v", ok, err)
	}
	got := polledIDs(ctx, t, cmds, tenant, b)
	if got[shared1] || !got[free] || !got[noKeys] {
		t.Fatalf("b was offered %v; want the free chunk and the keyless command, not the busy host", got)
	}
	assertPollParity(ctx, t, cmds, tenant, b, nil, len(got))
	if ok, err := cmds.ClaimForSensor(ctx, tenant, shared1, b.String()); err != nil || ok {
		t.Fatalf("a chunk on a busy host was claimed by id: ok=%v err=%v", ok, err)
	}

	// The holder finishes: the host is free again.
	if _, err := sqlDB.ExecContext(ctx, `UPDATE commands SET status = 'completed' WHERE id = $1`, first.String()); err != nil {
		t.Fatal(err)
	}
	if ok, err := cmds.ClaimForSensor(ctx, tenant, shared1, b.String()); err != nil || !ok {
		t.Fatalf("chunk not claimable once its host was free: %v %v", ok, err)
	}

	// An expired lease frees the hosts too.
	again := createHostChunk(ctx, t, cmds, tenant, "y.example.com")
	if ok, _ := cmds.ClaimForSensor(ctx, tenant, again, a.String()); ok {
		t.Fatal("chunk on a host b holds was claimed")
	}
	if _, err := sqlDB.ExecContext(ctx, `UPDATE commands SET lease_expires_at = NOW() - interval '1 second' WHERE id = $1`, shared1.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := cmds.RequeueExpiredLeases(ctx); err != nil {
		t.Fatal(err)
	}
	if ok, err := cmds.ClaimForSensor(ctx, tenant, again, a.String()); err != nil || !ok {
		t.Fatalf("host not freed by the expired lease: %v %v", ok, err)
	}
}

func TestCommandHostKeys_BatchClaimTakesOneChunkPerHost(t *testing.T) {
	sqlDB := openSensorDB(t)
	ctx := context.Background()
	cmds := NewCommandRepository(&DB{DB: sqlDB})
	tenant := seedTestTenant(ctx, t, sqlDB)
	a := seedZoneSensor(ctx, t, sqlDB, &tenant, "a", zoneSensorOpts{tools: []string{"httpx"}})

	c1 := createHostChunk(ctx, t, cmds, tenant, "p.example.com", "q.example.com")
	c2 := createHostChunk(ctx, t, cmds, tenant, "q.example.com")
	c3 := createHostChunk(ctx, t, cmds, tenant, "r.example.com")
	claimed, err := cmds.ClaimManyForSensor(ctx, tenant, a, nil, []shared.ID{c1, c2, c3})
	if err != nil {
		t.Fatal(err)
	}
	got := map[shared.ID]bool{}
	for _, id := range claimed {
		got[id] = true
	}
	if !got[c1] || got[c2] || !got[c3] || len(claimed) != 2 {
		t.Fatalf("batch claimed %v; want c1 and c3, not c2 (shares q with c1)", claimed)
	}
}

func TestCommandHostKeys_RacingSensorsNeverShareAHost(t *testing.T) {
	sqlDB := openSensorDB(t)
	ctx := context.Background()
	cmds := NewCommandRepository(&DB{DB: sqlDB})
	tenant := seedTestTenant(ctx, t, sqlDB)
	a := seedZoneSensor(ctx, t, sqlDB, &tenant, "a", zoneSensorOpts{tools: []string{"httpx"}})
	b := seedZoneSensor(ctx, t, sqlDB, &tenant, "b", zoneSensorOpts{tools: []string{"httpx"}})

	for round := 0; round < 15; round++ {
		c1 := createHostChunk(ctx, t, cmds, tenant, "race.example.com")
		c2 := createHostChunk(ctx, t, cmds, tenant, "race.example.com", "other.example.com")
		var wg sync.WaitGroup
		var ok1, ok2 bool
		var err1, err2 error
		wg.Add(2)
		go func() { defer wg.Done(); ok1, err1 = cmds.ClaimForSensor(ctx, tenant, c1, a.String()) }()
		go func() { defer wg.Done(); ok2, err2 = cmds.ClaimForSensor(ctx, tenant, c2, b.String()) }()
		wg.Wait()
		if err1 != nil || err2 != nil {
			t.Fatalf("round %d: claim errors %v / %v", round, err1, err2)
		}
		if ok1 == ok2 {
			t.Fatalf("round %d: claims a=%v b=%v; want exactly one sensor on the host", round, ok1, ok2)
		}
		if _, err := sqlDB.ExecContext(ctx, `UPDATE commands SET status = 'completed' WHERE id = ANY($1::uuid[])`,
			"{"+c1.String()+","+c2.String()+"}"); err != nil {
			t.Fatal(err)
		}
	}
}
