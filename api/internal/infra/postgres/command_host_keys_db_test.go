package postgres

import (
	"context"
	"encoding/json"
	"slices"
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

// A range chunk and an address chunk inside it are never run at once by two
// sensors, in either order, by poll, by id, in a batch or racing; two
// addresses of one /24 still run in parallel; another tenant's range never
// holds this tenant back (RFC-088 §6). Keys as scanrun writes them.
func TestCommandHostKeys_RangeAndAddressOverlap(t *testing.T) {
	sqlDB := openSensorDB(t)
	ctx := context.Background()
	cmds := NewCommandRepository(&DB{DB: sqlDB})
	tenant := seedTestTenant(ctx, t, sqlDB)
	other := seedTestTenant(ctx, t, sqlDB)
	a := seedZoneSensor(ctx, t, sqlDB, &tenant, "a", zoneSensorOpts{tools: []string{"httpx"}})
	b := seedZoneSensor(ctx, t, sqlDB, &tenant, "b", zoneSensorOpts{tools: []string{"httpx"}})
	o := seedZoneSensor(ctx, t, sqlDB, &other, "o", zoneSensorOpts{tools: []string{"httpx"}})
	done := func(ids ...shared.ID) {
		t.Helper()
		for _, id := range ids {
			if _, err := sqlDB.ExecContext(ctx, `UPDATE commands SET status = 'completed' WHERE id = $1`, id.String()); err != nil {
				t.Fatal(err)
			}
		}
	}
	const bucket = "203.0.113.0/24"

	// Another tenant scans the range: it never holds this tenant back.
	theirs := createHostChunk(ctx, t, cmds, other, "net:"+bucket)
	if ok, err := cmds.ClaimForSensor(ctx, other, theirs, o.String()); err != nil || !ok {
		t.Fatalf("other tenant claim: %v %v", ok, err)
	}

	// Range first: an address inside it waits; an address elsewhere runs.
	rng := createHostChunk(ctx, t, cmds, tenant, "net:"+bucket)
	inside := createHostChunk(ctx, t, cmds, tenant, "203.0.113.7", "in:"+bucket)
	outside := createHostChunk(ctx, t, cmds, tenant, "203.0.114.7", "in:203.0.114.0/24")
	if ok, err := cmds.ClaimForSensor(ctx, tenant, rng, a.String()); err != nil || !ok {
		t.Fatalf("range chunk not claimed: %v %v", ok, err)
	}
	got := polledIDs(ctx, t, cmds, tenant, b)
	if got[inside] || !got[outside] {
		t.Fatalf("b was offered %v; want the address elsewhere, not the one inside the busy range", got)
	}
	if ok, err := cmds.ClaimForSensor(ctx, tenant, inside, b.String()); err != nil || ok {
		t.Fatalf("an address inside a busy range was claimed: ok=%v err=%v", ok, err)
	}
	done(rng, outside)

	// Address first: the range waits; another address of the bucket runs.
	if ok, err := cmds.ClaimForSensor(ctx, tenant, inside, a.String()); err != nil || !ok {
		t.Fatalf("address chunk not claimed: %v %v", ok, err)
	}
	rng2 := createHostChunk(ctx, t, cmds, tenant, "net:"+bucket)
	neighbor := createHostChunk(ctx, t, cmds, tenant, "203.0.113.200", "in:"+bucket)
	if ok, err := cmds.ClaimForSensor(ctx, tenant, rng2, b.String()); err != nil || ok {
		t.Fatalf("a range holding a busy address was claimed: ok=%v err=%v", ok, err)
	}
	if ok, err := cmds.ClaimForSensor(ctx, tenant, neighbor, b.String()); err != nil || !ok {
		t.Fatalf("two addresses of one bucket must run in parallel: %v %v", ok, err)
	}
	done(inside, neighbor)

	// A batch never takes a range and an address inside it together.
	r3 := createHostChunk(ctx, t, cmds, tenant, "net:"+bucket)
	a3 := createHostChunk(ctx, t, cmds, tenant, "203.0.113.9", "in:"+bucket)
	a4 := createHostChunk(ctx, t, cmds, tenant, "203.0.113.10", "in:"+bucket)
	claimed, err := cmds.ClaimManyForSensor(ctx, tenant, a, nil, []shared.ID{a3, r3, a4})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(claimed, a3) || slices.Contains(claimed, r3) || !slices.Contains(claimed, a4) {
		t.Fatalf("batch claimed %v; want both addresses, not the range", claimed)
	}
	done(a3, a4)
	if ok, err := cmds.ClaimForSensor(ctx, tenant, r3, b.String()); err != nil || !ok {
		t.Fatalf("range not claimable once its bucket was free: %v %v", ok, err)
	}
	done(r3, rng2)

	// Racing claims of a range and an address inside it: exactly one wins.
	for round := 0; round < 15; round++ {
		r := createHostChunk(ctx, t, cmds, tenant, "net:"+bucket)
		x := createHostChunk(ctx, t, cmds, tenant, "203.0.113.50", "in:"+bucket)
		var wg sync.WaitGroup
		var okR, okX bool
		var errR, errX error
		wg.Add(2)
		go func() { defer wg.Done(); okR, errR = cmds.ClaimForSensor(ctx, tenant, r, a.String()) }()
		go func() { defer wg.Done(); okX, errX = cmds.ClaimForSensor(ctx, tenant, x, b.String()) }()
		wg.Wait()
		if errR != nil || errX != nil {
			t.Fatalf("round %d: claim errors %v / %v", round, errR, errX)
		}
		if okR == okX {
			t.Fatalf("round %d: range=%v address=%v; want exactly one", round, okR, okX)
		}
		done(r, x)
	}
}
