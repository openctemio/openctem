package postgres

import (
	"context"
	"database/sql"
	"sync"
	"testing"
	"time"

	commandapp "github.com/openctemio/openctem/api/internal/app/command"
	"github.com/openctemio/openctem/api/pkg/domain/command"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// Spreading work across an organization's sensors (claim_balance.go),
// against the real SQL: the first sensor to claim leaves fresh jobs to an
// eligible, less-loaded peer, never to a sensor without the tool, an
// offline or full one, or another tenant's; and only for the window.

type balanceFixture struct {
	ctx    context.Context
	t      *testing.T
	db     *sql.DB
	cmds   *CommandRepository
	svc    *commandapp.Service
	tenant shared.ID
}

func newBalanceFixture(t *testing.T) *balanceFixture {
	t.Helper()
	sqlDB := openSensorDB(t)
	ctx := context.Background()
	pg := &DB{DB: sqlDB}
	cmds := NewCommandRepository(pg)
	return &balanceFixture{
		ctx: ctx, t: t, db: sqlDB, cmds: cmds,
		svc:    commandapp.NewService(cmds, logger.NewNop(), commandapp.WithSensorLookup(NewSensorRepository(pg))),
		tenant: seedTestTenant(ctx, t, sqlDB),
	}
}

func (f *balanceFixture) sensor(name string, maxJobs int, o zoneSensorOpts) shared.ID {
	f.t.Helper()
	id := seedZoneSensor(f.ctx, f.t, f.db, &f.tenant, name, o)
	f.exec(`UPDATE sensors SET max_concurrent_jobs = $2 WHERE id = $1`, id.String(), maxJobs)
	return id
}

func (f *balanceFixture) exec(q string, args ...any) {
	f.t.Helper()
	if _, err := f.db.ExecContext(f.ctx, q, args...); err != nil {
		f.t.Fatalf("exec %q: %v", q, err)
	}
}

// jobs queues n nuclei scans (age ago).
func (f *balanceFixture) jobs(n int, tool string, age time.Duration) []shared.ID {
	f.t.Helper()
	out := make([]shared.ID, n)
	for i := range out {
		out[i] = createZoneCommand(f.ctx, f.t, f.cmds, f.tenant, nil, nil, tool)
		if age > 0 {
			f.exec(`UPDATE commands SET created_at = NOW() - make_interval(secs => $2) WHERE id = $1`,
				out[i].String(), age.Seconds())
		}
	}
	return out
}

func (f *balanceFixture) claim(id shared.ID, maxJobs int) []shared.ID {
	f.t.Helper()
	got, err := f.svc.Claim(f.ctx, commandapp.ClaimInput{TenantID: f.tenant.String(), SensorID: id.String(), Limit: 10, MaxJobs: maxJobs})
	if err != nil {
		f.t.Fatalf("claim: %v", err)
	}
	ids := make([]shared.ID, len(got))
	for i, c := range got {
		ids[i] = c.ID
	}
	return ids
}

// recent records n commands the sensor claimed a minute ago (and finished).
func (f *balanceFixture) recent(sensorID shared.ID, n int) {
	f.t.Helper()
	for _, id := range f.jobs(n, "nuclei", time.Hour) {
		f.exec(`UPDATE commands SET status = 'completed', sensor_id = $2,
			acknowledged_at = NOW() - INTERVAL '1 minute', completed_at = NOW() WHERE id = $1`, id.String(), sensorID.String())
	}
}

func TestClaimBalance_TwoIdleSensorsSplitFreshJobs(t *testing.T) {
	f := newBalanceFixture(t)
	fast := f.sensor("fast", 5, zoneSensorOpts{tools: []string{"nuclei", "naabu"}})
	slow := f.sensor("slow", 4, zoneSensorOpts{tools: []string{"nuclei", "naabu"}})

	// Two jobs, both sensors idle: the first claim keeps one and leaves
	// the other to the idle peer (before: it took both).
	f.jobs(2, "naabu", 0)
	if got := f.claim(fast, 5); len(got) != 1 {
		t.Fatalf("first sensor claimed %d of 2 fresh jobs, want 1", len(got))
	}
	if got := f.claim(slow, 4); len(got) != 1 {
		t.Fatalf("idle peer claimed %d, want the job left to it", len(got))
	}

	// Nine jobs, room for 5+4 minus what each holds (4 and 3): the walk
	// gives each sensor what it has room for, and nothing is left.
	f.jobs(7, "nuclei", 0)
	a := f.claim(fast, 5)
	b := f.claim(slow, 4)
	if len(a) != 4 || len(b) != 3 {
		t.Fatalf("claimed %d and %d, want 4 and 3 (every free slot used, none idle)", len(a), len(b))
	}
}

func TestClaimBalance_RecentLoadBreaksTies(t *testing.T) {
	f := newBalanceFixture(t)
	busy := f.sensor("busy", 5, zoneSensorOpts{tools: []string{"nuclei"}})
	idle := f.sensor("idle", 5, zoneSensorOpts{tools: []string{"nuclei"}})
	f.recent(busy, 3)

	job := f.jobs(1, "nuclei", 0)[0]
	if got := f.claim(busy, 5); len(got) != 0 {
		t.Fatalf("the sensor with more recent work claimed %v; the less-loaded peer goes first", got)
	}
	if got := f.claim(idle, 5); len(got) != 1 || got[0] != job {
		t.Fatalf("less-loaded peer claimed %v, want the job", got)
	}
}

func TestClaimBalance_WindowOverAnyoneTakesIt(t *testing.T) {
	f := newBalanceFixture(t)
	busy := f.sensor("busy", 5, zoneSensorOpts{tools: []string{"nuclei"}})
	f.sensor("idle", 5, zoneSensorOpts{tools: []string{"nuclei"}})
	f.recent(busy, 3)

	// Queued longer ago than the window: the peer had its chance.
	f.jobs(2, "nuclei", time.Minute)
	if got := f.claim(busy, 5); len(got) != 2 {
		t.Fatalf("claimed %d of 2 jobs past the window, want both (no starvation)", len(got))
	}
}

func TestClaimBalance_OnlyEligibleLivePeersOfTheTenant(t *testing.T) {
	f := newBalanceFixture(t)
	claimer := f.sensor("claimer", 5, zoneSensorOpts{tools: []string{"nuclei", "naabu"}})
	f.recent(claimer, 5)
	noTool := f.sensor("no-tool", 5, zoneSensorOpts{tools: []string{"naabu"}})
	f.sensor("offline", 5, zoneSensorOpts{tools: []string{"nuclei"}, health: "offline"})
	f.sensor("disabled", 5, zoneSensorOpts{tools: []string{"nuclei"}, status: "disabled"})
	full := f.sensor("full", 1, zoneSensorOpts{tools: []string{"nuclei"}})
	held := f.jobs(1, "nuclei", time.Hour)[0]
	f.exec(`UPDATE commands SET status = 'running', sensor_id = $2, acknowledged_at = NOW() - INTERVAL '1 hour',
		lease_expires_at = NOW() + INTERVAL '5 minutes' WHERE id = $1`, held.String(), full.String())
	// Another tenant's idle sensor with the tool.
	other := seedTestTenant(f.ctx, t, f.db)
	seedZoneSensor(f.ctx, t, f.db, &other, "foreign", zoneSensorOpts{tools: []string{"nuclei"}})

	jobs := f.jobs(3, "nuclei", 0)
	got := f.claim(claimer, 5)
	if len(got) != len(jobs) {
		t.Fatalf("claimed %d of %d: no peer could take a nuclei job (no tool, offline, disabled, full, other tenant), want all",
			len(got), len(jobs))
	}
	// The sensor without the tool never gets a nuclei job.
	f.jobs(1, "nuclei", time.Minute)
	if got := f.claim(noTool, 5); len(got) != 0 {
		t.Fatalf("a sensor without nuclei claimed %v", got)
	}
}

func TestClaimBalance_PinnedJobIsNotShared(t *testing.T) {
	f := newBalanceFixture(t)
	owner := f.sensor("owner", 5, zoneSensorOpts{tools: []string{"nuclei"}})
	f.recent(owner, 5)
	f.sensor("peer", 5, zoneSensorOpts{tools: []string{"nuclei"}})
	pinned := createZoneCommand(f.ctx, t, f.cmds, f.tenant, nil, &owner, "nuclei")
	if got := f.claim(owner, 5); len(got) != 1 || got[0] != pinned {
		t.Fatalf("claimed %v, want the job addressed to this sensor", got)
	}
}

func TestClaimBalance_ExpiredLeaseFreesTheSlot(t *testing.T) {
	f := newBalanceFixture(t)
	gone := f.sensor("gone", 1, zoneSensorOpts{tools: []string{"nuclei"}})
	live := f.sensor("live", 1, zoneSensorOpts{tools: []string{"nuclei"}})
	job := f.jobs(1, "nuclei", time.Minute)[0]
	if got := f.claim(gone, 1); len(got) != 1 {
		t.Fatalf("claim: %v", got)
	}
	f.exec(`UPDATE commands SET status = 'running', lease_expires_at = NOW() - INTERVAL '1 second' WHERE id = $1`, job.String())
	if n, _ := f.cmds.CountHeldScans(f.ctx, f.tenant, gone); n != 1 {
		t.Fatalf("held = %d before the reaper, want 1", n)
	}
	if _, err := f.cmds.RequeueExpiredLeases(f.ctx); err != nil {
		t.Fatal(err)
	}
	if n, _ := f.cmds.CountHeldScans(f.ctx, f.tenant, gone); n != 0 {
		t.Fatalf("held = %d after the lease ran out, want 0 (the slot is free again)", n)
	}
	if got := f.claim(live, 1); len(got) != 1 || got[0] != job {
		t.Fatalf("the re-queued job went to %v, want the live sensor", got)
	}
	if c, _ := f.cmds.GetByTenantAndID(f.ctx, f.tenant, job); c.Status != command.CommandStatusAcknowledged || *c.SensorID != live {
		t.Fatalf("job is %s on %v", c.Status, c.SensorID)
	}
}

func TestClaimBalance_PlacementSaysWhoYields(t *testing.T) {
	f := newBalanceFixture(t)
	busy := f.sensor("busy", 5, zoneSensorOpts{tools: []string{"nuclei"}})
	idle := f.sensor("idle", 5, zoneSensorOpts{tools: []string{"nuclei"}})
	f.recent(busy, 3)
	job := f.jobs(1, "nuclei", 0)[0]

	p, err := f.svc.ExplainPlacement(f.ctx, f.tenant, job)
	if err != nil {
		t.Fatal(err)
	}
	yields := map[shared.ID]bool{}
	for _, s := range p.Sensors {
		if !s.Eligible {
			t.Fatalf("sensor %s not eligible: %v", s.Name, s.Reasons)
		}
		yields[s.SensorID] = s.Yields
	}
	if !yields[busy] || yields[idle] {
		t.Fatalf("yields = %v, want only the busier sensor to yield", yields)
	}
	if p.Eligible != 2 {
		t.Fatalf("eligible = %d, want 2 (yielding does not make a sensor ineligible)", p.Eligible)
	}

	// Past the window nobody yields.
	f.exec(`UPDATE commands SET created_at = NOW() - INTERVAL '1 minute' WHERE id = $1`, job.String())
	if p, err = f.svc.ExplainPlacement(f.ctx, f.tenant, job); err != nil {
		t.Fatal(err)
	}
	for _, s := range p.Sensors {
		if s.Yields {
			t.Fatalf("%s yields past the window", s.Name)
		}
	}
}

func TestClaimBalance_Off(t *testing.T) {
	f := newBalanceFixture(t)
	a := f.sensor("a", 5, zoneSensorOpts{tools: []string{"nuclei"}})
	f.sensor("b", 5, zoneSensorOpts{tools: []string{"nuclei"}})
	f.svc = commandapp.NewService(f.cmds, logger.NewNop(), commandapp.WithClaimBalanceWindow(0))
	f.jobs(2, "nuclei", 0)
	if got := f.claim(a, 5); len(got) != 2 {
		t.Fatalf("with balancing off the first claim takes %d, want 2", len(got))
	}
}

// Claims racing on one sensor (a poll and a stream wake, two replicas)
// never hand it more scans than its job limit, and the job count the
// console shows is the same count: a non-scan command adds nothing.
func TestClaim_ConcurrentClaimsNeverExceedTheSlots(t *testing.T) {
	f := newBalanceFixture(t)
	s := f.sensor("racer", 3, zoneSensorOpts{tools: []string{"nuclei"}})
	jobs := f.jobs(12, "nuclei", time.Minute)

	const racers = 8
	var wg sync.WaitGroup
	counts := make([]int, racers)
	errs := make([]error, racers)
	for i := range racers {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			// Half go through the service (which reads the held count
			// first), half straight to the repository with every id.
			if i%2 == 0 {
				got, err := f.svc.Claim(f.ctx, commandapp.ClaimInput{TenantID: f.tenant.String(), SensorID: s.String(), Limit: 10, MaxJobs: 3})
				counts[i], errs[i] = len(got), err
				return
			}
			got, err := f.cmds.ClaimManyForSensor(f.ctx, f.tenant, s, nil, jobs)
			counts[i], errs[i] = len(got), err
		}(i)
	}
	wg.Wait()
	total := 0
	for i := range racers {
		if errs[i] != nil {
			t.Fatalf("claim %d: %v", i, errs[i])
		}
		total += counts[i]
	}
	held, err := f.cmds.CountHeldScans(f.ctx, f.tenant, s)
	if err != nil {
		t.Fatal(err)
	}
	if total != 3 || held != 3 {
		t.Fatalf("concurrent claims took %d (held %d), want exactly the 3 slots", total, held)
	}

	// A content refresh in flight takes no scan slot and is not a job.
	refresh := createZoneCommand(f.ctx, t, f.cmds, f.tenant, nil, nil, "nuclei")
	f.exec(`UPDATE commands SET type = 'refresh_content', status = 'running', sensor_id = $2,
		acknowledged_at = NOW(), lease_expires_at = NOW() + INTERVAL '5 minutes' WHERE id = $1`, refresh.String(), s.String())
	sn, err := NewSensorRepository(&DB{DB: f.db}).GetByTenantAndID(f.ctx, f.tenant, s)
	if err != nil {
		t.Fatal(err)
	}
	if sn.CurrentJobs != 3 {
		t.Fatalf("jobs shown = %d, want 3 (the 3 scans; the content refresh is not a job)", sn.CurrentJobs)
	}
}

// A claim by a sensor id that is not the tenant's claims nothing.
func TestClaim_ForeignSensorClaimsNothing(t *testing.T) {
	f := newBalanceFixture(t)
	other := seedTestTenant(f.ctx, t, f.db)
	foreign := seedZoneSensor(f.ctx, t, f.db, &other, "foreign", zoneSensorOpts{tools: []string{"nuclei"}})
	jobs := f.jobs(2, "nuclei", time.Minute)
	got, err := f.cmds.ClaimManyForSensor(f.ctx, f.tenant, foreign, nil, jobs)
	if err != nil || len(got) != 0 {
		t.Fatalf("foreign sensor claimed %v (%v)", got, err)
	}
}
