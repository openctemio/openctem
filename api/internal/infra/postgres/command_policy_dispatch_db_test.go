package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	commandapp "github.com/openctemio/openctem/api/internal/app/command"
	"github.com/openctemio/openctem/api/pkg/domain/command"
	"github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// The dispatch pre-check against the real SQL (research/25 §3.6, T-P0a):
// a sensor whose reported local policy refuses a job never claims it; the
// job goes to another sensor of the zone that accepts it.

func setLocalPolicy(ctx context.Context, t *testing.T, repo *SensorRepository, tenantID, id shared.ID, r *sensor.LocalPolicyReport) {
	t.Helper()
	if ok, err := repo.UpdateLocalPolicy(ctx, &tenantID, id, r); err != nil || !ok {
		t.Fatalf("UpdateLocalPolicy: %v %v", ok, err)
	}
}

func createPayloadCommand(ctx context.Context, t *testing.T, repo *CommandRepository, tenantID shared.ID, zoneID *shared.ID, payload map[string]any) shared.ID {
	t.Helper()
	raw, _ := json.Marshal(payload)
	cmd, err := command.NewCommand(tenantID, command.CommandTypeScan, command.CommandPriorityNormal, raw)
	if err != nil {
		t.Fatal(err)
	}
	if zoneID != nil {
		cmd.SetScanZone(*zoneID)
	}
	if err := repo.Create(ctx, cmd); err != nil {
		t.Fatalf("create command: %v", err)
	}
	return cmd.ID
}

func TestDispatch_SensorPolicyRefusesJob_OtherSensorClaimsIt(t *testing.T) {
	sqlDB := openSensorDB(t)
	ctx := context.Background()
	pg := &DB{DB: sqlDB}
	zones := NewScanZoneRepository(pg)
	sensors := NewSensorRepository(pg)
	cmds := NewCommandRepository(pg)
	tenant := seedTestTenant(ctx, t, sqlDB)

	zone := newTestZone(t, tenant, "dmz", false, "10.40.0.0/16")
	if err := zones.Create(ctx, zone); err != nil {
		t.Fatal(err)
	}
	strict := seedZoneSensor(ctx, t, sqlDB, &tenant, "strict", zoneSensorOpts{tools: []string{"nuclei"}})
	open := seedZoneSensor(ctx, t, sqlDB, &tenant, "open", zoneSensorOpts{tools: []string{"nuclei"}})
	for _, id := range []shared.ID{strict, open} {
		if err := zones.AssignSensor(ctx, tenant, zone.ID, id, nil); err != nil {
			t.Fatal(err)
		}
	}
	// strict enforces a policy without interactsh; open runs without a
	// policy (legacy: both opt-ins on).
	setLocalPolicy(ctx, t, sensors, tenant, strict, &sensor.LocalPolicyReport{State: sensor.LocalPolicyEnforced,
		Summary: &sensor.LocalPolicySummary{TargetsAllow: -1, AllowPrivate: true, Tools: []string{"nuclei"}}})
	setLocalPolicy(ctx, t, sensors, tenant, open, &sensor.LocalPolicyReport{State: sensor.LocalPolicyAbsent})

	oast := createPayloadCommand(ctx, t, cmds, tenant, &zone.ID, map[string]any{
		"scanner": "nuclei", "targets": []string{"10.40.0.5"}, "config": map[string]any{"allow_interactsh": true}})
	plain := createPayloadCommand(ctx, t, cmds, tenant, &zone.ID, map[string]any{
		"scanner": "nuclei", "targets": []string{"10.40.0.6"}})

	svc := commandapp.NewService(cmds, logger.NewNop(), commandapp.WithSensorLookup(sensors))
	claim := func(id shared.ID) map[shared.ID]bool {
		t.Helper()
		got, err := svc.Claim(ctx, commandapp.ClaimInput{TenantID: tenant.String(), SensorID: id.String(), Limit: 10, MaxJobs: 5})
		if err != nil {
			t.Fatalf("claim: %v", err)
		}
		out := map[shared.ID]bool{}
		for _, c := range got {
			out[c.ID] = true
		}
		return out
	}

	// The strict sensor claims only what its policy accepts.
	if got := claim(strict); !got[plain] || got[oast] {
		t.Fatalf("strict sensor claimed %v, want only the plain job", got)
	}
	// A claim by id is refused as "claimed" and leaves the job pending.
	if _, err := svc.Acknowledge(ctx, tenant.String(), strict.String(), oast.String()); !errors.Is(err, commandapp.ErrSensorPolicyRefuses) ||
		!errors.Is(err, commandapp.ErrCommandClaimed) {
		t.Fatalf("claim by id from the strict sensor: %v", err)
	}
	if c, _ := cmds.GetByTenantAndID(ctx, tenant, oast); c.Status != command.CommandStatusPending || c.SensorID != nil {
		t.Fatalf("refused claim changed the job: %s %v", c.Status, c.SensorID)
	}
	// The other sensor of the zone gets it.
	if got := claim(open); !got[oast] {
		t.Fatalf("open sensor claimed %v, want the interactsh job", got)
	}

	// The kill switch withholds everything, even from a sensor that would
	// otherwise accept it.
	more := createPayloadCommand(ctx, t, cmds, tenant, &zone.ID, map[string]any{"scanner": "nuclei", "targets": []string{"10.40.0.7"}})
	setLocalPolicy(ctx, t, sensors, tenant, open, &sensor.LocalPolicyReport{State: sensor.LocalPolicyAbsent, KillSwitch: true})
	if got := claim(open); len(got) != 0 {
		t.Fatalf("paused sensor claimed %v", got)
	}
	if got := claim(strict); !got[more] {
		t.Fatalf("strict sensor did not get the plain job %v", got)
	}
}

// A queue head of jobs the sensor refuses does not starve it of the jobs
// behind them that it accepts.
func TestDispatch_RefusedQueueHeadDoesNotStarve(t *testing.T) {
	sqlDB := openSensorDB(t)
	ctx := context.Background()
	pg := &DB{DB: sqlDB}
	sensors := NewSensorRepository(pg)
	cmds := NewCommandRepository(pg)
	tenant := seedTestTenant(ctx, t, sqlDB)
	s := seedZoneSensor(ctx, t, sqlDB, &tenant, "httpx-only", zoneSensorOpts{tools: []string{"nuclei", "httpx"}})
	setLocalPolicy(ctx, t, sensors, tenant, s, &sensor.LocalPolicyReport{State: sensor.LocalPolicyEnforced,
		Summary: &sensor.LocalPolicySummary{TargetsAllow: -1, Tools: []string{"httpx"}}})
	for range 3 {
		createPayloadCommand(ctx, t, cmds, tenant, nil, map[string]any{"scanner": "nuclei", "target": "203.0.113.9"})
	}
	ok := createPayloadCommand(ctx, t, cmds, tenant, nil, map[string]any{"scanner": "httpx", "target": "203.0.113.9"})

	svc := commandapp.NewService(cmds, logger.NewNop(), commandapp.WithSensorLookup(sensors))
	got, err := svc.Poll(ctx, commandapp.PollInput{TenantID: tenant.String(), SensorID: s.String(), Limit: 2})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].ID != ok {
		t.Fatalf("polled %d commands, want only the httpx job", len(got))
	}
}

// research/191 W-2: more refused jobs at the head of the queue than one
// candidate page holds no longer starve the sensor: the claim reads the next
// page without them and claims the job it accepts.
func TestDispatch_RefusedPageDoesNotStarveTheClaim(t *testing.T) {
	sqlDB := openSensorDB(t)
	ctx := context.Background()
	pg := &DB{DB: sqlDB}
	sensors := NewSensorRepository(pg)
	cmds := NewCommandRepository(pg)
	tenant := seedTestTenant(ctx, t, sqlDB)
	s := seedZoneSensor(ctx, t, sqlDB, &tenant, "httpx-only", zoneSensorOpts{tools: []string{"nuclei", "httpx"}})
	setLocalPolicy(ctx, t, sensors, tenant, s, &sensor.LocalPolicyReport{State: sensor.LocalPolicyEnforced,
		Summary: &sensor.LocalPolicySummary{TargetsAllow: -1, Tools: []string{"httpx"}}})
	// candidateLimit(2) = 12 per page: 20 refused jobs fill the first page.
	for i := range 20 {
		createPayloadCommand(ctx, t, cmds, tenant, nil, map[string]any{"scanner": "nuclei", "target": fmt.Sprintf("203.0.113.%d", i+1)})
	}
	ok := createPayloadCommand(ctx, t, cmds, tenant, nil, map[string]any{"scanner": "httpx", "target": "198.51.100.7"})

	svc := commandapp.NewService(cmds, logger.NewNop(), commandapp.WithSensorLookup(sensors))
	got, err := svc.Claim(ctx, commandapp.ClaimInput{TenantID: tenant.String(), SensorID: s.String(), Limit: 2, MaxJobs: 5})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].ID != ok {
		t.Fatalf("claimed %d commands, want only the httpx job behind 20 refused ones", len(got))
	}
}

// The next page excludes what was read: a shared sensor's page and an
// organization sensor's page never repeat an excluded job.
func TestPendingPages_ExcludeWhatWasRead(t *testing.T) {
	sqlDB := openSensorDB(t)
	ctx := context.Background()
	cmds := NewCommandRepository(&DB{DB: sqlDB})
	tenant := seedTestTenant(ctx, t, sqlDB)
	s := seedZoneSensor(ctx, t, sqlDB, &tenant, "pager", zoneSensorOpts{tools: []string{"nuclei"}})
	for i := range 5 {
		createPayloadCommand(ctx, t, cmds, tenant, nil, map[string]any{"scanner": "nuclei", "target": fmt.Sprintf("192.0.2.%d", i+1)})
	}
	first, err := cmds.GetPendingForSensor(ctx, tenant, &s, nil, 3)
	if err != nil || len(first) != 3 {
		t.Fatalf("first page: %d %v", len(first), err)
	}
	seen := []shared.ID{first[0].ID, first[1].ID, first[2].ID}
	next, err := cmds.GetPendingForSensorExcluding(ctx, tenant, &s, nil, 3, seen)
	if err != nil || len(next) != 2 {
		t.Fatalf("next page: %d %v", len(next), err)
	}
	for _, c := range next {
		for _, id := range seen {
			if c.ID == id {
				t.Fatalf("the next page repeated %s", id)
			}
		}
	}

	db := openPlatformJobDB(t)
	tool := uniqueTool()
	shs := seedSharedSensor(ctx, t, db, sharedSensorSeed{tools: []string{tool}})
	org := seedTestTenant(ctx, t, db)
	a := seedSharedJob(ctx, t, db, org, sharedJobSeed{tool: tool, platform: true})
	b := seedSharedJob(ctx, t, db, org, sharedJobSeed{tool: tool, platform: true})
	shared1, err := cmds.GetSharedPendingForSensorExcluding(ctx, shs, nil, 10, []shared.ID{a})
	if err != nil {
		t.Fatal(err)
	}
	if len(shared1) != 1 || shared1[0].ID != b {
		t.Fatalf("shared page without %s: %v", a, shared1)
	}
}
