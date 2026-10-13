package postgres

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	commandapp "github.com/openctemio/openctem/api/internal/app/command"
	"github.com/openctemio/openctem/api/pkg/domain/command"
	"github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// The placement explainer agrees with the claim: for every (command,
// sensor) pair of a fixture table, the explainer calls the sensor eligible
// (with no job-level reason) exactly when the sensor's poll returns the
// command. Against the real claim SQL.

// placementGrants is a grant reader: every sensor gets a trusted grant
// without limits, except the ones listed.
type placementGrants map[shared.ID]*sensor.Grant

func (g placementGrants) Get(_ context.Context, tenantID, sensorID shared.ID) (*sensor.Grant, error) {
	if gr, ok := g[sensorID]; ok {
		return gr, nil
	}
	return &sensor.Grant{TenantID: tenantID, SensorID: sensorID, TrustLevel: sensor.TrustTrusted,
		TierCeiling: sensor.TierIntrusive, TargetNetwork: sensor.TargetNetworkAny}, nil
}

type placementFixture struct {
	ctx     context.Context
	tenant  shared.ID
	sensors []shared.ID
	cmds    map[string]shared.ID
	repo    *CommandRepository
	sensRep *SensorRepository
	svc     *commandapp.Service
}

func newPlacementFixture(t *testing.T) *placementFixture {
	t.Helper()
	sqlDB := openSensorDB(t)
	ctx := context.Background()
	pg := &DB{DB: sqlDB}
	f := &placementFixture{ctx: ctx, repo: NewCommandRepository(pg), sensRep: NewSensorRepository(pg), cmds: map[string]shared.ID{}}
	f.tenant = seedTestTenant(ctx, t, sqlDB)

	zones := NewScanZoneRepository(pg)
	z := newTestZone(t, f.tenant, "dmz", false, "10.60.0.0/16")
	if err := zones.Create(ctx, z); err != nil {
		t.Fatal(err)
	}
	inZoneNuclei := seedZoneSensor(ctx, t, sqlDB, &f.tenant, "a-zone-nuclei", zoneSensorOpts{tools: []string{"nuclei"}})
	outNuclei := seedZoneSensor(ctx, t, sqlDB, &f.tenant, "b-nuclei", zoneSensorOpts{tools: []string{"nuclei"}})
	inZoneHttpx := seedZoneSensor(ctx, t, sqlDB, &f.tenant, "c-zone-httpx", zoneSensorOpts{tools: []string{"httpx"}})
	dast := seedZoneSensor(ctx, t, sqlDB, &f.tenant, "d-dast", zoneSensorOpts{tools: []string{"nuclei"}})
	grantNarrow := seedZoneSensor(ctx, t, sqlDB, &f.tenant, "e-grant-httpx", zoneSensorOpts{tools: []string{"nuclei"}})
	never := seedZoneSensor(ctx, t, sqlDB, &f.tenant, "f-never-reported", zoneSensorOpts{tools: []string{"nuclei"}, declaredOnly: true})
	f.sensors = []shared.ID{inZoneNuclei, outNuclei, inZoneHttpx, dast, grantNarrow, never}
	for _, s := range []shared.ID{inZoneNuclei, inZoneHttpx} {
		if err := zones.AssignSensor(ctx, f.tenant, z.ID, s, nil); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := sqlDB.ExecContext(ctx, `UPDATE sensors SET reported_capabilities = '{nuclei,dast}' WHERE id = $1`, dast.String()); err != nil {
		t.Fatal(err)
	}

	nuclei := func(extra map[string]any) map[string]any {
		p := map[string]any{"scanner": "nuclei", "targets": []string{"10.60.0.5"}}
		for k, v := range extra {
			p[k] = v
		}
		return p
	}
	f.cmds["zoned"] = createPayloadCommand(ctx, t, f.repo, f.tenant, &z.ID, nuclei(nil))
	f.cmds["unzoned"] = createPayloadCommand(ctx, t, f.repo, f.tenant, nil, nuclei(nil))
	f.cmds["needs-dast"] = createPayloadCommand(ctx, t, f.repo, f.tenant, nil, nuclei(map[string]any{"required_capabilities": []string{"dast"}}))
	f.cmds["tool-less"] = createPayloadCommand(ctx, t, f.repo, f.tenant, nil, map[string]any{"targets": []string{"10.60.0.5"}})
	f.cmds["pinned"] = createPayloadCommand(ctx, t, f.repo, f.tenant, nil, nuclei(nil))
	f.cmds["refused"] = createPayloadCommand(ctx, t, f.repo, f.tenant, nil, nuclei(nil))
	f.cmds["later"] = createPayloadCommand(ctx, t, f.repo, f.tenant, nil, nuclei(nil))
	for q, args := range map[string][]any{
		`UPDATE commands SET sensor_id = $2 WHERE id = $1`:                               {f.cmds["pinned"].String(), outNuclei.String()},
		`UPDATE commands SET refused_by = ARRAY[$2::uuid] WHERE id = $1`:                 {f.cmds["refused"].String(), outNuclei.String()},
		`UPDATE commands SET scheduled_at = NOW() + interval '30 minutes' WHERE id = $1`: {f.cmds["later"].String()},
	} {
		if _, err := sqlDB.ExecContext(ctx, q, args...); err != nil {
			t.Fatal(err)
		}
	}

	grants := placementGrants{grantNarrow: {TenantID: f.tenant, SensorID: grantNarrow, TrustLevel: sensor.TrustTrusted,
		TierCeiling: sensor.TierIntrusive, TargetNetwork: sensor.TargetNetworkAny, Tools: []string{"httpx"}}}
	f.svc = commandapp.NewService(f.repo, logger.NewNop(), commandapp.WithSensorLookup(f.sensRep), commandapp.WithGrants(grants, nil))
	return f
}

// polled reports whether the sensor's poll returns the command.
func (f *placementFixture) polled(t *testing.T, sensorID, cmdID shared.ID) bool {
	t.Helper()
	sn, err := f.sensRep.GetByTenantAndID(f.ctx, f.tenant, sensorID)
	if err != nil {
		t.Fatal(err)
	}
	got, err := f.svc.Poll(f.ctx, commandapp.PollInput{TenantID: f.tenant.String(), SensorID: sensorID.String(),
		Capabilities: sn.EffectiveCapabilities(), Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	return slices.ContainsFunc(got, func(c *command.Command) bool { return c.ID == cmdID })
}

func TestPlacement_AgreesWithTheClaim(t *testing.T) {
	f := newPlacementFixture(t)
	eligiblePairs, blockedPairs := 0, 0
	for name, cmdID := range f.cmds {
		p, err := f.svc.ExplainPlacement(f.ctx, f.tenant, cmdID)
		if err != nil {
			t.Fatalf("%s: explain: %v", name, err)
		}
		if len(p.Sensors) != len(f.sensors) {
			t.Fatalf("%s: explained %d sensors, want %d", name, len(p.Sensors), len(f.sensors))
		}
		for _, sp := range p.Sensors {
			explained := sp.Eligible && len(p.JobReasons) == 0
			if got := f.polled(t, sp.SensorID, cmdID); got != explained {
				t.Errorf("%s / %s: poll returns it %v, explainer says eligible %v (reasons %v, job %v)",
					name, sp.Name, got, explained, sp.Reasons, p.JobReasons)
			}
			if explained {
				eligiblePairs++
			} else {
				blockedPairs++
			}
		}
	}
	if eligiblePairs == 0 || blockedPairs == 0 {
		t.Fatalf("fixture too weak: %d eligible, %d blocked pairs", eligiblePairs, blockedPairs)
	}
}

func TestPlacement_ReasonsPerSensor(t *testing.T) {
	f := newPlacementFixture(t)
	reasons := func(cmd string) map[string][]string {
		t.Helper()
		p, err := f.svc.ExplainPlacement(f.ctx, f.tenant, f.cmds[cmd])
		if err != nil {
			t.Fatal(err)
		}
		out := map[string][]string{}
		for _, sp := range p.Sensors {
			out[sp.Name[:len(sp.Name)-9]] = sp.Reasons
		}
		return out
	}
	want := map[string]map[string]string{
		"zoned":      {"b-nuclei": command.PlacementOutsideZone, "c-zone-httpx": command.PlacementOutsideZone, "f-never-reported": command.PlacementOutsideZone},
		"unzoned":    {"c-zone-httpx": command.PlacementToolMissing, "e-grant-httpx": command.PlacementGrantPrefix + sensor.DimTools, "f-never-reported": command.PlacementToolMissing},
		"needs-dast": {"a-zone-nuclei": command.PlacementCapabilityMissing},
		"pinned":     {"a-zone-nuclei": command.PlacementPinnedElsewhere},
		"refused":    {"b-nuclei": command.PlacementRefusedEarlier},
	}
	for cmd, bySensor := range want {
		got := reasons(cmd)
		for s, code := range bySensor {
			if !slices.Contains(got[s], code) {
				t.Errorf("%s / %s: reasons %v, want %s", cmd, s, got[s], code)
			}
		}
	}
	p, err := f.svc.ExplainPlacement(f.ctx, f.tenant, f.cmds["later"])
	if err != nil || !slices.Equal(p.JobReasons, []string{command.PlacementWindowClosed}) {
		t.Fatalf("scheduled job: reasons %v err %v, want window_closed", p.JobReasons, err)
	}
	if p.Eligible == 0 || len(p.Blocking) == 0 {
		t.Fatalf("summary: eligible %d blocking %v", p.Eligible, p.Blocking)
	}
}

// A command of another tenant is not found, and a tenant's explanation
// never evaluates another tenant's sensors.
func TestPlacement_TenantIsolation(t *testing.T) {
	f := newPlacementFixture(t)
	sqlDB := openSensorDB(t)
	other := seedTestTenant(f.ctx, t, sqlDB)
	foreign := seedZoneSensor(f.ctx, t, sqlDB, &other, "foreign", zoneSensorOpts{tools: []string{"nuclei"}})
	foreignCmd := createPayloadCommand(f.ctx, t, f.repo, other, nil, map[string]any{"scanner": "nuclei", "targets": []string{"10.60.0.5"}})

	if _, err := f.svc.ExplainPlacement(f.ctx, f.tenant, foreignCmd); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("another tenant's command: err %v, want not found", err)
	}
	if _, err := f.svc.ExplainPlacement(f.ctx, other, f.cmds["unzoned"]); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("this tenant's command read as the other tenant: err %v, want not found", err)
	}
	p, err := f.svc.ExplainPlacement(f.ctx, f.tenant, f.cmds["unzoned"])
	if err != nil {
		t.Fatal(err)
	}
	for _, sp := range p.Sensors {
		if sp.SensorID == foreign {
			t.Fatal("the explanation evaluated another tenant's sensor")
		}
	}
	// A run task is read through its run only.
	run := shared.NewID()
	task := createPayloadCommand(f.ctx, t, f.repo, f.tenant, nil, map[string]any{"scanner": "nuclei", "scan_run_id": run.String(), "targets": []string{"10.60.0.5"}})
	if p, err := f.svc.ExplainRunTaskPlacement(f.ctx, f.tenant, run, task); err != nil || len(p.Sensors) == 0 {
		t.Fatalf("a task through its own run: %+v err %v", p, err)
	}
	if _, err := f.svc.ExplainRunTaskPlacement(f.ctx, other, run, task); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("a task through its run as another tenant: err %v, want not found", err)
	}
	if _, err := f.svc.ExplainRunTaskPlacement(f.ctx, f.tenant, shared.NewID(), f.cmds["unzoned"]); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("a task read through another run: err %v, want not found", err)
	}
	// A platform sensor in the tenant row space is never listed either.
	plat := seedZoneSensor(f.ctx, t, sqlDB, &f.tenant, "platform", zoneSensorOpts{tools: []string{"nuclei"}, platform: true})
	p, err = f.svc.ExplainPlacement(f.ctx, f.tenant, f.cmds["unzoned"])
	if err != nil {
		t.Fatal(err)
	}
	for _, sp := range p.Sensors {
		if sp.SensorID == plat {
			t.Fatal("the explanation named a platform sensor")
		}
	}
}

// A platform job names no sensor; a command that is no longer pending is
// not evaluated.
func TestPlacement_PlatformAndSettledJobs(t *testing.T) {
	f := newPlacementFixture(t)
	sqlDB := openSensorDB(t)
	if _, err := sqlDB.ExecContext(f.ctx, `UPDATE commands SET is_platform_job = TRUE WHERE id = $1`, f.cmds["unzoned"].String()); err != nil {
		t.Fatal(err)
	}
	p, err := f.svc.ExplainPlacement(f.ctx, f.tenant, f.cmds["unzoned"])
	if err != nil || !p.Platform || len(p.Sensors) != 0 {
		t.Fatalf("platform job: %+v err %v, want platform with no sensors", p, err)
	}
	if _, err := sqlDB.ExecContext(f.ctx, `UPDATE commands SET status = 'completed', completed_at = $2 WHERE id = $1`,
		f.cmds["zoned"].String(), time.Now()); err != nil {
		t.Fatal(err)
	}
	p, err = f.svc.ExplainPlacement(f.ctx, f.tenant, f.cmds["zoned"])
	if err != nil || p.Status != command.CommandStatusCompleted || len(p.Sensors) != 0 {
		t.Fatalf("completed job: %+v err %v", p, err)
	}
}
