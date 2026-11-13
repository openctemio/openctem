package postgres

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"

	commandapp "github.com/openctemio/openctem/server/internal/app/command"
	"github.com/openctemio/openctem/server/pkg/domain/command"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/domain/sourceretire"
	"github.com/openctemio/openctem/server/pkg/logger"
)

// Scans of a retired source (docs/architecture/source-retirement.md): the
// claim never hands a sensor a scan job of a tool the organization retired
// as a source on that sensor. Against the real SQL.

type failedAtClaim struct {
	mu    sync.Mutex
	codes map[shared.ID]string
}

func (f *failedAtClaim) OnCommandFailed(_ context.Context, cmd *command.Command, _ string, code string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.codes == nil {
		f.codes = map[shared.ID]string{}
	}
	f.codes[cmd.ID] = code
}

func (f *failedAtClaim) code(id shared.ID) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.codes[id]
}

type retiredFixture struct {
	t           *testing.T
	ctx         context.Context
	db          *DB
	cmds        *CommandRepository
	retirements *SourceRetirementRepository
	svc         *commandapp.Service
	failures    *failedAtClaim
	n           int
}

func newRetiredFixture(t *testing.T) *retiredFixture {
	t.Helper()
	sqlDB := openSensorDB(t)
	pg := &DB{DB: sqlDB}
	f := &retiredFixture{t: t, ctx: context.Background(), db: pg, cmds: NewCommandRepository(pg),
		retirements: NewSourceRetirementRepository(pg), failures: &failedAtClaim{}}
	f.svc = commandapp.NewService(f.cmds, logger.NewNop(), commandapp.WithSensorLookup(NewSensorRepository(pg)),
		commandapp.WithRetiredSources(f.retirements))
	f.svc.SetFailureObserver(f.failures)
	return f
}

func (f *retiredFixture) sensor(tenant shared.ID) shared.ID {
	return seedZoneSensor(f.ctx, f.t, f.db.DB, &tenant, "s", zoneSensorOpts{tools: []string{"nuclei", "httpx"}})
}

// job queues a scan job of a scan run for tool, pinned to a sensor or not.
func (f *retiredFixture) job(tenant shared.ID, tool string, pinned *shared.ID) shared.ID {
	f.t.Helper()
	// A host of its own: a job holding a host keeps the next one on it waiting.
	f.n++
	raw, _ := json.Marshal(map[string]any{"scanner": tool, "targets": []string{fmt.Sprintf("203.0.113.%d", f.n)},
		"scan_run_id": shared.NewID().String(), "step_key": "s"})
	cmd, err := command.NewCommand(tenant, command.CommandTypeScan, command.CommandPriorityNormal, raw)
	if err != nil {
		f.t.Fatal(err)
	}
	if pinned != nil {
		cmd.SetSensorID(*pinned)
	}
	if err := f.cmds.Create(f.ctx, cmd); err != nil {
		f.t.Fatalf("create command: %v", err)
	}
	return cmd.ID
}

func (f *retiredFixture) claim(tenant, sensorID shared.ID) map[shared.ID]bool {
	f.t.Helper()
	got, err := f.svc.Claim(f.ctx, commandapp.ClaimInput{TenantID: tenant.String(), SensorID: sensorID.String(), Limit: 10, MaxJobs: 10})
	if err != nil {
		f.t.Fatalf("claim: %v", err)
	}
	out := map[shared.ID]bool{}
	for _, c := range got {
		out[c.ID] = true
	}
	return out
}

func (f *retiredFixture) retire(tenant, sensorID shared.ID, tool string) *sourceretire.Retirement {
	f.t.Helper()
	r, err := f.retirements.Create(f.ctx, &sourceretire.Retirement{TenantID: tenant,
		Selector: sourceretire.Selector{Kind: sourceretire.KindSensorTool, SensorID: &sensorID, Tool: tool},
		Options:  sourceretire.Options{Mode: sourceretire.ModeKeepOpen}, Reason: "the results were wrong all along"})
	if err != nil {
		f.t.Fatalf("retire: %v", err)
	}
	return r
}

func (f *retiredFixture) state(tenant, id shared.ID) (status, withheld, msg string) {
	f.t.Helper()
	if err := f.db.QueryRowContext(f.ctx, `SELECT status, COALESCE(withheld_reason, ''), COALESCE(error_message, '')
		FROM commands WHERE tenant_id = $1 AND id = $2`, tenant.String(), id.String()).Scan(&status, &withheld, &msg); err != nil {
		f.t.Fatal(err)
	}
	return status, withheld, msg
}

// One sensor: the retired tool's job is refused at claim with
// SOURCE_RETIRED (never sent), another tool of the same sensor still runs,
// and the source used again makes the tool run again.
func TestSourceRetired_RefusedAtClaim_OtherToolRuns_RestoreRunsAgain(t *testing.T) {
	f := newRetiredFixture(t)
	tenant := seedTestTenant(f.ctx, t, f.db.DB)
	a := f.sensor(tenant)
	ret := f.retire(tenant, a, "Nuclei") // case and spelling as ingest compares them

	retired := f.job(tenant, "nuclei", nil)
	other := f.job(tenant, "httpx", nil)
	got := f.claim(tenant, a)
	if got[retired] {
		t.Fatal("the sensor was handed a job of a tool retired on it")
	}
	if !got[other] {
		t.Fatal("another tool of the same sensor was not dispatched")
	}
	status, _, msg := f.state(tenant, retired)
	if status != string(command.CommandStatusFailed) || !strings.Contains(msg, commandapp.FailureSourceRetired) {
		t.Fatalf("retired job: %s %q, want failed with SOURCE_RETIRED", status, msg)
	}
	if code := f.failures.code(retired); code != commandapp.FailureSourceRetired {
		t.Fatalf("the run was told %q, want SOURCE_RETIRED", code)
	}

	// The claim by id refuses it as well.
	byID := f.job(tenant, "nuclei", &a)
	if _, err := f.svc.Acknowledge(f.ctx, tenant.String(), a.String(), byID.String()); err == nil {
		t.Fatal("the claim by id handed out a job of a retired tool")
	}
	if status, _, _ := f.state(tenant, byID); status != string(command.CommandStatusFailed) {
		t.Fatalf("job claimed by id: %s, want failed", status)
	}

	// Use this source again: the next claim dispatches the tool.
	if _, err := f.retirements.StartRestore(f.ctx, tenant, ret.ID, nil, "the scanner was fixed"); err != nil {
		t.Fatal(err)
	}
	again := f.job(tenant, "nuclei", nil)
	if !f.claim(tenant, a)[again] {
		t.Fatal("the tool was not dispatched after the source was used again")
	}
}

// Two sensors: an unpinned job is left to the sensor the tool is not
// retired on (recorded as source_retired), a job pinned to the retired
// sensor is refused.
func TestSourceRetired_UnpinnedJobGoesToAnotherSensor(t *testing.T) {
	f := newRetiredFixture(t)
	tenant := seedTestTenant(f.ctx, t, f.db.DB)
	a, b := f.sensor(tenant), f.sensor(tenant)
	f.retire(tenant, a, "nuclei")

	free := f.job(tenant, "nuclei", nil)
	pinned := f.job(tenant, "nuclei", &a)
	if got := f.claim(tenant, a); got[free] || got[pinned] {
		t.Fatal("the retired sensor was handed the tool's jobs")
	}
	status, withheld, _ := f.state(tenant, free)
	if status != string(command.CommandStatusPending) || withheld != command.PlacementSourceRetired {
		t.Fatalf("unpinned job: %s withheld %q, want pending source_retired", status, withheld)
	}
	if status, _, _ := f.state(tenant, pinned); status != string(command.CommandStatusFailed) {
		t.Fatalf("pinned job: %s, want failed", status)
	}
	if !f.claim(tenant, b)[free] {
		t.Fatal("the other sensor did not get the job")
	}
}

// A retirement is the organization's: another organization's sensor with
// the same tool is never stopped, even by a retirement row that names it.
func TestSourceRetired_TenantIsolation(t *testing.T) {
	f := newRetiredFixture(t)
	tenantA := seedTestTenant(f.ctx, t, f.db.DB)
	tenantB := seedTestTenant(f.ctx, t, f.db.DB)
	a := f.sensor(tenantA)
	b := f.sensor(tenantB)
	f.retire(tenantA, a, "nuclei")
	// A row of tenant A naming tenant B's sensor (the API refuses it; the
	// claim must not honor it either).
	f.retire(tenantA, b, "nuclei")

	job := f.job(tenantB, "nuclei", nil)
	if !f.claim(tenantB, b)[job] {
		t.Fatal("tenant A's retirement stopped tenant B's sensor")
	}
	if code := f.failures.code(job); code != "" {
		t.Fatalf("tenant B's job was refused with %q", code)
	}
}
