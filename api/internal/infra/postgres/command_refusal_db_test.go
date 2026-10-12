package postgres

import (
	"context"
	"strings"
	"testing"

	commandapp "github.com/openctemio/openctem/api/internal/app/command"
	"github.com/openctemio/openctem/api/pkg/domain/command"
	"github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// A refused routed job is re-queued to another eligible sensor and never
// offered to the refuser again; it fails once no other eligible sensor
// accepts it, or after 3 refusals (research/25 §3.6, D8; T-P0e, T-P0f).
// Against the real SQL, as the app role.

type refusalFixture struct {
	t       *testing.T
	ctx     context.Context
	tenant  shared.ID
	zone    shared.ID
	cmds    *CommandRepository
	sensors *SensorRepository
	svc     *commandapp.Service
}

func newRefusalFixture(t *testing.T, sensorCount int) (*refusalFixture, []shared.ID) {
	t.Helper()
	sqlDB := openSensorDB(t)
	ctx := context.Background()
	pg := &DB{DB: sqlDB}
	f := &refusalFixture{t: t, ctx: ctx, cmds: NewCommandRepository(pg), sensors: NewSensorRepository(pg)}
	f.tenant = seedTestTenant(ctx, t, sqlDB)
	zones := NewScanZoneRepository(pg)
	z := newTestZone(t, f.tenant, "dmz", false, "10.60.0.0/16")
	if err := zones.Create(ctx, z); err != nil {
		t.Fatal(err)
	}
	f.zone = z.ID
	ids := make([]shared.ID, sensorCount)
	for i := range ids {
		ids[i] = seedZoneSensor(ctx, t, sqlDB, &f.tenant, "s", zoneSensorOpts{tools: []string{"nuclei"}})
		if err := zones.AssignSensor(ctx, f.tenant, z.ID, ids[i], nil); err != nil {
			t.Fatal(err)
		}
	}
	f.svc = commandapp.NewService(f.cmds, logger.NewNop(), commandapp.WithSensorLookup(f.sensors))
	return f, ids
}

// routedJob creates a zone scan command of a scan run (routed work).
func (f *refusalFixture) routedJob(routed bool) shared.ID {
	payload := map[string]any{"scanner": "nuclei", "targets": []string{"10.60.0.5"}}
	if routed {
		payload["scan_run_id"] = shared.NewID().String()
	}
	return createPayloadCommand(f.ctx, f.t, f.cmds, f.tenant, &f.zone, payload)
}

func (f *refusalFixture) claim(sensorID shared.ID) map[shared.ID]bool {
	f.t.Helper()
	got, err := f.svc.Claim(f.ctx, commandapp.ClaimInput{TenantID: f.tenant.String(), SensorID: sensorID.String(), Limit: 10, MaxJobs: 5})
	if err != nil {
		f.t.Fatalf("claim: %v", err)
	}
	out := map[shared.ID]bool{}
	for _, c := range got {
		out[c.ID] = true
	}
	return out
}

func (f *refusalFixture) refuse(sensorID, cmdID shared.ID, ref *sensor.DispatchRefusal, msg string) *command.Command {
	f.t.Helper()
	out, err := f.svc.Fail(f.ctx, commandapp.FailInput{TenantID: f.tenant.String(), SensorID: sensorID.String(),
		CommandID: cmdID.String(), ErrorMessage: msg, Refusal: ref})
	if err != nil {
		f.t.Fatalf("fail: %v", err)
	}
	return out
}

func TestRefusal_RequeuedToAnotherSensorThenFails(t *testing.T) {
	f, ids := newRefusalFixture(t, 2)
	a, b := ids[0], ids[1]
	job := f.routedJob(true)

	if !f.claim(a)[job] {
		t.Fatal("sensor A did not claim the job")
	}
	// A refuses with a structured refusal (v2).
	out := f.refuse(a, job, &sensor.DispatchRefusal{Layer: "local", Rule: "tools.allow", Detail: "nuclei is not allowed"}, "refused")
	if out.Status != command.CommandStatusPending || out.SensorID != nil {
		t.Fatalf("after A refused: status %s sensor %v, want pending and unpinned", out.Status, out.SensorID)
	}
	if out.ScanZoneID == nil || *out.ScanZoneID != f.zone {
		t.Fatal("the re-queue dropped the zone")
	}
	// A never sees it again; B claims it.
	if f.claim(a)[job] {
		t.Fatal("the refusing sensor claimed the job again")
	}
	if _, err := f.svc.Acknowledge(f.ctx, f.tenant.String(), a.String(), job.String()); err == nil {
		t.Fatal("the refusing sensor claimed the job by id")
	}
	if !f.claim(b)[job] {
		t.Fatal("sensor B did not get the re-queued job")
	}
	// B refuses with the text-only form of an older SDK (T-P0f): nobody is
	// left, the job fails with both reasons.
	out = f.refuse(b, job, nil, "refused by local policy: allow_interactsh: callbacks are off")
	if out.Status != command.CommandStatusFailed {
		t.Fatalf("after B refused: %s, want failed", out.Status)
	}
	if !strings.HasPrefix(out.ErrorMessage, sensor.LocalPolicyRefusalPrefix+"allow_interactsh") ||
		!strings.Contains(out.ErrorMessage, "tools.allow") || !strings.Contains(out.ErrorMessage, "refused by 2 sensors") {
		t.Fatalf("failure reason %q does not aggregate both refusals", out.ErrorMessage)
	}
	recs, err := f.cmds.CommandRefusals(f.ctx, f.tenant, job)
	if err != nil || len(recs) != 2 || recs[0].SensorID != a.String() || recs[1].Rule != "allow_interactsh" {
		t.Fatalf("recorded refusals %+v err %v", recs, err)
	}
}

func TestRefusal_FailsAfterThreeRefusals(t *testing.T) {
	f, ids := newRefusalFixture(t, 4)
	job := f.routedJob(true)
	ref := &sensor.DispatchRefusal{Layer: "local", Rule: "ports.allow"}
	var out *command.Command
	for i := range 3 {
		if !f.claim(ids[i])[job] {
			t.Fatalf("sensor %d did not claim the job", i)
		}
		out = f.refuse(ids[i], job, ref, "")
	}
	if out.Status != command.CommandStatusFailed {
		t.Fatalf("after 3 refusals: %s, want failed (a 4th sensor exists but the cap is 3)", out.Status)
	}
	if f.claim(ids[3])[job] {
		t.Fatal("a failed job was offered again")
	}
}

// Only routed scan work moves: a command a person addressed (no scan workflow
// run) fails at once, as before.
func TestRefusal_UnroutedCommandFails(t *testing.T) {
	f, ids := newRefusalFixture(t, 2)
	job := f.routedJob(false)
	if !f.claim(ids[0])[job] {
		t.Fatal("not claimed")
	}
	if out := f.refuse(ids[0], job, &sensor.DispatchRefusal{Layer: "local", Rule: "checks.allow"}, ""); out.Status != command.CommandStatusFailed {
		t.Fatalf("unrouted refused command: %s, want failed", out.Status)
	}
}

// The other sensor's own report refuses it too: nothing to re-queue to.
// Another tenant's sensor never counts.
func TestRefusal_NoOtherSensorAccepts(t *testing.T) {
	f, ids := newRefusalFixture(t, 2)
	if ok, err := f.sensors.UpdateLocalPolicy(f.ctx, &f.tenant, ids[1], &sensor.LocalPolicyReport{State: sensor.LocalPolicyEnforced,
		Summary: &sensor.LocalPolicySummary{TargetsAllow: -1, AllowPrivate: true, Tools: []string{"httpx"}}}); err != nil || !ok {
		t.Fatalf("UpdateLocalPolicy: %v %v", ok, err)
	}
	other := seedTestTenant(f.ctx, t, openSensorDB(t))
	seedZoneSensor(f.ctx, t, openSensorDB(t), &other, "foreign", zoneSensorOpts{tools: []string{"nuclei"}})

	job := f.routedJob(true)
	if !f.claim(ids[0])[job] {
		t.Fatal("not claimed")
	}
	out := f.refuse(ids[0], job, &sensor.DispatchRefusal{Layer: "local", Rule: "allow_private"}, "")
	if out.Status != command.CommandStatusFailed || !strings.Contains(out.ErrorMessage, "no other eligible sensor") {
		t.Fatalf("status %s reason %q, want failed with no other eligible sensor", out.Status, out.ErrorMessage)
	}
}
