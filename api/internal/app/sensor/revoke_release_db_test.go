package sensor_test

// RFC-040 §5.2, "revocation reaches running work": revoking or disabling a
// sensor takes back the commands it holds under a lease at once, instead of
// leaving them with it until the lease runs out, and its late results are
// refused by the RFC-035 fence.

import (
	"context"
	"encoding/json"
	"testing"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	commandapp "github.com/openctemio/openctem/api/internal/app/command"
	sensorapp "github.com/openctemio/openctem/api/internal/app/sensor"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/command"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

type releaseHarness struct {
	*activityHarness
	cmds   *postgres.CommandRepository
	cmdSvc *commandapp.Service
	svc    *sensorapp.SensorService
	tenant shared.ID
}

func newReleaseHarness(t *testing.T) *releaseHarness {
	h := &releaseHarness{activityHarness: newActivityHarness(t)}
	db := &postgres.DB{DB: h.db}
	h.cmds = postgres.NewCommandRepository(db)
	h.cmdSvc = commandapp.NewService(h.cmds, logger.NewNop())
	h.svc = sensorapp.NewSensorService(postgres.NewSensorRepository(db),
		auditapp.NewAuditService(postgres.NewAuditRepository(db), logger.NewNop()), logger.NewNop())
	h.svc.SetHolderReleaser(h.cmds)
	h.tenant = h.activityHarness.tenant()
	t.Cleanup(func() {
		_, _ = h.db.ExecContext(context.Background(), `DELETE FROM audit_logs WHERE tenant_id = $1`, h.tenant.String())
	})
	return h
}

// command creates a command; pinTo addresses it to one sensor.
func (h *releaseHarness) command(typ command.CommandType, payload map[string]any, pinTo *shared.ID) shared.ID {
	h.t.Helper()
	raw, _ := json.Marshal(payload)
	cmd, err := command.NewCommand(h.tenant, typ, command.CommandPriorityNormal, raw)
	if err != nil {
		h.t.Fatal(err)
	}
	if pinTo != nil {
		cmd.SetSensorID(*pinTo)
	}
	if err := h.cmds.Create(context.Background(), cmd); err != nil {
		h.t.Fatal(err)
	}
	return cmd.ID
}

func (h *releaseHarness) in(sensorID, cmdID shared.ID) commandapp.TransitionInput {
	return commandapp.TransitionInput{TenantID: h.tenant.String(), SensorID: sensorID.String(), CommandID: cmdID.String()}
}

// hold has sensorID claim cmdID and, when start is set, start it.
func (h *releaseHarness) hold(sensorID, cmdID shared.ID, start bool) *command.Command {
	h.t.Helper()
	trs := []commandapp.Transition{commandapp.TransitionClaim}
	if start {
		trs = append(trs, commandapp.TransitionStart)
	}
	for _, tr := range trs {
		if _, err := h.cmdSvc.Transition(context.Background(), tr, h.in(sensorID, cmdID)); err != nil {
			h.t.Fatalf("%s %s: %v", tr, cmdID, err)
		}
	}
	return h.get(cmdID)
}

func (h *releaseHarness) get(id shared.ID) *command.Command {
	h.t.Helper()
	c, err := h.cmds.GetByTenantAndID(context.Background(), h.tenant, id)
	if err != nil {
		h.t.Fatal(err)
	}
	return c
}

// lateResults sends what the old holder would send after it lost cmd:
// a complete through the transition service, and a complete that read the
// command before the release (the race the fence closes). Both must fail.
func (h *releaseHarness) lateResults(holder shared.ID, before *command.Command) {
	h.t.Helper()
	done := h.in(holder, before.ID)
	done.Result = json.RawMessage(`{"by":"withdrawn"}`)
	if _, err := h.cmdSvc.Transition(context.Background(), commandapp.TransitionComplete, done); err == nil {
		h.t.Fatalf("command %s: a late completion from the withdrawn sensor was accepted", before.ID)
	}
	stale := *before
	fence := command.Fence{SensorID: holder.String(), Status: before.Status, Epoch: before.LeaseEpoch}
	stale.Complete(json.RawMessage(`{"by":"withdrawn"}`))
	if ok, err := h.cmds.FencedUpdate(context.Background(), &stale, fence); err != nil || ok {
		h.t.Fatalf("command %s: a stale completion applied: %v %v", before.ID, ok, err)
	}
}

func (h *releaseHarness) auditRow(sensorID shared.ID) (requeued, failed []string, actor string) {
	h.t.Helper()
	var meta []byte
	if err := h.db.QueryRowContext(context.Background(), `
		SELECT metadata, COALESCE(actor_email, '') FROM audit_logs
		WHERE tenant_id = $1 AND action = 'sensor.commands_released' AND resource_id = $2`,
		h.tenant.String(), sensorID.String()).Scan(&meta, &actor); err != nil {
		h.t.Fatalf("no sensor.commands_released audit entry: %v", err)
	}
	var m struct {
		Requeued []string `json:"requeued_command_ids"`
		Failed   []string `json:"failed_command_ids"`
	}
	if err := json.Unmarshal(meta, &m); err != nil {
		h.t.Fatal(err)
	}
	return m.Requeued, m.Failed, actor
}

func TestRevokeSensor_ReleasesLeasedCommands_DB(t *testing.T) {
	h := newReleaseHarness(t)
	ctx := context.Background()
	a, b := h.sensor(h.tenant), h.sensor(h.tenant)

	// Routed scan work A is running, routed work it only claimed, a plain
	// scan sent to A by id, A's config update, and B's own work.
	routed := map[string]any{"scan_run_id": shared.NewID().String(), "step_key": "scan", "target": "10.9.0.1"}
	running := h.command(command.CommandTypeScan, routed, nil)
	claimed := h.command(command.CommandTypeScan, routed, nil)
	plain := h.command(command.CommandTypeScan, map[string]any{"target": "10.9.0.2"}, &a)
	config := h.command(command.CommandTypeConfigUpdate, map[string]any{"interval": 30}, &a)
	other := h.command(command.CommandTypeScan, routed, nil)
	before := map[shared.ID]*command.Command{
		running: h.hold(a, running, true),
		claimed: h.hold(a, claimed, false),
		plain:   h.hold(a, plain, true),
		config:  h.hold(a, config, false),
	}
	h.hold(b, other, true)

	actor := auditapp.AuditContext{TenantID: h.tenant.String(), ActorEmail: "admin@example.test"}
	if _, err := h.svc.RevokeSensor(ctx, h.tenant.String(), a.String(), "key leaked", &actor); err != nil {
		t.Fatal(err)
	}

	// Routed work is back in the queue at once: unpinned, no lease, not
	// counted as a dispatch attempt.
	for _, id := range []shared.ID{running, claimed} {
		c := h.get(id)
		if c.Status != command.CommandStatusPending || c.SensorID != nil || c.LeaseExpiresAt != nil ||
			c.StartedAt != nil || c.DispatchAttempts != 0 || c.ErrorMessage != command.SensorRevokedRequeuedMessage {
			t.Fatalf("routed %s: status %s sensor %v lease %v started %v attempts %d msg %q",
				id, c.Status, c.SensorID, c.LeaseExpiresAt, c.StartedAt, c.DispatchAttempts, c.ErrorMessage)
		}
	}
	// Work addressed to A only is failed with the reason.
	for _, id := range []shared.ID{plain, config} {
		c := h.get(id)
		if c.Status != command.CommandStatusFailed || c.CompletedAt == nil || c.LeaseExpiresAt != nil ||
			c.ErrorMessage != command.SensorRevokedFailedMessage {
			t.Fatalf("pinned %s: status %s completed %v lease %v msg %q", id, c.Status, c.CompletedAt, c.LeaseExpiresAt, c.ErrorMessage)
		}
	}
	// B's command is untouched.
	if c := h.get(other); c.Status != command.CommandStatusRunning || c.SensorID == nil || *c.SensorID != b {
		t.Fatalf("another sensor's command changed: %s %v", c.Status, c.SensorID)
	}

	// A's late results are refused, for every command it held.
	for _, c := range before {
		h.lateResults(a, c)
	}

	// B picks the re-queued scan up and completes it.
	h.hold(b, running, true)
	bDone := h.in(b, running)
	bDone.Result = json.RawMessage(`{"by":"B"}`)
	if res, err := h.cmdSvc.Transition(ctx, commandapp.TransitionComplete, bDone); err != nil ||
		res.Command.Status != command.CommandStatusCompleted {
		t.Fatalf("B completing the re-queued scan: %v", err)
	}

	// The release is audited, under the administrator who revoked.
	requeued, failed, who := h.auditRow(a)
	if len(requeued) != 2 || len(failed) != 2 || who != "admin@example.test" {
		t.Fatalf("audit: requeued %v failed %v actor %q", requeued, failed, who)
	}
}

func TestDisableSensor_ReleasesLeasedCommands_DB(t *testing.T) {
	h := newReleaseHarness(t)
	ctx := context.Background()

	// DisableSensor and PUT /sensors/{id} {"status":"disabled"} both release.
	for _, disable := range []func(id shared.ID) error{
		func(id shared.ID) error {
			_, err := h.svc.DisableSensor(ctx, h.tenant.String(), id.String(), "", nil)
			return err
		},
		func(id shared.ID) error {
			_, err := h.svc.UpdateSensor(ctx, sensorapp.UpdateSensorInput{
				TenantID: h.tenant.String(), SensorID: id.String(), Status: "disabled"})
			return err
		},
	} {
		a := h.sensor(h.tenant)
		routed := h.command(command.CommandTypeScan,
			map[string]any{"scan_run_id": shared.NewID().String(), "step_key": "scan"}, nil)
		before := h.hold(a, routed, true)
		if err := disable(a); err != nil {
			t.Fatal(err)
		}
		c := h.get(routed)
		if c.Status != command.CommandStatusPending || c.SensorID != nil || c.ErrorMessage != command.SensorDisabledRequeuedMessage {
			t.Fatalf("disabled: status %s sensor %v msg %q", c.Status, c.SensorID, c.ErrorMessage)
		}
		h.lateResults(a, before)
		// No administrator in the context: recorded as a system action.
		if requeued, _, who := h.auditRow(a); len(requeued) != 1 || who != "system" {
			t.Fatalf("audit: requeued %v actor %q", requeued, who)
		}
	}
}
