package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"testing"
	"time"

	commandapp "github.com/openctemio/openctem/api/internal/app/command"
	"github.com/openctemio/openctem/api/pkg/domain/command"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// Command leases (RFC-035 D6). Requires DATABASE_URL (CI applies every
// migration first).

func newLeaseTestCommand(ctx context.Context, t *testing.T, cmds *CommandRepository, tenant shared.ID) shared.ID {
	t.Helper()
	raw, _ := json.Marshal(map[string]any{"scanner": "nuclei", "target": "10.9.0.1"})
	cmd, err := command.NewCommand(tenant, command.CommandTypeScan, command.CommandPriorityNormal, raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := cmds.Create(ctx, cmd); err != nil {
		t.Fatal(err)
	}
	return cmd.ID
}

func expireLease(ctx context.Context, t *testing.T, db *sql.DB, id shared.ID) {
	t.Helper()
	if _, err := db.ExecContext(ctx, `UPDATE commands SET lease_expires_at = NOW() - INTERVAL '1 second' WHERE id = $1`, id.String()); err != nil {
		t.Fatal(err)
	}
}

func requeuedIDs(rq []command.RequeuedCommand) map[string]command.RequeuedCommand {
	out := map[string]command.RequeuedCommand{}
	for _, r := range rq {
		out[r.ID.String()] = r
	}
	return out
}

// A claim starts a lease epoch and a lease; a heartbeat that lists the
// command renews it, and a lease nobody renews puts the command back in the
// queue, unpinned, with one more dispatch attempt.
func TestCommandLease_ClaimRenewRequeue(t *testing.T) {
	sqlDB := openSensorDB(t)
	ctx := context.Background()
	defer lockGlobalSweep(ctx, t, sqlDB)()
	db := &DB{DB: sqlDB}
	cmds := NewCommandRepository(db)
	tenant := seedTestTenant(ctx, t, sqlDB)
	a := seedZoneSensor(ctx, t, sqlDB, &tenant, "a", zoneSensorOpts{tools: []string{"nuclei"}})

	kept := newLeaseTestCommand(ctx, t, cmds, tenant)
	lost := newLeaseTestCommand(ctx, t, cmds, tenant)
	for _, id := range []shared.ID{kept, lost} {
		ok, err := cmds.ClaimForSensor(ctx, tenant, id, a.String())
		if err != nil || !ok {
			t.Fatalf("claim %s: %v %v", id, ok, err)
		}
		got, err := cmds.GetByTenantAndID(ctx, tenant, id)
		if err != nil {
			t.Fatal(err)
		}
		if got.LeaseEpoch != 1 || got.LeaseExpiresAt == nil || time.Until(*got.LeaseExpiresAt) < 2*time.Minute {
			t.Fatalf("after the claim: epoch %d, lease %v", got.LeaseEpoch, got.LeaseExpiresAt)
		}
	}

	// Both leases run out; the heartbeat lists only "kept": it is renewed.
	expireLease(ctx, t, sqlDB, kept)
	expireLease(ctx, t, sqlDB, lost)
	if n, err := cmds.RenewLeases(ctx, tenant, a, []string{kept.String()}, false); err != nil || n != 1 {
		t.Fatalf("renew: %d %v", n, err)
	}
	rq, err := cmds.RequeueExpiredLeases(ctx)
	if err != nil {
		t.Fatal(err)
	}
	got := requeuedIDs(rq)
	if _, ok := got[kept.String()]; ok {
		t.Fatal("a renewed lease was re-queued")
	}
	r, ok := got[lost.String()]
	if !ok || r.Epoch != 1 || r.SensorID == nil || *r.SensorID != a {
		t.Fatalf("expired lease not re-queued with its holder: %+v", r)
	}
	c, err := cmds.GetByTenantAndID(ctx, tenant, lost)
	if err != nil {
		t.Fatal(err)
	}
	if c.Status != command.CommandStatusPending || c.SensorID != nil || c.LeaseExpiresAt != nil ||
		c.DispatchAttempts != 1 || c.ErrorMessage != command.LeaseExpiredMessage {
		t.Fatalf("re-queued command: status %s sensor %v lease %v attempts %d msg %q",
			c.Status, c.SensorID, c.LeaseExpiresAt, c.DispatchAttempts, c.ErrorMessage)
	}

	// A sensor that does not report what it runs renews all it holds.
	expireLease(ctx, t, sqlDB, kept)
	if n, err := cmds.RenewLeases(ctx, tenant, a, nil, true); err != nil || n != 1 {
		t.Fatalf("renew all: %d %v", n, err)
	}
	if rq, err := cmds.RequeueExpiredLeases(ctx); err != nil || requeuedIDs(rq)[kept.String()].ID == kept {
		t.Fatalf("a wholesale-renewed lease was re-queued: %v", err)
	}
}

// No duplicate completion: the sensor whose lease ran out cannot start,
// complete or fail the command once it was re-queued, whether it is still
// pending or already claimed by another sensor; the new holder completes it.
func TestCommandLease_NoCompletionAfterRequeue(t *testing.T) {
	sqlDB := openSensorDB(t)
	ctx := context.Background()
	defer lockGlobalSweep(ctx, t, sqlDB)()
	db := &DB{DB: sqlDB}
	cmds := NewCommandRepository(db)
	svc := commandapp.NewService(cmds, logger.NewNop())
	tenant := seedTestTenant(ctx, t, sqlDB)
	a := seedZoneSensor(ctx, t, sqlDB, &tenant, "a", zoneSensorOpts{tools: []string{"nuclei"}})
	b := seedZoneSensor(ctx, t, sqlDB, &tenant, "b", zoneSensorOpts{tools: []string{"nuclei"}})
	id := newLeaseTestCommand(ctx, t, cmds, tenant)
	in := func(s shared.ID) commandapp.TransitionInput {
		return commandapp.TransitionInput{TenantID: tenant.String(), SensorID: s.String(), CommandID: id.String()}
	}

	// A claims and starts it, then goes silent.
	for _, tr := range []commandapp.Transition{commandapp.TransitionClaim, commandapp.TransitionStart} {
		if _, err := svc.Transition(ctx, tr, in(a)); err != nil {
			t.Fatalf("A %s: %v", tr, err)
		}
	}
	stale, err := cmds.GetByTenantAndID(ctx, tenant, id) // what A's late completion read
	if err != nil {
		t.Fatal(err)
	}
	staleFence := command.Fence{SensorID: a.String(), Status: stale.Status, Epoch: stale.LeaseEpoch}
	expireLease(ctx, t, sqlDB, id)
	if rq, err := cmds.RequeueExpiredLeases(ctx); err != nil || len(requeuedIDs(rq)) == 0 {
		t.Fatalf("re-queue: %v", err)
	}

	// Re-queued, not yet claimed: A's completion is refused...
	aDone := commandapp.TransitionInput{TenantID: tenant.String(), SensorID: a.String(), CommandID: id.String(), Result: json.RawMessage(`{"by":"A"}`)}
	if _, err := svc.Transition(ctx, commandapp.TransitionComplete, aDone); err == nil {
		t.Fatal("A completed a command it no longer holds")
	}
	// ...and so is a completion that read the command before the re-queue
	// (the race the guarded write closes).
	stale.Complete(json.RawMessage(`{"by":"A"}`))
	if ok, err := cmds.FencedUpdate(ctx, stale, staleFence); err != nil || ok {
		t.Fatalf("stale completion applied: %v %v", ok, err)
	}

	// B claims it (epoch 2) and starts it; A is still refused, under its
	// stale epoch too.
	for _, tr := range []commandapp.Transition{commandapp.TransitionClaim, commandapp.TransitionStart} {
		if _, err := svc.Transition(ctx, tr, in(b)); err != nil {
			t.Fatalf("B %s: %v", tr, err)
		}
	}
	if _, err := svc.Transition(ctx, commandapp.TransitionComplete, aDone); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("A completing B's command: %v, want not found", err)
	}
	if ok, err := cmds.FencedUpdate(ctx, stale, staleFence); err != nil || ok {
		t.Fatalf("stale completion applied over B's claim: %v %v", ok, err)
	}
	// B says it holds epoch 1 (it does not): refused.
	one := 1
	bWrong := commandapp.TransitionInput{TenantID: tenant.String(), SensorID: b.String(), CommandID: id.String(),
		Result: json.RawMessage(`{"by":"B"}`), LeaseEpoch: &one}
	if _, err := svc.Transition(ctx, commandapp.TransitionComplete, bWrong); err == nil {
		t.Fatal("a completion under an old lease epoch was applied")
	}
	two := 2
	bDone := bWrong
	bDone.LeaseEpoch = &two
	res, err := svc.Transition(ctx, commandapp.TransitionComplete, bDone)
	if err != nil {
		t.Fatalf("B complete: %v", err)
	}
	if res.Command.Status != command.CommandStatusCompleted || res.Command.LeaseEpoch != 2 {
		t.Fatalf("B's completion: %+v", res.Command)
	}
	final, err := cmds.GetByTenantAndID(ctx, tenant, id)
	if err != nil {
		t.Fatal(err)
	}
	var result map[string]string
	_ = json.Unmarshal(final.Result, &result)
	if final.Status != command.CommandStatusCompleted || final.SensorID == nil || *final.SensorID != b ||
		result["by"] != "B" || final.LeaseExpiresAt != nil {
		t.Fatalf("final: status %s sensor %v result %s lease %v", final.Status, final.SensorID, final.Result, final.LeaseExpiresAt)
	}
	// Completed: nothing re-queues it, whatever its lease.
	if rq, err := cmds.RequeueExpiredLeases(ctx); err != nil || requeuedIDs(rq)[id.String()].ID == id {
		t.Fatalf("a completed command was re-queued: %v", err)
	}
}
