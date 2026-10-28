package postgres

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/ctis/outcome"

	commandapp "github.com/openctemio/openctem/api/internal/app/command"
	"github.com/openctemio/openctem/api/pkg/domain/command"
	"github.com/openctemio/openctem/api/pkg/domain/scanrun"
	"github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// A routed job that fails for a reason that is not the target's moves to
// another eligible sensor, excluding every sensor that failed it
// (research/302 B1, B3, B7). Against the real SQL, as the app role.

func (f *refusalFixture) infraFail(sensorID, cmdID shared.ID, class, msg string, ev command.FailureEvidence) (*command.Command, error) {
	f.t.Helper()
	return f.svc.Fail(f.ctx, commandapp.FailInput{TenantID: f.tenant.String(), SensorID: sensorID.String(),
		CommandID: cmdID.String(), ErrorMessage: msg, Infra: &commandapp.InfraReport{Class: class, Evidence: ev}})
}

func (f *refusalFixture) mustInfraFail(sensorID, cmdID shared.ID, class, msg string, ev command.FailureEvidence) *command.Command {
	f.t.Helper()
	out, err := f.infraFail(sensorID, cmdID, class, msg, ev)
	if err != nil {
		f.t.Fatalf("fail: %v", err)
	}
	return out
}

func (f *refusalFixture) eventCodes(cmdID shared.ID) []string {
	f.t.Helper()
	rows, err := f.cmds.db.QueryContext(f.ctx, `SELECT event, COALESCE(code, '') FROM command_events WHERE command_id = $1 AND tenant_id = $2 ORDER BY id`,
		cmdID.String(), f.tenant.String())
	if err != nil {
		f.t.Fatal(err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var ev, code string
		if err := rows.Scan(&ev, &code); err != nil {
			f.t.Fatal(err)
		}
		out = append(out, ev+":"+code)
	}
	if err := rows.Err(); err != nil {
		f.t.Fatal(err)
	}
	return out
}

func TestInfra_MovedToAnotherSensorExcludesFailedOne(t *testing.T) {
	f, ids := newRefusalFixture(t, 2)
	a, b := ids[0], ids[1]
	job := f.claimableJob(true)
	if !f.claim(a)[job] {
		t.Fatal("sensor A did not claim the job")
	}
	out := f.mustInfraFail(a, job, "infra.tool_crashed", "nuclei crashed", command.FailureEvidence{Tool: "nuclei", Signal: "SIGSEGV"})
	if out.Status != command.CommandStatusPending || out.SensorID != nil {
		t.Fatalf("after A failed: status %s sensor %v, want pending and unpinned", out.Status, out.SensorID)
	}
	if out.ScanZoneID == nil || *out.ScanZoneID != f.zone {
		t.Fatal("the move dropped the zone")
	}
	if !strings.Contains(out.ErrorMessage, "Moved to another sensor") || !strings.Contains(out.ErrorMessage, "nuclei crashed") {
		t.Fatalf("move reason %q", out.ErrorMessage)
	}
	if f.claim(a)[job] {
		t.Fatal("the failing sensor claimed the job again")
	}
	if _, err := f.svc.Acknowledge(f.ctx, f.tenant.String(), a.String(), job.String()); err == nil {
		t.Fatal("the failing sensor claimed the job by id")
	}
	if !f.claim(b)[job] {
		t.Fatal("sensor B did not get the moved job")
	}
	// The timeline says why it moved.
	codes := f.eventCodes(job)
	if !strings.Contains(strings.Join(codes, ","), "requeued:moved.tool_crashed") {
		t.Fatalf("events %v lack the move with its reason", codes)
	}
	// The placement explainer names the exclusion.
	_, claims, err := f.cmds.PlacementPredicates(f.ctx, f.tenant, job, 10)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range claims {
		if c.SensorID == a && c.NotFailedHere {
			t.Fatal("placement does not show the failing sensor as excluded")
		}
		if c.SensorID == b && !c.NotFailedHere {
			t.Fatal("placement excludes the sensor that did not fail")
		}
	}
	// B has no other sensor to hand it to: the failure states both causes.
	out = f.mustInfraFail(b, job, "infra.resource.disk", "write: no space left on device", command.FailureEvidence{})
	if out.Status != command.CommandStatusFailed {
		t.Fatalf("after B failed: %s, want failed (no other sensor)", out.Status)
	}
	for _, want := range []string{"nuclei crashed", "ran out of disk space", "no other eligible sensor", sensorShort(a), sensorShort(b)} {
		if !strings.Contains(out.ErrorMessage, want) {
			t.Fatalf("failure reason %q lacks %q", out.ErrorMessage, want)
		}
	}
	if out.FailureCode != scanrun.FailureResourceExhausted {
		t.Fatalf("failure code %q", out.FailureCode)
	}
	atts, err := f.cmds.CommandAttempts(f.ctx, f.tenant, job)
	if err != nil || len(atts) != 2 || atts[0].SensorID != a.String() || atts[1].Class != command.ClassResourceDisk {
		t.Fatalf("recorded attempts %+v err %v", atts, err)
	}
}

// claimableJob is a routed or unrouted job that has waited past the
// claim-balance window, so the first sensor to ask takes it instead of
// yielding a fresh task to an idle peer (these tests claim as one sensor).
func (f *refusalFixture) claimableJob(routed bool) shared.ID {
	f.t.Helper()
	job := f.routedJob(routed)
	if _, err := f.cmds.db.ExecContext(f.ctx, `UPDATE commands SET created_at = NOW() - INTERVAL '1 minute' WHERE id = $1`, job.String()); err != nil {
		f.t.Fatal(err)
	}
	return job
}

func sensorShort(id shared.ID) string { return id.String()[:8] }

// The budget of 3 attempts per command is shared by every cause: a refusal,
// then two infrastructure failures, end the command although a fourth
// sensor is available, and the reason lists the causes.
func TestInfra_BudgetSharedWithRefusals(t *testing.T) {
	f, ids := newRefusalFixture(t, 4)
	job := f.claimableJob(true)
	if !f.claim(ids[0])[job] {
		t.Fatal("A did not claim")
	}
	f.refuse(ids[0], job, &sensor.DispatchRefusal{Layer: "local", Rule: "ports.allow"}, "")
	if !f.claim(ids[1])[job] {
		t.Fatal("B did not claim")
	}
	if out := f.mustInfraFail(ids[1], job, "infra.resource.memory", "out of memory", command.FailureEvidence{}); out.Status != command.CommandStatusPending {
		t.Fatalf("second attempt: %s, want moved", out.Status)
	}
	if !f.claim(ids[2])[job] {
		t.Fatal("C did not claim")
	}
	out := f.mustInfraFail(ids[2], job, "infra.resource.disk", "disk full", command.FailureEvidence{})
	if out.Status != command.CommandStatusFailed {
		t.Fatalf("third attempt: %s, want failed (budget spent, a 4th sensor exists)", out.Status)
	}
	if strings.Contains(out.ErrorMessage, "Max dispatch attempts") || !strings.Contains(out.ErrorMessage, "ran out of memory") ||
		!strings.Contains(out.ErrorMessage, "ran out of disk space") {
		t.Fatalf("failure reason %q does not state the causes", out.ErrorMessage)
	}
	if f.claim(ids[3])[job] {
		t.Fatal("a failed job was offered again")
	}
}

// A fact about the target is never moved, nor a code that names another
// kind of failure; a command a person addressed fails as before.
func TestInfra_TargetSideAndUnroutedNeverMoved(t *testing.T) {
	f, ids := newRefusalFixture(t, 2)
	for _, class := range []string{"target.edge_blocked", "target.edge_challenged", "target.rate_limited", "target.unreachable", "infra.resource.output_limit"} {
		job := f.claimableJob(true)
		if !f.claim(ids[0])[job] {
			t.Fatalf("%s: not claimed", class)
		}
		out := f.mustInfraFail(ids[0], job, class, "the target answered", command.FailureEvidence{})
		if out.Status != command.CommandStatusFailed {
			t.Fatalf("%s: %s, want failed (never resent elsewhere)", class, out.Status)
		}
		if f.claim(ids[1])[job] {
			t.Fatalf("%s: offered to another sensor", class)
		}
	}
	// A TOOL_EXIT code with a crash-like text is the sensor's own verdict.
	job := f.claimableJob(true)
	f.claim(ids[0])
	out, err := f.svc.Fail(f.ctx, commandapp.FailInput{TenantID: f.tenant.String(), SensorID: ids[0].String(), CommandID: job.String(),
		ErrorMessage: "tool crashed", Infra: &commandapp.InfraReport{ErrorCode: "TOOL_EXIT"}})
	if err != nil || out.Status != command.CommandStatusFailed {
		t.Fatalf("TOOL_EXIT: %v %v", out, err)
	}
	// Not routed work.
	pinned := f.claimableJob(false)
	if !f.claim(ids[0])[pinned] {
		t.Fatal("unrouted not claimed")
	}
	if out := f.mustInfraFail(ids[0], pinned, "infra.tool_crashed", "crashed", command.FailureEvidence{}); out.Status != command.CommandStatusFailed {
		t.Fatalf("unrouted: %s, want failed", out.Status)
	}
}

// Without a class a sensor that predates the field is read by its text and
// its error code.
func TestInfra_TextAndErrorCodeFallback(t *testing.T) {
	f, ids := newRefusalFixture(t, 2)
	job := f.claimableJob(true)
	f.claim(ids[0])
	out, err := f.svc.Fail(f.ctx, commandapp.FailInput{TenantID: f.tenant.String(), SensorID: ids[0].String(), CommandID: job.String(),
		ErrorMessage: `exec: "nuclei": executable file not found in $PATH`})
	if err != nil || out.Status != command.CommandStatusPending {
		t.Fatalf("text fallback: %v %v", out, err)
	}
	job2 := f.claimableJob(true)
	f.claim(ids[0])
	out, err = f.svc.Fail(f.ctx, commandapp.FailInput{TenantID: f.tenant.String(), SensorID: ids[0].String(), CommandID: job2.String(),
		ErrorMessage: "the run failed", Infra: &commandapp.InfraReport{ErrorCode: "RESOURCE_MEMORY"}})
	if err != nil || out.Status != command.CommandStatusPending {
		t.Fatalf("error code: %v %v", out, err)
	}
	// A plain failure with no infrastructure sign fails as before.
	job3 := f.claimableJob(true)
	f.claim(ids[0])
	out, err = f.svc.Fail(f.ctx, commandapp.FailInput{TenantID: f.tenant.String(), SensorID: ids[0].String(), CommandID: job3.String(), ErrorMessage: "scan failed"})
	if err != nil || out.Status != command.CommandStatusFailed {
		t.Fatalf("plain failure: %v %v", out, err)
	}
}

// Fleet stop rule: the same tool and content version failing on two
// sensors ends the command and the next ones, instead of bouncing across
// the fleet; another version is not affected.
func TestInfra_FleetStopRuleAfterTwoSensors(t *testing.T) {
	f, ids := newRefusalFixture(t, 4)
	ev := command.FailureEvidence{Tool: "nuclei", ToolDigest: "sha256:aaaa", ContentDigest: "sha256:c1"}
	job := f.claimableJob(true)
	if !f.claim(ids[0])[job] {
		t.Fatal("A did not claim")
	}
	if out := f.mustInfraFail(ids[0], job, "infra.tool_crashed", "crashed", ev); out.Status != command.CommandStatusPending {
		t.Fatalf("first failure: %s, want moved", out.Status)
	}
	if !f.claim(ids[1])[job] {
		t.Fatal("B did not claim")
	}
	out := f.mustInfraFail(ids[1], job, "infra.tool_crashed", "crashed", ev)
	if out.Status != command.CommandStatusFailed || out.FailureCode != scanrun.FailureFleetToolFailure {
		t.Fatalf("second sensor: status %s code %q, want failed FLEET_TOOL_FAILURE (sensors C and D exist)", out.Status, out.FailureCode)
	}
	if !strings.Contains(out.ErrorMessage, "nuclei") || !strings.Contains(out.ErrorMessage, "not moved to more sensors") {
		t.Fatalf("stop reason %q", out.ErrorMessage)
	}
	// Another command with the same tool version stops at its first failure.
	job2 := f.claimableJob(true)
	if !f.claim(ids[2])[job2] {
		t.Fatal("C did not claim")
	}
	if out := f.mustInfraFail(ids[2], job2, "infra.tool_crashed", "crashed", ev); out.Status != command.CommandStatusFailed {
		t.Fatalf("while the rule holds: %s, want failed", out.Status)
	}
	// Another version of the tool is not affected.
	job3 := f.claimableJob(true)
	if !f.claim(ids[3])[job3] {
		t.Fatal("D did not claim")
	}
	ev2 := ev
	ev2.ToolDigest = "sha256:bbbb"
	if out := f.mustInfraFail(ids[3], job3, "infra.tool_crashed", "crashed", ev2); out.Status != command.CommandStatusPending {
		t.Fatalf("other tool version: %s, want moved", out.Status)
	}
	// The rule is per tenant.
	var n int
	if err := f.cmds.db.QueryRowContext(f.ctx, `SELECT count(*) FROM failure_breakers WHERE tenant_id <> $1 AND tool = 'nuclei'`, f.tenant.String()).Scan(&n); err != nil || n != 0 {
		t.Fatalf("breaker rows of other tenants: %d %v", n, err)
	}
}

// The rule expires: after its hold, a failure counts afresh.
func TestInfra_FleetStopRuleExpires(t *testing.T) {
	f, ids := newRefusalFixture(t, 2)
	key := command.FleetKey{Tool: "nuclei", ToolDigest: "sha256:aaaa"}
	now := time.Now()
	a, b := ids[0], ids[1]
	if tripped, err := f.cmds.RecordFleetFailure(f.ctx, f.tenant, key, a, command.ClassToolCrashed, now); err != nil || tripped {
		t.Fatalf("one sensor: %v %v", tripped, err)
	}
	if tripped, err := f.cmds.RecordFleetFailure(f.ctx, f.tenant, key, a, command.ClassToolCrashed, now); err != nil || tripped {
		t.Fatalf("the same sensor twice: %v %v", tripped, err)
	}
	if tripped, err := f.cmds.RecordFleetFailure(f.ctx, f.tenant, key, b, command.ClassToolCrashed, now); err != nil || !tripped {
		t.Fatalf("two sensors: %v %v", tripped, err)
	}
	later := now.Add(command.FleetBreakerHold + time.Minute)
	if tripped, err := f.cmds.RecordFleetFailure(f.ctx, f.tenant, key, a, command.ClassToolCrashed, later); err != nil || tripped {
		t.Fatalf("after the hold: %v %v", tripped, err)
	}
	// Failures further apart than the window do not add up.
	key2 := command.FleetKey{Tool: "httpx"}
	if _, err := f.cmds.RecordFleetFailure(f.ctx, f.tenant, key2, a, command.ClassToolCrashed, now); err != nil {
		t.Fatal(err)
	}
	if tripped, err := f.cmds.RecordFleetFailure(f.ctx, f.tenant, key2, b, command.ClassToolCrashed, now.Add(command.FleetBreakerWindow+time.Minute)); err != nil || tripped {
		t.Fatalf("outside the window: %v %v", tripped, err)
	}
}

// A sensor that loses its lease is excluded when another sensor can take
// the job; with no other sensor it gets it back. A pinned command goes back
// to its sensor. The exhausted sweep states the causes.
func TestInfra_LostLeaseExcludesHolderWhenAnotherCanTake(t *testing.T) {
	f, ids := newRefusalFixture(t, 2)
	a, b := ids[0], ids[1]
	job := f.claimableJob(true)
	if !f.claim(a)[job] {
		t.Fatal("A did not claim")
	}
	f.expireLease(job)
	if _, err := f.cmds.RequeueExpiredLeases(f.ctx); err != nil {
		t.Fatal(err)
	}
	if f.claim(a)[job] {
		t.Fatal("the sensor that lost the lease claimed the job again although B can take it")
	}
	if !f.claim(b)[job] {
		t.Fatal("B did not get the job")
	}
	if codes := strings.Join(f.eventCodes(job), ","); !strings.Contains(codes, "requeued:moved.sensor_offline") {
		t.Fatalf("events %s lack the move after the lost lease", codes)
	}

	// Alone in the tenant, the sensor keeps the job.
	g, ids2 := newRefusalFixture(t, 1)
	solo := g.routedJob(true)
	if !g.claim(ids2[0])[solo] {
		t.Fatal("solo did not claim")
	}
	g.expireLease(solo)
	if _, err := g.cmds.RequeueExpiredLeases(g.ctx); err != nil {
		t.Fatal(err)
	}
	if !g.claim(ids2[0])[solo] {
		t.Fatal("the only sensor was locked out of its own job")
	}
}

func (f *refusalFixture) expireLease(id shared.ID) {
	f.t.Helper()
	if _, err := f.cmds.db.ExecContext(f.ctx, `UPDATE commands SET lease_expires_at = NOW() - interval '1 minute' WHERE id = $1 AND tenant_id = $2`,
		id.String(), f.tenant.String()); err != nil {
		f.t.Fatal(err)
	}
}

func TestInfra_ExhaustedSweepStatesTheCauses(t *testing.T) {
	f, ids := newRefusalFixture(t, 3)
	job := f.claimableJob(true)
	for i := range 3 {
		if !f.claim(ids[i])[job] {
			t.Fatalf("sensor %d did not claim", i)
		}
		f.expireLease(job)
		if _, err := f.cmds.RequeueExpiredLeases(f.ctx); err != nil {
			t.Fatal(err)
		}
		// Skip the re-queue back-off.
		if _, err := f.cmds.db.ExecContext(f.ctx, `UPDATE commands SET scheduled_at = NULL WHERE id = $1`, job.String()); err != nil {
			t.Fatal(err)
		}
	}
	failed, err := f.cmds.FailExhaustedCommandsReturning(f.ctx, command.MaxDispatchAttempts)
	if err != nil {
		t.Fatal(err)
	}
	var got *command.Command
	for _, c := range failed {
		if c.ID == job {
			got = c
		}
	}
	if got == nil {
		t.Fatal("the exhausted job was not failed")
	}
	if strings.Contains(got.ErrorMessage, "Max dispatch attempts") || !strings.Contains(got.ErrorMessage, "infra.sensor_offline") ||
		!strings.Contains(got.ErrorMessage, sensorShort(ids[0])) || got.FailureCode != scanrun.FailureSensorLost {
		t.Fatalf("reason %q code %q", got.ErrorMessage, got.FailureCode)
	}
}

// The fence stays: a stale lease epoch cannot fail the command, and a late
// completion by the sensor that failed it changes nothing.
func TestInfra_FencingAndLateResult(t *testing.T) {
	f, ids := newRefusalFixture(t, 2)
	a, b := ids[0], ids[1]
	job := f.claimableJob(true)
	f.claim(a)
	cmd, err := f.cmds.GetByTenantAndID(f.ctx, f.tenant, job)
	if err != nil {
		t.Fatal(err)
	}
	stale := cmd.LeaseEpoch - 1
	_, err = f.svc.Fail(f.ctx, commandapp.FailInput{TenantID: f.tenant.String(), SensorID: a.String(), CommandID: job.String(),
		ErrorMessage: "crashed", LeaseEpoch: &stale, Infra: &commandapp.InfraReport{Class: "infra.tool_crashed"}})
	if !errors.Is(err, commandapp.ErrLeaseLost) {
		t.Fatalf("stale epoch: %v, want lease lost", err)
	}
	if cur, _ := f.cmds.GetByTenantAndID(f.ctx, f.tenant, job); cur.Status == command.CommandStatusPending {
		t.Fatal("a stale-epoch failure moved the command")
	}
	f.mustInfraFail(a, job, "infra.tool_crashed", "crashed", command.FailureEvidence{})
	// A late result from A is refused; B's stands.
	late, _ := json.Marshal(map[string]any{"status": "completed", "findings": 1})
	if _, err := f.svc.Complete(f.ctx, commandapp.CompleteInput{TenantID: f.tenant.String(), SensorID: a.String(), CommandID: job.String(), Result: late}); err == nil {
		t.Fatal("the sensor that failed the job completed it afterwards")
	}
	f.claim(b)
	if cur, _ := f.cmds.GetByTenantAndID(f.ctx, f.tenant, job); len(cur.Result) > 0 {
		t.Fatalf("a late result was stored: %s", cur.Result)
	}
}

// Another organization's sensor can neither fail nor see a command, and a
// failure never excludes or moves across organizations.
func TestInfra_CrossTenant(t *testing.T) {
	f, ids := newRefusalFixture(t, 2)
	job := f.claimableJob(true)
	f.claim(ids[0])
	g, gids := newRefusalFixture(t, 1)
	_, err := g.svc.Fail(g.ctx, commandapp.FailInput{TenantID: g.tenant.String(), SensorID: gids[0].String(), CommandID: job.String(),
		ErrorMessage: "crashed", Infra: &commandapp.InfraReport{Class: "infra.tool_crashed"}})
	if !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("foreign tenant: %v, want not found", err)
	}
	cur, _ := f.cmds.GetByTenantAndID(f.ctx, f.tenant, job)
	if cur.Status == command.CommandStatusPending || cur.Status == command.CommandStatusFailed {
		t.Fatalf("foreign failure changed the command: %s", cur.Status)
	}
	// The store itself is tenant-scoped.
	if atts, err := g.cmds.CommandAttempts(g.ctx, g.tenant, job); err == nil && len(atts) > 0 {
		t.Fatal("read another tenant's attempts")
	}
	if ok, err := g.cmds.RequeueFailed(g.ctx, g.tenant, job, command.Fence{SensorID: ids[0].String(), Status: cur.Status, Epoch: cur.LeaseEpoch},
		command.InfraAttempt{SensorID: ids[0].String(), Class: command.ClassToolCrashed, At: time.Now()}, "x"); err != nil || ok {
		t.Fatalf("foreign re-queue applied: %v %v", ok, err)
	}
}

// B3: targets the sensor's own network failed go out again on another
// sensor; facts about the target are never resent.
func TestInfra_SensorSideTargetsGoOutOnAnotherSensor(t *testing.T) {
	f, ids := newRefusalFixture(t, 2)
	a, b := ids[0], ids[1]
	targets := []string{"10.60.0.1", "10.60.0.2", "10.60.0.3", "10.60.0.4", "10.60.0.5", "10.60.0.6"}
	job := f.stepJob(targets)
	if !f.claim(a)[job] {
		t.Fatal("A did not claim")
	}
	outs := []outcome.Target{
		{Target: targets[0], State: outcome.Done},
		{Target: targets[1], State: outcome.Failed, Class: outcome.SensorNetworkFault, Cause: outcome.CauseSensor},
		{Target: targets[2], State: outcome.Failed, Class: outcome.EdgeBlocked, Cause: outcome.CauseTarget},
		{Target: targets[3], State: outcome.Failed, Class: outcome.Unreachable, Cause: outcome.CauseTarget},
		{Target: targets[4], State: outcome.Failed, Class: outcome.RateLimited, Cause: outcome.CauseTarget},
		{Target: targets[5], State: outcome.Failed, Class: outcome.ToolError},
	}
	res, _ := json.Marshal(map[string]any{"status": "completed", "target_outcomes": outs})
	if _, err := f.svc.Start(f.ctx, f.tenant.String(), a.String(), job.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.Complete(f.ctx, commandapp.CompleteInput{TenantID: f.tenant.String(), SensorID: a.String(), CommandID: job.String(), Result: res}); err != nil {
		t.Fatalf("complete: %v", err)
	}
	var fuID string
	var failedOn string
	var fuTargets string
	err := f.cmds.db.QueryRowContext(f.ctx, `SELECT id, failed_on::text, payload->>'targets' FROM commands WHERE retry_of = $1 AND tenant_id = $2`,
		job.String(), f.tenant.String()).Scan(&fuID, &failedOn, &fuTargets)
	if err != nil {
		t.Fatalf("no follow-up: %v", err)
	}
	if fuTargets != `["10.60.0.2"]` {
		t.Fatalf("follow-up targets %s, want only the sensor-side one (edge block, unreachable, rate limit and tool error stay settled)", fuTargets)
	}
	if !strings.Contains(failedOn, a.String()) {
		t.Fatalf("follow-up failed_on %s lacks the parent's sensor", failedOn)
	}
	fid, _ := shared.IDFromString(fuID)
	if f.claim(a)[fid] {
		t.Fatal("the sensor whose network failed took the targets again")
	}
	if !f.claim(b)[fid] {
		t.Fatal("the other sensor did not get the follow-up")
	}
}

// With no other sensor to take them, sensor-side targets stay settled (no
// doomed follow-up).
func TestInfra_SensorSideTargetsStaySettledWithoutAnotherSensor(t *testing.T) {
	f, ids := newRefusalFixture(t, 1)
	targets := []string{"10.60.0.1", "10.60.0.2"}
	job := f.stepJob(targets)
	f.claim(ids[0])
	outs := []outcome.Target{
		{Target: targets[0], State: outcome.Done},
		{Target: targets[1], State: outcome.Failed, Class: outcome.SensorNetworkFault, Cause: outcome.CauseSensor},
	}
	res, _ := json.Marshal(map[string]any{"status": "completed", "target_outcomes": outs})
	if _, err := f.svc.Start(f.ctx, f.tenant.String(), ids[0].String(), job.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.Complete(f.ctx, commandapp.CompleteInput{TenantID: f.tenant.String(), SensorID: ids[0].String(), CommandID: job.String(), Result: res}); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := f.cmds.db.QueryRowContext(f.ctx, `SELECT count(*) FROM commands WHERE retry_of = $1`, job.String()).Scan(&n); err != nil || n != 0 {
		t.Fatalf("follow-ups %d %v, want none", n, err)
	}
}

// stepJob creates a zone scan of a workflow step run (routed work whose
// follow-ups are read) over targets.
func (f *refusalFixture) stepJob(targets []string) shared.ID {
	f.t.Helper()
	stepRun := seedChunkStepRun(f.ctx, f.t, f.cmds.db.DB, f.tenant)
	raw, _ := json.Marshal(map[string]any{"scanner": "nuclei", "targets": targets,
		"scan_run_id": shared.NewID().String(), "step_key": "probe", "scan_run_step_id": stepRun.String()})
	cmd, err := command.NewCommand(f.tenant, command.CommandTypeScan, command.CommandPriorityNormal, raw)
	if err != nil {
		f.t.Fatal(err)
	}
	cmd.SetStepRunID(stepRun)
	cmd.SetScanZone(f.zone)
	if err := f.cmds.Create(f.ctx, cmd); err != nil {
		f.t.Fatal(err)
	}
	return cmd.ID
}
