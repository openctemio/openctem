package routes

// Cross-tenant job isolation (research note 460, sensors.md "Tenant
// isolation of jobs"): an attacker holding organization A's credentials
// (A's sensor key, or a shared sensor that does not hold the job) tries every
// sensor route that takes a command or report id against organization B's
// jobs. Every attempt must fail exactly like an unknown id (same status, same
// problem body), and leave B's job, logs and reports untouched.
//
// These tests are a required CI gate (.github/scripts/cross-tenant-gate.sh,
// API CI "Security Gates (cross-tenant job isolation)"): renaming or removing
// one fails the build. They are never quarantined.

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	protov2 "github.com/openctemio/openctem/api/pkg/sensorproto/v2"
)

// xtJob is the state of a command an attacker must not change.
type xtJob struct {
	status, sensor string
	epoch          int
	result, errMsg sql.NullString
	logs, reports  int
}

func (h *ctlHarness) xtState(id string) xtJob {
	h.t.Helper()
	var j xtJob
	var sensor sql.NullString
	if err := h.db.QueryRowContext(context.Background(), `
		SELECT status, sensor_id::text, lease_epoch, result::text, error_message,
		       (SELECT count(*) FROM command_logs l WHERE l.command_id = c.id),
		       (SELECT count(*) FROM ingest_reports r WHERE r.command_id = c.id)
		FROM commands c WHERE id = $1`, id).Scan(&j.status, &sensor, &j.epoch, &j.result, &j.errMsg, &j.logs, &j.reports); err != nil {
		h.t.Fatalf("read command %s: %v", id, err)
	}
	j.sensor = sensor.String
	return j
}

// xtRunning makes command id running for holder under lease epoch 3.
func (h *ctlHarness) xtRunning(id, holder string) {
	h.t.Helper()
	if _, err := h.db.ExecContext(context.Background(), `
		UPDATE commands SET status = 'running', sensor_id = $2, lease_epoch = 3,
		       acknowledged_at = now(), started_at = now(), lease_expires_at = now() + interval '10 minutes'
		WHERE id = $1`, id, holder); err != nil {
		h.t.Fatal(err)
	}
}

// xtAttempt is one request an attacker sends with a command id.
type xtAttempt struct {
	name   string
	method string
	path   func(id string) string
	body   []byte
	hdr    []string
}

// xtCommandAttempts are every sensor route that takes a command id. Each
// states the lease epoch the victim's job holds, so a refusal can only come
// from the job not being the caller's.
func xtCommandAttempts() []xtAttempt {
	ctrl := func(action string) func(string) string {
		return func(id string) string { return "/api/v2/sensor/commands/" + id + "/" + action }
	}
	epoch := []string{protov2.HeaderLeaseEpoch, "3"}
	report := v2Segment("semgrep", "2.0", "xt-rule")
	logs, _ := json.Marshal(protov2.LogsRequest{Seq: 0, Lines: []protov2.LogLine{{TS: "2026-11-06T00:00:00Z", Level: "info", Msg: "xt"}}})
	egress, _ := json.Marshal(map[string]any{"lease_epoch": 3, "pool_id": shared.NewID().String(), "endpoints": []any{}})
	return []xtAttempt{
		{name: "claim", method: http.MethodPost, path: ctrl("claim")},
		{name: "start", method: http.MethodPost, path: ctrl("start")},
		{name: "complete", method: http.MethodPost, path: ctrl("complete"), body: []byte(`{"result":{"xt":true}}`), hdr: epoch},
		{name: "fail", method: http.MethodPost, path: ctrl("fail"), body: []byte(`{"error_message":"xt"}`), hdr: epoch},
		{name: "refusal", method: http.MethodPost, path: ctrl("fail"), hdr: epoch,
			body: []byte(`{"error_message":"refused","refusal":{"layer":"local_policy","rule":"r","detail":"d"}}`)},
		{name: "release", method: http.MethodPost, path: ctrl("release"), body: []byte(`{"reason":"xt"}`)},
		{name: "logs", method: http.MethodPost, path: ctrl("logs"), body: logs, hdr: epoch},
		{name: "egress-report", method: http.MethodPost, path: ctrl(protov2.EgressReportAction), body: egress},
		{name: "results", method: http.MethodPut, path: ctrl("results/" + newReportID()), body: report,
			hdr: append([]string{"Content-Type", protov2.MediaTypeCTIS, protov2.HeaderContentDigest, digestOf(report)}, epoch...)},
		{name: "commit", method: http.MethodPost, path: ctrl("results/" + newReportID() + "/commit"), body: []byte(`{}`), hdr: epoch},
	}
}

// xtRaiseWriteBurst lifts the per-sensor write budget for the test: the suite
// sends every command route twice (victim and unknown id) per victim from one
// sensor, which would otherwise answer 429 to the unknown id after the budget
// is spent and make the two answers differ for a reason that is not isolation.
// The budgets are exercised by their own tests.
func xtRaiseWriteBurst(t *testing.T) {
	t.Helper()
	old := v2WriteBurstPerSensor
	v2WriteBurstPerSensor = 1000
	t.Cleanup(func() { v2WriteBurstPerSensor = old })
}

// xtSame sends attempt a with key against victim and against an unknown id
// and fails unless both are refused identically (status and body, with the
// id itself masked). It returns the status.
func (h *ctlHarness) xtSame(key string, a xtAttempt, victim string) int {
	h.t.Helper()
	unknown := strings.ToLower(shared.NewID().String())
	send := func(id string) (int, string) {
		resp, raw := h.call(key, a.method, a.path(id), a.body, a.hdr...)
		return resp.StatusCode, strings.ReplaceAll(string(raw), id, "<id>")
	}
	vs, vb := send(victim)
	us, ub := send(unknown)
	if vs < 400 {
		h.t.Fatalf("%s on another organization's job: %d %s", a.name, vs, vb)
	}
	if vs != us || vb != ub {
		h.t.Fatalf("%s: the victim's job answers differently from an unknown id:\n victim  %d %s\n unknown %d %s", a.name, vs, vb, us, ub)
	}
	return vs
}

// TestCrossTenantJobs_ClaimPaths: A's sensor is never offered B's jobs on
// any claim path (v2 poll, claim-N, claim by id, the claim repeat), whether
// they are unpinned, pinned to B's sensor, held by it, or queued for the
// shared fleet; and nothing about them changes.
func TestCrossTenantJobs_ClaimPaths(t *testing.T) {
	xtRaiseWriteBurst(t)
	h := newCtlHarness(t)
	tenantA, tenantB := h.tenantID, h.newTenant()
	sa, sb := h.newSensor(tenantA, "xt-a"), h.newSensor(tenantB, "xt-b")

	unpinned := h.newCommand(tenantB, "")
	pinned := h.newCommand(tenantB, sb.id)
	acked := h.newCommand(tenantB, "")
	resp, raw := h.call(sb.key, http.MethodPost, "/api/v2/sensor/commands/"+acked+"/claim", nil)
	h.want(resp, raw, 200, "")
	sharedQueued := h.sharedJob(tenantB, "", 0)
	victims := []string{unpinned, pinned, acked, sharedQueued}
	before := map[string]xtJob{}
	for _, id := range victims {
		before[id] = h.xtState(id)
	}

	for name, hdr := range map[string][]string{"poll": nil, "claim-N": capacityHeader} {
		resp, raw := h.call(sa.key, http.MethodGet, "/api/v2/sensor/commands?limit=100", nil, hdr...)
		h.want(resp, raw, 200, "")
		for _, c := range decodeAs[protov2.CommandList](t, raw).Commands {
			for _, id := range victims {
				if strings.EqualFold(c.ID, id) {
					t.Fatalf("%s handed A's sensor B's job %s", name, id)
				}
			}
		}
	}
	claim := xtCommandAttempts()[0]
	for _, id := range victims {
		if st := h.xtSame(sa.key, claim, id); st != http.StatusNotFound {
			t.Fatalf("claim of B's job %s: %d, want 404", id, st)
		}
	}
	for _, id := range victims {
		if got := h.xtState(id); got != before[id] {
			t.Fatalf("B's job %s changed: %+v -> %+v", id, before[id], got)
		}
	}
}

// TestCrossTenantJobs_CommandRoutes: A's sensor sends every command route
// (start, complete, fail, refusal, release, logs, egress report, bound
// results, commit) at B's running job. Each is refused like an unknown id,
// and B's job, its logs and its reports stay as they were.
func TestCrossTenantJobs_CommandRoutes(t *testing.T) {
	xtRaiseWriteBurst(t)
	h := newCtlHarnessConfig(t, ctlHarnessConfig{egress: true})
	tenantA, tenantB := h.tenantID, h.newTenant()
	sa, sb := h.newSensor(tenantA, "xt-a"), h.newSensor(tenantB, "xt-b")
	victim := h.newCommand(tenantB, sb.id)
	h.xtRunning(victim, sb.id)
	before := h.xtState(victim)

	for _, a := range xtCommandAttempts() {
		t.Run(a.name, func(t *testing.T) {
			st := h.xtSame(sa.key, a, victim)
			if a.name != "commit" && st != http.StatusNotFound {
				t.Fatalf("status %d, want 404", st)
			}
			if got := h.xtState(victim); got != before {
				t.Fatalf("B's job changed: %+v -> %+v", before, got)
			}
		})
	}
	var stored int
	if err := h.db.QueryRowContext(context.Background(),
		`SELECT count(*) FROM ingest_reports WHERE sensor_id = $1`, sa.id).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if stored != 0 {
		t.Fatalf("A's refused bound reports were stored: %d", stored)
	}
}

// TestCrossTenantJobs_TaskSecretsOfAnotherTenant: A's key-bound, trusted
// sensor asks for the task secrets of B's running job (B has a provider
// key): refused exactly like an unknown command, no value in the answer.
func TestCrossTenantJobs_TaskSecretsOfAnotherTenant(t *testing.T) {
	h := newCtlHarnessConfig(t, ctlHarnessConfig{secrets: true})
	tenantA, tenantB := h.tenantID, h.newTenant()
	const valueB = "xt-provider-key-of-b-0123456789"
	h.setProviderKey(tenantB, "shodan", valueB)
	sa, sb := h.newSensor(tenantA, "xt-a"), h.newSensor(tenantB, "xt-b")
	h.trustSensor(sa)
	h.trustSensor(sb)
	keyA := h.keyBind(sa, tenantA)
	jobB := h.runningJob(tenantB, sb.id, "scan", secSubfinderJob, false)

	victim := h.fetchSecrets(keyA, sa.id, jobB, 3, "k1")
	unknown := h.fetchSecrets(keyA, sa.id, shared.NewID().String(), 3, "k1")
	if victim.resp.StatusCode != http.StatusNotFound || unknown.resp.StatusCode != http.StatusNotFound {
		t.Fatalf("secrets: victim %d, unknown %d", victim.resp.StatusCode, unknown.resp.StatusCode)
	}
	if string(victim.raw) != string(unknown.raw) {
		t.Fatalf("victim and unknown answers differ:\n%s\n%s", victim.raw, unknown.raw)
	}
	noValues(t, "the refusal", string(victim.raw), valueB)
}

// TestCrossTenantJobs_SharedSensorOnlyHeldJobs: a shared sensor (no tenant)
// reaches only the shared jobs it holds, under their current epoch. B's
// organization job, B's shared job held by another shared sensor and B's
// queued shared job are all refused like an unknown id on every command
// route, and stay unchanged.
func TestCrossTenantJobs_SharedSensorOnlyHeldJobs(t *testing.T) {
	xtRaiseWriteBurst(t)
	h := newCtlHarnessConfig(t, ctlHarnessConfig{egress: true})
	tenantB := h.newTenant()
	sb := h.newSensor(tenantB, "xt-b")
	attacker, other := h.newSharedSensor("xt-shared-attacker"), h.newSharedSensor("xt-shared-other")

	orgJob := h.newCommand(tenantB, sb.id)
	h.xtRunning(orgJob, sb.id)
	heldByOther := h.sharedJob(tenantB, other.id, 3)
	queued := h.sharedJob(tenantB, "", 0)
	victims := map[string]string{"organization job": orgJob, "shared job of another shared sensor": heldByOther, "queued shared job": queued}

	for what, id := range victims {
		before := h.xtState(id)
		for _, a := range xtCommandAttempts() {
			if a.name == "egress-report" {
				// Shared sensors are refused the egress report outright
				// (scope-denied), whatever the id.
				continue
			}
			t.Run(what+"/"+a.name, func(t *testing.T) {
				h.xtSame(attacker.key, a, id)
			})
		}
		if got := h.xtState(id); got != before {
			t.Fatalf("%s changed: %+v -> %+v", what, before, got)
		}
	}
	// A shared sensor is never shown the queue without claiming it.
	resp, raw := h.call(attacker.key, http.MethodGet, "/api/v2/sensor/commands", nil)
	h.want(resp, raw, http.StatusForbidden, ingestProblem(string(protov2.ProblemScopeDenied)))
}

// TestCrossTenantJobs_ReportIDsArePerSensor: B's sensor sends a report; A's
// sensor reading, abandoning or reusing that report id learns nothing and
// changes nothing of B's report.
func TestCrossTenantJobs_ReportIDsArePerSensor(t *testing.T) {
	h := newCtlHarness(t)
	tenantA, tenantB := h.tenantID, h.newTenant()
	sa, sb := h.newSensor(tenantA, "xt-a"), h.newSensor(tenantB, "xt-b")
	rid := newReportID()
	body := v2Segment("semgrep", "2.0", "xt-push")
	put := func(key string) (*http.Response, []byte) {
		return h.call(key, http.MethodPut, "/api/v2/sensor/results/"+rid, body,
			"Content-Type", protov2.MediaTypeCTIS, protov2.HeaderContentDigest, digestOf(body))
	}
	if resp, raw := put(sb.key); resp.StatusCode >= 300 {
		t.Fatalf("B's report: %d %s", resp.StatusCode, raw)
	}
	tenant, n := h.reportTenant(sb.id, rid)
	if tenant != tenantB || n != 1 {
		t.Fatalf("B's report row: tenant %s, %d rows", tenant, n)
	}
	unknown := newReportID()
	for _, m := range []string{http.MethodGet, http.MethodDelete} {
		vr, vb := h.call(sa.key, m, "/api/v2/sensor/results/"+rid, nil)
		ur, ub := h.call(sa.key, m, "/api/v2/sensor/results/"+unknown, nil)
		mask := func(b []byte, id string) string { return strings.ReplaceAll(string(b), id, "<id>") }
		if vr.StatusCode != http.StatusNotFound || vr.StatusCode != ur.StatusCode || mask(vb, rid) != mask(ub, unknown) {
			t.Fatalf("%s of B's report id: %d %s, unknown %d %s", m, vr.StatusCode, vb, ur.StatusCode, ub)
		}
	}
	// A reusing the id makes A's own report, in A; B's stays B's.
	if resp, raw := put(sa.key); resp.StatusCode >= 300 {
		t.Fatalf("A's report: %d %s", resp.StatusCode, raw)
	}
	if tenant, n := h.reportTenant(sa.id, rid); tenant != tenantA || n != 1 {
		t.Fatalf("A's report row: tenant %s, %d rows", tenant, n)
	}
	if tenant, n := h.reportTenant(sb.id, rid); tenant != tenantB || n != 1 {
		t.Fatalf("B's report row after A's reuse: tenant %s, %d rows", tenant, n)
	}
	var state string
	if err := h.db.QueryRowContext(context.Background(),
		`SELECT state FROM ingest_reports WHERE sensor_id = $1 AND report_id = $2`, sb.id, rid).Scan(&state); err != nil {
		t.Fatal(err)
	}
	if state == "abandoned" {
		t.Fatal("A's DELETE abandoned B's report")
	}
}

// TestCrossTenantJobs_HeartbeatLeaksNothing: B has queued and running work;
// A's heartbeat shows no pending job, and naming B's running job in A's
// running list is answered exactly like naming an unknown id.
func TestCrossTenantJobs_HeartbeatLeaksNothing(t *testing.T) {
	h := newCtlHarness(t)
	tenantA, tenantB := h.tenantID, h.newTenant()
	sa, sb := h.newSensor(tenantA, "xt-a"), h.newSensor(tenantB, "xt-b")
	for range 3 {
		h.newCommand(tenantB, "")
	}
	running := h.newCommand(tenantB, sb.id)
	h.xtRunning(running, sb.id)
	unknown := strings.ToLower(shared.NewID().String())

	beat := func(ids ...string) protov2.HeartbeatResponse {
		resp, raw := h.call(sa.key, http.MethodPost, "/api/v2/sensor/heartbeat",
			map[string]any{"status": "running", "queue": map[string]any{"running": len(ids)}, "running": ids})
		h.want(resp, raw, 200, "")
		return decodeAs[protov2.HeartbeatResponse](t, raw)
	}
	victim, other := beat(running), beat(unknown)
	if victim.PendingJobs != 0 || other.PendingJobs != 0 {
		t.Fatalf("A sees B's pending jobs: %d / %d", victim.PendingJobs, other.PendingJobs)
	}
	in := func(ids []string, id string) bool {
		for _, x := range ids {
			if strings.EqualFold(x, id) {
				return true
			}
		}
		return false
	}
	if in(victim.CancelCommandIDs, running) != in(other.CancelCommandIDs, unknown) {
		t.Fatalf("cancel list tells B's job from an unknown id: %v vs %v", victim.CancelCommandIDs, other.CancelCommandIDs)
	}
	if victim.TenantID != tenantA {
		t.Fatalf("heartbeat names tenant %q", victim.TenantID)
	}
	if got := h.xtState(running); got.status != "running" || got.sensor != sb.id {
		t.Fatalf("B's running job changed: %+v", got)
	}
}

// TestCrossTenantJobs_RelayedRequestMustBeTheRoutesSensor: a request the
// relay connector forwards names the sensor of its route (X-Relay-Sensor).
// A credential of any other sensor, bearer key included, is refused like a
// bad credential; the route's own sensor is served.
func TestCrossTenantJobs_RelayedRequestMustBeTheRoutesSensor(t *testing.T) {
	h := newCtlHarness(t)
	tenantA, tenantB := h.tenantID, h.newTenant()
	sa, sb := h.newSensor(tenantA, "xt-a"), h.newSensor(tenantB, "xt-b")
	beat := map[string]any{"status": "running"}

	resp, raw := h.call(sa.key, http.MethodPost, "/api/v2/sensor/heartbeat", beat, "X-Relay-Sensor", sb.id)
	h.want(resp, raw, http.StatusUnauthorized, ingestProblem(string(protov2.ProblemUnauthenticated)))
	resp, raw = h.call(sa.key, http.MethodPost, "/api/v2/sensor/heartbeat", beat, "X-Relay-Sensor", sa.id)
	h.want(resp, raw, http.StatusOK, "")
}
