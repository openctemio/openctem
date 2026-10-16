package routes

// The shared claim path on the v2 control routes
// (docs/rfcs/RFC-100-shared-sensors.md §8): a shared sensor claims shared
// jobs of every organization, by its own identity only; it starts, ends,
// releases and logs only the shared jobs it holds, in the command's
// organization; its heartbeat renews only those leases. Requires
// DATABASE_URL.

import (
	"context"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/internal/app/command"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	commanddom "github.com/openctemio/openctem/api/pkg/domain/command"
	"github.com/openctemio/openctem/api/pkg/domain/plan"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	protov2 "github.com/openctemio/openctem/api/pkg/sensorproto/v2"
)

// testSharedLimits is the platform_scans_concurrent limit per organization:
// the organizations of the test only (any other organization's shared jobs
// on the shared test database get 0 and are never claimed by this test).
type testSharedLimits map[string]int

func (l testSharedLimits) Limit(_ context.Context, tenantID shared.ID, key plan.Key) (int, error) {
	if key != plan.PlatformScansConcurrent {
		return 0, nil
	}
	if v, ok := l[tenantID.String()]; ok {
		return v, nil
	}
	return 0, nil
}

// isolate makes s a shared sensor that reports the shared isolation profile
// and verified tool (a name only this test uses).
func (h *ctlHarness) isolate(s ctlSensor, tool string) {
	h.t.Helper()
	if _, err := h.db.ExecContext(context.Background(), `
		UPDATE sensors SET reported_tool_names = $2, reported_capabilities = $3, max_concurrent_jobs = 10
		WHERE id = $1`, s.id, pq.Array([]string{tool}), pq.Array([]string{commanddom.CapabilitySharedIsolation})); err != nil {
		h.t.Fatal(err)
	}
}

// pendingSharedJob creates a pending shared job of tenantID for tool.
func (h *ctlHarness) pendingSharedJob(tenantID, tool string) string {
	h.t.Helper()
	id := h.newCommand(tenantID, "")
	if _, err := h.db.ExecContext(context.Background(), `
		UPDATE commands SET is_platform_job = TRUE, payload = jsonb_build_object('scanner', $2::text, 'target', '.'),
		       queued_at = NOW()
		WHERE id = $1`, id, tool); err != nil {
		h.t.Fatal(err)
	}
	return id
}

func (h *ctlHarness) sharedClaim(key string) wireCommandList {
	h.t.Helper()
	resp, raw := h.call(key, http.MethodGet, "/api/v2/sensor/commands?limit=10", nil, capacityHeader...)
	h.want(resp, raw, 200, "")
	return decodeAs[wireCommandList](h.t, raw)
}

func idsOf(l wireCommandList) map[string]wireCommand {
	out := map[string]wireCommand{}
	for _, c := range l.Commands {
		out[c.ID] = c
	}
	return out
}

func TestSharedClaim_V2ClaimsSharedJobsOfEveryOrganization(t *testing.T) {
	limits := testSharedLimits{}
	h := newCtlHarness(t, command.WithSharedLimits(limits))
	tenantX, tenantY := h.tenantID, h.newTenant()
	limits[tenantX], limits[tenantY] = -1, -1
	tool := uniqueTool()
	a := h.newSharedSensor("shared-a")
	h.isolate(a, tool)

	jobX := h.pendingSharedJob(tenantX, tool)
	jobY := h.pendingSharedJob(tenantY, tool)
	tenantJob := h.newCommand(tenantX, "")
	if _, err := h.db.ExecContext(context.Background(),
		`UPDATE commands SET payload = jsonb_build_object('scanner', $2::text) WHERE id = $1`, tenantJob, tool); err != nil {
		t.Fatal(err)
	}

	// Without the capacity feature a shared sensor is refused: it never
	// lists the organizations' queued work without claiming it.
	resp, raw := h.call(a.key, http.MethodGet, "/api/v2/sensor/commands?limit=10", nil)
	h.want(resp, raw, http.StatusForbidden, ingestProblem(string(protov2.ProblemScopeDenied)))

	got := idsOf(h.sharedClaim(a.key))
	if _, ok := got[tenantJob]; ok {
		t.Fatal("a shared sensor claimed an organization's own job")
	}
	for _, id := range []string{jobX, jobY} {
		c, ok := got[id]
		if !ok {
			t.Fatalf("shared job %s of an organization not claimed: %v", id, got)
		}
		if c.Status != "acknowledged" || c.SensorID == nil || *c.SensorID != a.id || c.LeaseEpoch != 1 {
			t.Fatalf("claimed %+v", c)
		}
	}
	status, holder, leased := h.commandState(jobY)
	if status != "acknowledged" || holder == nil || *holder != a.id || !leased {
		t.Fatalf("job of the other organization is %s held by %v leased %v", status, holder, leased)
	}
}

func TestSharedClaim_V2NoIsolationNoJobs(t *testing.T) {
	limits := testSharedLimits{}
	h := newCtlHarness(t, command.WithSharedLimits(limits))
	tenant := h.tenantID
	limits[tenant] = -1
	tool := uniqueTool()
	a := h.newSharedSensor("shared-a")
	h.isolate(a, tool)
	if _, err := h.db.ExecContext(context.Background(),
		`UPDATE sensors SET reported_capabilities = '{}' WHERE id = $1`, a.id); err != nil {
		t.Fatal(err)
	}
	job := h.pendingSharedJob(tenant, tool)
	if got := idsOf(h.sharedClaim(a.key)); len(got) != 0 {
		t.Fatalf("a shared sensor without the isolation profile claimed %v", got)
	}
	if status, holder, _ := h.commandState(job); status != "pending" || holder != nil {
		t.Fatalf("job %s held by %v", status, holder)
	}
}

func TestSharedClaim_V2OrganizationAtItsLimitWaits(t *testing.T) {
	limits := testSharedLimits{}
	h := newCtlHarness(t, command.WithSharedLimits(limits))
	full, open := h.tenantID, h.newTenant()
	limits[full], limits[open] = 0, -1
	tool := uniqueTool()
	a := h.newSharedSensor("shared-a")
	h.isolate(a, tool)
	waits := h.pendingSharedJob(full, tool)
	runs := h.pendingSharedJob(open, tool)

	got := idsOf(h.sharedClaim(a.key))
	if _, ok := got[waits]; ok {
		t.Fatal("an organization at its platform_scans_concurrent limit got a shared job")
	}
	if _, ok := got[runs]; !ok {
		t.Fatalf("the organization under its limit got nothing: %v", got)
	}
}

func TestSharedClaim_V2StepsOnlyForHeldJobsInTheirOrganization(t *testing.T) {
	limits := testSharedLimits{}
	h := newCtlHarness(t, command.WithSharedLimits(limits))
	tenantX, tenantY := h.tenantID, h.newTenant()
	limits[tenantX], limits[tenantY] = -1, -1
	tool := uniqueTool()
	a, b := h.newSharedSensor("shared-a"), h.newSharedSensor("shared-b")
	h.isolate(a, tool)
	h.isolate(b, tool)
	org := h.newSensor(tenantX, "org-x")

	jobX := h.pendingSharedJob(tenantX, tool)
	if got := idsOf(h.sharedClaim(a.key)); got[jobX].ID == "" {
		t.Fatalf("not claimed: %v", got)
	}
	jobY := h.pendingSharedJob(tenantY, tool)
	if got := idsOf(h.sharedClaim(b.key)); got[jobY].ID == "" {
		t.Fatalf("not claimed by b: %v", got)
	}
	epoch := func(n int) []string { return []string{protov2.HeaderLeaseEpoch, strconv.Itoa(n)} }
	notFound := ingestProblem(string(protov2.ProblemCommandNotFound))

	// B cannot touch A's job (another organization's or not); the
	// organization's own sensor cannot either.
	for _, k := range []string{b.key, org.key} {
		resp, raw := h.call(k, http.MethodPost, "/api/v2/sensor/commands/"+jobX+"/start", nil)
		if resp.StatusCode == http.StatusOK {
			t.Fatalf("a non-holder started a shared job: %s", raw)
		}
	}
	resp, raw := h.call(b.key, http.MethodPost, "/api/v2/sensor/commands/"+jobX+"/release", map[string]any{"reason": "x"})
	h.want(resp, raw, http.StatusNotFound, notFound)
	resp, raw = h.call(b.key, http.MethodPost, "/api/v2/sensor/commands/"+jobX+"/logs",
		map[string]any{"seq": 0, "lines": []map[string]any{{"msg": "x"}}}, epoch(1)...)
	h.want(resp, raw, http.StatusNotFound, notFound)

	// A starts, logs and completes its job, under its epoch; ending it
	// without the epoch is refused.
	resp, raw = h.call(a.key, http.MethodPost, "/api/v2/sensor/commands/"+jobX+"/start", nil)
	h.want(resp, raw, 200, "")
	resp, raw = h.call(a.key, http.MethodPost, "/api/v2/sensor/commands/"+jobX+"/logs",
		map[string]any{"seq": 0, "lines": []map[string]any{{"msg": "scanning"}}})
	h.want(resp, raw, http.StatusNotFound, notFound)
	resp, raw = h.call(a.key, http.MethodPost, "/api/v2/sensor/commands/"+jobX+"/logs",
		map[string]any{"seq": 0, "lines": []map[string]any{{"msg": "scanning"}}}, epoch(1)...)
	h.want(resp, raw, 200, "")
	var logTenant string
	if err := h.db.QueryRowContext(context.Background(),
		`SELECT DISTINCT tenant_id::text FROM command_logs WHERE command_id = $1`, jobX).Scan(&logTenant); err != nil || logTenant != tenantX {
		t.Fatalf("logs stored in tenant %q (%v), want the command's %s", logTenant, err, tenantX)
	}
	resp, raw = h.call(a.key, http.MethodPost, "/api/v2/sensor/commands/"+jobX+"/complete", map[string]any{})
	h.want(resp, raw, http.StatusNotFound, notFound)
	resp, raw = h.call(a.key, http.MethodPost, "/api/v2/sensor/commands/"+jobX+"/complete", map[string]any{}, epoch(2)...)
	if resp.StatusCode == http.StatusOK {
		t.Fatalf("completed under an old epoch: %s", raw)
	}
	resp, raw = h.call(a.key, http.MethodPost, "/api/v2/sensor/commands/"+jobX+"/complete", map[string]any{}, epoch(1)...)
	h.want(resp, raw, 200, "")
	if status, _, _ := h.commandState(jobX); status != "completed" {
		t.Fatalf("job is %s", status)
	}
}

func TestSharedClaim_V2HeartbeatRenewsOnlyHeldSharedLeases(t *testing.T) {
	limits := testSharedLimits{}
	h := newCtlHarness(t, command.WithSharedLimits(limits))
	limits[h.tenantID] = -1
	h.sensors.SetLeaseRenewer(postgres.NewCommandRepository(&postgres.DB{DB: h.db}))
	tool := uniqueTool()
	a, b := h.newSharedSensor("shared-a"), h.newSharedSensor("shared-b")
	h.isolate(a, tool)
	h.isolate(b, tool)
	mine := h.pendingSharedJob(h.tenantID, tool)
	if got := idsOf(h.sharedClaim(a.key)); got[mine].ID == "" {
		t.Fatalf("not claimed: %v", got)
	}
	theirs := h.pendingSharedJob(h.tenantID, tool)
	if got := idsOf(h.sharedClaim(b.key)); got[theirs].ID == "" {
		t.Fatalf("not claimed by b: %v", got)
	}
	soon := time.Now().Add(5 * time.Second)
	for _, id := range []string{mine, theirs} {
		if _, err := h.db.ExecContext(context.Background(), `UPDATE commands SET lease_expires_at = $2 WHERE id = $1`, id, soon); err != nil {
			t.Fatal(err)
		}
	}
	unknown := shared.NewID().String()
	resp, raw := h.call(a.key, http.MethodPost, "/api/v2/sensor/heartbeat", map[string]any{
		"status": "running", "running": []string{mine, theirs, unknown}, "queue": map[string]any{"running": 3},
	})
	h.want(resp, raw, 200, "")
	hb := decodeAs[protov2.HeartbeatResponse](t, raw)
	if hb.TenantID != "" {
		t.Fatalf("a shared sensor's heartbeat named a tenant: %q", hb.TenantID)
	}
	cancel := map[string]bool{}
	for _, id := range hb.CancelCommandIDs {
		cancel[id] = true
	}
	if cancel[mine] || !cancel[theirs] || !cancel[unknown] {
		t.Fatalf("cancel %v; want the job it does not hold and the unknown id, never its own", hb.CancelCommandIDs)
	}
	lease := func(id string) time.Time {
		var at time.Time
		if err := h.db.QueryRowContext(context.Background(), `SELECT lease_expires_at FROM commands WHERE id = $1`, id).Scan(&at); err != nil {
			t.Fatal(err)
		}
		return at
	}
	if !lease(mine).After(soon.Add(time.Second)) {
		t.Fatal("the held job's lease was not renewed")
	}
	if lease(theirs).After(soon.Add(time.Second)) {
		t.Fatal("a heartbeat renewed another shared sensor's lease")
	}
}

func TestSharedClaim_V2ClaimsAreSignedForTheCommandsOrganization(t *testing.T) {
	client, pub := realSigner(t)
	limits := testSharedLimits{}
	h := newCtlHarness(t, command.WithJobSigner(client), command.WithSharedLimits(limits))
	tenantX, tenantY := h.tenantID, h.newTenant()
	limits[tenantX], limits[tenantY] = -1, -1
	// verifySignedJob expects the semgrep job of a scope-ledger test; the
	// limits keep this test to its own organizations' jobs.
	tool := "semgrep"
	a := h.newSharedSensor("shared-a")
	h.isolate(a, tool)
	jobs := map[string]string{h.pendingSharedJob(tenantX, tool): tenantX, h.pendingSharedJob(tenantY, tool): tenantY}

	list := h.sharedClaim(a.key)
	if len(list.Commands) != 2 {
		t.Fatalf("claimed %d jobs, want 2", len(list.Commands))
	}
	for _, c := range list.Commands {
		tenant, ok := jobs[c.ID]
		if !ok {
			t.Fatalf("claimed a job of another test: %s", c.ID)
		}
		// Signed for this shared sensor, in the command's organization.
		verifySignedJob(t, c, pub, tenant, a.id)
	}
}

func uniqueTool() string { return "tool-" + shared.NewID().String() }
