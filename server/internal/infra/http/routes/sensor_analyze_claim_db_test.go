package routes

// Analysis jobs reach only AI workers (docs/rfcs/RFC-131-ai-analysis.md §5),
// end to end over the real sensor poll against a migrated database with
// grants enforced: an `analyze` command carries required_capabilities
// ["analyze.<kind>"], so a sensor that does not advertise the kind never
// sees it; the ai-worker grant admits it and no scanning profile does; an AI
// worker is never handed a scan; and no sensor of another organization
// sees it.

import (
	"context"
	"encoding/json"
	"net/http"
	"slices"
	"testing"

	"github.com/openctemio/openctem/server/internal/app/command"
	"github.com/openctemio/openctem/server/internal/infra/postgres"
	protov2 "github.com/openctemio/openctem/server/pkg/sensorproto/v2"
)

const analyzeTriageCap = "analyze.triage.v1"

// aiWorkerGrant puts the sensor on the ai-worker grant profile.
func (h *ctlHarness) aiWorkerGrant(s ctlSensor) {
	h.t.Helper()
	if _, err := h.db.ExecContext(context.Background(), `UPDATE sensor_grants SET profile = 'ai-worker',
	        job_types = ARRAY['analyze'], tools = NULL, capabilities = NULL, zone_ids = NULL, tier_ceiling = 0,
	        target_network = 'none', target_cidrs = NULL, target_domains = NULL, allow_credentials = FALSE,
	        allow_push_ingest = FALSE, version = version + 1 WHERE sensor_id = $1`, s.id); err != nil {
		h.t.Fatalf("ai-worker grant: %v", err)
	}
}

func (h *ctlHarness) analyzeCommand(tenantID string) string {
	h.t.Helper()
	p, err := json.Marshal(map[string]any{
		"contract": "openctem.analyze/v1", "kind": "triage.v1", "use_case": "triage",
		"subject":               map[string]any{"type": "finding", "id": "0193a000-0000-7000-8000-000000000002"},
		"bundle":                map[string]any{"masked": true, "text": "HOST_1 answers on URL_1"},
		"required_capabilities": []string{analyzeTriageCap},
	})
	if err != nil {
		h.t.Fatal(err)
	}
	c, err := h.cmds.Create(context.Background(), command.CreateInput{TenantID: tenantID, Type: "analyze",
		Priority: "normal", Payload: p, ExpiresIn: 3600})
	if err != nil {
		h.t.Fatalf("create analyze command: %v", err)
	}
	return c.ID.String()
}

func TestAnalyzeClaim_OnlyAIWorkerWithTheCapability(t *testing.T) {
	h := newCtlHarness(t, command.WithGrants(postgres.NewSensorGrantRepository(openSharedTestDB(t)), nil))
	const poll = "/api/v2/sensor/commands?limit=10"

	worker := h.newLimitedSensor(h.tenantID, "example-worker", nil, []string{analyzeTriageCap}, 5)
	h.reportCaps(worker, analyzeTriageCap)
	h.aiWorkerGrant(worker)

	noCap := h.newLimitedSensor(h.tenantID, "example-worker-nocap", nil, []string{"analyze.summary.v1"}, 5)
	h.reportCaps(noCap, "analyze.summary.v1")
	h.aiWorkerGrant(noCap)

	// A scanner on the default profile that (wrongly) advertises the kind.
	scanner := h.newVerifiedSensor(h.tenantID, "scanner", []string{"semgrep"}, []string{analyzeTriageCap}, 5)
	h.reportCaps(scanner, analyzeTriageCap)

	other := h.newTenant()
	foreign := h.newLimitedSensor(other, "example-worker-other-org", nil, []string{analyzeTriageCap}, 5)
	h.reportCaps(foreign, analyzeTriageCap)
	h.aiWorkerGrant(foreign)

	job := h.analyzeCommand(h.tenantID)
	scan := h.scanCommand(h.tenantID, "semgrep")

	if got := h.pollIDs(foreign, poll); len(got) != 0 {
		t.Fatalf("a sensor of another organization was handed %v", got)
	}
	if got := h.pollIDs(noCap, poll); len(got) != 0 {
		t.Fatalf("an AI worker without %s (and no scan grant) was handed %v", analyzeTriageCap, got)
	}
	// The AI worker polls before the scanner, so the unpinned scan is
	// still pending: the grant, not the scanner, keeps it from the worker.
	got := h.pollIDs(worker, poll)
	if !slices.Contains(got, job) {
		t.Fatalf("the AI worker was not handed its analysis job: %v", got)
	}
	if slices.Contains(got, scan) {
		t.Fatal("the AI worker was handed a scan")
	}

	// A second job: the scanner advertises the kind but its profile
	// refuses the job type.
	job2 := h.analyzeCommand(h.tenantID)
	if got := h.pollIDs(scanner, poll); slices.Contains(got, job2) {
		t.Fatal("a scanning profile was handed an analysis job")
	}
	if status, _, _ := h.commandState(job2); status != "pending" {
		t.Fatalf("analysis job is %s after the scanner's poll, want pending", status)
	}
}

// legacyBroadGrant puts the sensor on the legacy-broad grant: no job type
// list, every tier, any network (a sensor that predates grants).
func (h *ctlHarness) legacyBroadGrant(s ctlSensor) {
	h.t.Helper()
	if _, err := h.db.ExecContext(context.Background(), `UPDATE sensor_grants SET profile = 'legacy-broad',
	        job_types = NULL, tools = NULL, capabilities = NULL, zone_ids = NULL, tier_ceiling = 2,
	        target_network = 'any', target_cidrs = NULL, target_domains = NULL, allow_credentials = TRUE,
	        allow_push_ingest = TRUE, version = version + 1 WHERE sensor_id = $1`, s.id); err != nil {
		h.t.Fatalf("legacy-broad grant: %v", err)
	}
	if _, err := h.db.ExecContext(context.Background(), `UPDATE sensors SET trust_level = 'trusted' WHERE id = $1`, s.id); err != nil {
		h.t.Fatalf("trust sensor: %v", err)
	}
}

// claimByID asks for one command by id and reports whether the sensor got it.
func (h *ctlHarness) claimByID(s ctlSensor, id string) bool {
	h.t.Helper()
	resp, _ := h.call(s.key, http.MethodPost, "/api/v2/sensor/commands/"+id+"/claim", nil)
	return resp.StatusCode == http.StatusOK
}

// A sensor on the legacy-broad grant that advertises the kind never gets an
// analysis job, by poll or by id; an AI worker of the same organization then
// does.
func TestAnalyzeClaim_LegacyBroadNeverTakesIt(t *testing.T) {
	h := newCtlHarness(t, command.WithGrants(postgres.NewSensorGrantRepository(openSharedTestDB(t)), nil))
	const poll = "/api/v2/sensor/commands?limit=10"

	legacy := h.newLimitedSensor(h.tenantID, "legacy", nil, []string{analyzeTriageCap}, 5)
	h.reportCaps(legacy, analyzeTriageCap)
	h.legacyBroadGrant(legacy)

	job := h.analyzeCommand(h.tenantID)
	if got := h.pollIDs(legacy, poll); slices.Contains(got, job) {
		t.Fatal("a legacy-broad sensor was handed an analysis job")
	}
	if h.claimByID(legacy, job) {
		t.Fatal("a legacy-broad sensor claimed an analysis job by id")
	}
	if status, _, _ := h.commandState(job); status != "pending" {
		t.Fatalf("analysis job is %s after the legacy sensor, want pending", status)
	}

	worker := h.newLimitedSensor(h.tenantID, "example-worker", nil, []string{analyzeTriageCap}, 5)
	h.reportCaps(worker, analyzeTriageCap)
	h.aiWorkerGrant(worker)
	if got := h.pollIDs(worker, poll); !slices.Contains(got, job) {
		t.Fatalf("the AI worker was not handed the analysis job: %v", got)
	}
}

// Where the claim reads no grant (grant enforcement not wired), an
// analysis job is withheld from every sensor (fail closed), while other work
// still flows.
func TestAnalyzeClaim_NoGrantReadWithholdsIt(t *testing.T) {
	h := newCtlHarness(t)
	const poll = "/api/v2/sensor/commands?limit=10"
	worker := h.newLimitedSensor(h.tenantID, "example-worker", []string{"semgrep"}, []string{analyzeTriageCap}, 5)
	h.reportCaps(worker, analyzeTriageCap)
	h.aiWorkerGrant(worker)

	job := h.analyzeCommand(h.tenantID)
	got := h.pollIDs(worker, poll)
	if slices.Contains(got, job) {
		t.Fatal("an analysis job left without a grant read")
	}
	if h.claimByID(worker, job) {
		t.Fatal("an analysis job was claimed by id without a grant read")
	}
	if status, _, _ := h.commandState(job); status != "pending" {
		t.Fatalf("analysis job is %s, want pending", status)
	}
}

// An analysis job ends only by a request its AI worker signed with its own
// key, under the lease epoch it holds the job (its result is what an AI
// agent acts on): a bearer key, an unsigned request without the epoch, a
// superseded epoch and a worker of another organization are all told the job
// does not exist, and the job stays running; the signed request under the
// current epoch completes it.
func TestAnalyzeComplete_SignedUnderItsEpochOnly(t *testing.T) {
	// The secrets wiring carries the signed-request authenticator.
	h := newCtlHarnessConfig(t, ctlHarnessConfig{secrets: true})
	notFound := ingestProblem(string(protov2.ProblemCommandNotFound))
	worker := h.newLimitedSensor(h.tenantID, "example-worker", nil, []string{analyzeTriageCap}, 5)
	h.aiWorkerGrant(worker)
	job := h.analyzeCommand(h.tenantID)
	h.holdCommand(job, worker.id, 3)
	path := "/api/v2/sensor/commands/" + job + "/complete"
	body := map[string]any{"result": map[string]any{"status": "completed", "output": map[string]any{"contract": "openctem.analyze.result/v1"}}}

	// Bearer key, even with the epoch.
	resp, raw := h.call(worker.key, http.MethodPost, path, body, protov2.HeaderLeaseEpoch, "3")
	h.want(resp, raw, http.StatusNotFound, notFound)
	resp, raw = h.call(worker.key, http.MethodPost, "/api/v2/sensor/commands/"+job+"/fail", map[string]any{"error_message": "x"}, protov2.HeaderLeaseEpoch, "3")
	h.want(resp, raw, http.StatusNotFound, notFound)

	key := h.keyBind(worker, h.tenantID)
	raw, _ = json.Marshal(body)
	// Signed, without the epoch.
	resp, out := h.signedDo(key, http.MethodPost, path, raw)
	h.want(resp, out, http.StatusNotFound, notFound)
	// Signed, under a superseded epoch.
	resp, out = h.signedDo(key, http.MethodPost, path, raw, protov2.HeaderLeaseEpoch, "2")
	if resp.StatusCode == http.StatusOK {
		t.Fatalf("a superseded epoch completed the job: %s", out)
	}
	// A key-bound worker of another organization, under the right epoch.
	other := h.newTenant()
	foreign := h.newLimitedSensor(other, "example-worker-other", nil, []string{analyzeTriageCap}, 5)
	h.aiWorkerGrant(foreign)
	fkey := h.keyBind(foreign, other)
	resp, out = h.signedDo(fkey, http.MethodPost, path, raw, protov2.HeaderLeaseEpoch, "3")
	h.want(resp, out, http.StatusNotFound, notFound)
	if status, _, _ := h.commandState(job); status != "running" {
		t.Fatalf("job is %s after refused completions, want running", status)
	}

	// Signed by its worker, under its epoch.
	resp, out = h.signedDo(key, http.MethodPost, path, raw, protov2.HeaderLeaseEpoch, "3")
	h.want(resp, out, http.StatusOK, "")
	if status, _, _ := h.commandState(job); status != "completed" {
		t.Fatalf("job is %s, want completed", status)
	}
}
