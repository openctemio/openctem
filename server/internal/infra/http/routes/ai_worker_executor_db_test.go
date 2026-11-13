package routes

// Runs on the organization's AI workers, on a real database
// (docs/architecture/ai-analysis.md, "Runs on an AI worker"): the same checks
// as the built-in executor, then exactly one schema-valid analysis job with
// the masked bundle only, a queued run bound to it, an audit row; nothing
// for another organization's or an out-of-scope finding, nothing when AI is
// off; and a run whose worker never answers ends by its deadline.

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/openctemio/openctem/server/internal/app/aianalysis"
	"github.com/openctemio/openctem/server/internal/app/aibundle"
	"github.com/openctemio/openctem/server/internal/app/aimaskmap"
	"github.com/openctemio/openctem/server/internal/app/aipolicy"
	"github.com/openctemio/openctem/server/internal/app/apikey"
	auditapp "github.com/openctemio/openctem/server/internal/app/audit"
	"github.com/openctemio/openctem/server/internal/app/command"
	"github.com/openctemio/openctem/server/internal/app/datascope"
	"github.com/openctemio/openctem/server/internal/app/finding"
	"github.com/openctemio/openctem/server/internal/app/tenantai"
	"github.com/openctemio/openctem/server/internal/infra/postgres"
	"github.com/openctemio/openctem/server/pkg/crypto"
	aidom "github.com/openctemio/openctem/server/pkg/domain/aianalysis"
	commanddom "github.com/openctemio/openctem/server/pkg/domain/command"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/domain/tenant"
	"github.com/openctemio/openctem/server/pkg/logger"
	"github.com/openctemio/openctem/server/pkg/sensorproto/analyze"
)

// aiSwitchSettings is the organization's AI settings with AI on or off.
type aiSwitchSettings struct {
	tenant.AISettingsRepository
	off *bool
}

func (s aiSwitchSettings) Get(_ context.Context, _ shared.ID, d tenant.AISettings) (tenant.AISettings, error) {
	d.SetOptIn(!*s.off, "admin", time.Now())
	d.Mode = tenant.AIModePlatform
	return d, nil
}

// testJobQueue is the command queue adapter the server wires.
type testJobQueue struct{ cmds *command.Service }

func (q testJobQueue) QueueAnalysisJob(ctx context.Context, j aianalysis.AnalysisJob) error {
	_, err := q.cmds.Create(ctx, command.CreateInput{TenantID: j.TenantID.String(), ID: j.CommandID,
		Type: string(commanddom.CommandTypeAnalyze), Priority: j.Priority, Payload: j.Payload,
		ExpiresIn: int(time.Until(j.ExpiresAt) / time.Second)})
	return err
}

func (q testJobQueue) CancelAnalysisJob(ctx context.Context, tenantID, commandID shared.ID) error {
	_, err := q.cmds.CancelCommand(ctx, tenantID.String(), commandID.String())
	return err
}

type aiWorkerHarness struct {
	*aiExecHarness
	svc   *aianalysis.Service
	wexec *aianalysis.BuiltinExecutor
	aiOff bool
}

func newAIWorkerHarness(t *testing.T) *aiWorkerHarness {
	base := newAIExecHarness(t)
	h := &aiWorkerHarness{aiExecHarness: base}
	db := &postgres.DB{DB: base.db}
	log := logger.NewNop()
	tenants := postgres.NewTenantRepository(db)
	enforcer := datascope.New(postgres.NewDataScopeRepository(db), nil, log)
	enforcer.SetAdminLookup(func(ctx context.Context, tenantID, userID shared.ID) (bool, error) {
		m, err := tenants.GetMembership(ctx, userID, tenantID)
		if err != nil {
			return false, err
		}
		return m.IsOwner() || m.IsAdmin(), nil
	})
	repo := postgres.NewAIAnalysisRepository(db)
	audit := auditapp.NewAuditService(postgres.NewAuditRepository(db), log)
	h.svc = aianalysis.New(repo, repo, apikey.NewHolderPermissions(tenants, aiRolePerms{postgres.NewRoleRepository(db)}),
		enforcer, nil, audit, log)
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	cipher, err := crypto.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	maps := aimaskmap.NewStore(postgres.NewAIMaskMapRepository(db), cipher, time.Hour)
	h.wexec = aianalysis.NewBuiltinExecutor(postgres.NewFindingRepository(db), finding.AIAgentCommands{Findings: base.svc},
		aiSwitchSettings{off: &h.aiOff}, aiScriptedFactory{p: base.model}, aiFixedInputs{host: aiExecHost},
		aibundle.NewBuilder(aipolicy.New(nil, nil)), maps, aianalysis.ExecutorConfig{MaxTokens: 500}, log)
	h.wexec.SetAIAgents(h.svc)
	h.wexec.SetUseCases(tenantai.NewService(base.useCases, nil, nil, nil, nil, nil))
	jobs := testJobQueue{cmds: command.NewService(postgres.NewCommandRepository(db), log)}
	aianalysis.NewWorkerExecutor(h.wexec, jobs, audit, log)
	h.svc.SetJobCanceler(jobs)
	t.Cleanup(func() {
		_, _ = base.db.ExecContext(context.Background(), `DELETE FROM commands WHERE tenant_id = $1`, base.org)
		_, _ = base.db.ExecContext(context.Background(), `DELETE FROM audit_logs WHERE tenant_id = $1`, base.org)
	})
	return h
}

// aiAgentOnWorkers is an AI agent of the organization moved to its AI workers.
func (h *aiWorkerHarness) aiAgentOnWorkers(preset string) *aidom.AIAgent {
	h.t.Helper()
	a := h.aiAgent(preset)
	moved, err := h.svc.ChangeExecutor(context.Background(), a.ID, string(aidom.ExecutorTenantWorker),
		auditapp.AuditContext{TenantID: h.org, ActorID: h.owner.id})
	if err != nil || moved.Executor != aidom.ExecutorTenantWorker {
		h.t.Fatalf("move the AI agent to the AI workers: %v", err)
	}
	return a
}

func (h *aiWorkerHarness) ask(a *aidom.AIAgent, org, findingID string) (*aianalysis.RunDetail, error) {
	tid, _ := shared.IDFromString(org)
	fid, _ := shared.IDFromString(findingID)
	owner, _ := shared.IDFromString(h.owner.id)
	return h.wexec.Analyze(context.Background(), aianalysis.AnalyzeRequest{
		TenantID: tid, FindingID: fid, Kind: "triage.v1", AIAgentID: &a.ID, TriggeredBy: &owner,
	})
}

func (h *aiWorkerHarness) count(q string, args ...any) int {
	h.t.Helper()
	var n int
	if err := h.db.QueryRowContext(context.Background(), q, args...).Scan(&n); err != nil {
		h.t.Fatal(err)
	}
	return n
}

// jobOf reads the analysis job stored for a run.
func (h *aiWorkerHarness) jobOf(commandID string) (aianalysis.JobPayload, string, string, time.Time) {
	h.t.Helper()
	var (
		raw           []byte
		typ, priority string
		expires       time.Time
	)
	if err := h.db.QueryRowContext(context.Background(), `SELECT payload, type, priority, expires_at FROM commands WHERE tenant_id = $1 AND id = $2`,
		h.org, commandID).Scan(&raw, &typ, &priority, &expires); err != nil {
		h.t.Fatalf("read the analysis job: %v", err)
	}
	var p aianalysis.JobPayload
	if err := json.Unmarshal(raw, &p); err != nil {
		h.t.Fatalf("decode the job payload: %v", err)
	}
	return p, typ, priority, expires
}

const aiWorkerSecret = "Sup3rSecret!"

func TestAIWorker_DispatchQueuesOneMaskedSchemaValidJob_DB(t *testing.T) {
	h := newAIWorkerHarness(t)
	a := h.aiAgentOnWorkers("triage")
	f := h.findingFor(a, "high")
	h.exec(`UPDATE findings SET description = $2 WHERE id = $1`, f,
		"GET https://"+aiExecHost+"/admin returned password="+aiWorkerSecret+" from 10.20.30.40.")

	d, err := h.ask(a, h.org, f)
	if err != nil {
		t.Fatal(err)
	}
	run := d.Run
	if run.Status != aidom.RunQueued || run.Executor != aidom.ExecutorTenantWorker || run.CommandID == nil || run.SensorID != nil {
		t.Fatalf("run status=%s executor=%s command=%v sensor=%v", run.Status, run.Executor, run.CommandID, run.SensorID)
	}
	if h.model.prompt != "" {
		t.Fatal("the platform called a model for a run on an AI worker")
	}
	if n := h.count(`SELECT count(*) FROM commands WHERE tenant_id = $1 AND type = 'analyze'`, h.org); n != 1 {
		t.Fatalf("%d analysis jobs, want exactly one", n)
	}
	p, typ, priority, expires := h.jobOf(run.CommandID.String())
	if typ != "analyze" || priority != "high" {
		t.Fatalf("job type=%s priority=%s, want analyze/high (asked for by a person)", typ, priority)
	}
	if d := time.Until(expires); d < 13*time.Minute || d > 16*time.Minute {
		t.Fatalf("job expires in %s, want the job deadline (15 minutes)", d)
	}
	if len(p.RequiredCapabilities) != 1 || p.RequiredCapabilities[0] != "analyze.triage.v1" {
		t.Fatalf("required capabilities %v", p.RequiredCapabilities)
	}
	if err := analyze.Validate(analyze.SchemaJob, p.Job); err != nil {
		t.Fatalf("the job does not satisfy its schema: %v", err)
	}
	var job analyze.Job
	if err := json.Unmarshal(p.Job, &job); err != nil {
		t.Fatal(err)
	}
	if job.JobID != run.ID.String() || job.TenantID != h.org || job.Subject.ID != f || job.Kind != "triage.v1" {
		t.Fatalf("job names job_id=%s tenant=%s subject=%s kind=%s", job.JobID, job.TenantID, job.Subject.ID, job.Kind)
	}
	if !job.Bundle.Masked || job.Bundle.Text == "" || job.Bundle.Digest != run.BundleDigest {
		t.Fatalf("bundle masked=%v digest=%s (run %s) text=%d bytes", job.Bundle.Masked, job.Bundle.Digest, run.BundleDigest, len(job.Bundle.Text))
	}
	if job.Budgets == nil || job.Budgets.Tokens < 1 || job.Budgets.Seconds != 900 || time.Until(job.Deadline) > 15*time.Minute {
		t.Fatalf("budgets %+v deadline %s", job.Budgets, job.Deadline)
	}
	// Only the masked text leaves: no real value, no secret, no mapping.
	for _, leak := range []string{aiExecHost, aiWorkerSecret, "10.20.30.40"} {
		if strings.Contains(string(p.Job), leak) {
			t.Fatalf("%q reached the analysis job", leak)
		}
	}
	// The run on record: queued, bound to its job, what it sends.
	var status, cmd string
	var sent int
	if err := h.db.QueryRowContext(context.Background(), `SELECT status, command_id::text, cardinality(fields_sent) FROM ai_runs WHERE tenant_id = $1 AND id = $2`,
		h.org, run.ID.String()).Scan(&status, &cmd, &sent); err != nil {
		t.Fatal(err)
	}
	if status != "queued" || cmd != run.CommandID.String() || sent == 0 {
		t.Fatalf("stored run status=%s command=%s fields_sent=%d", status, cmd, sent)
	}
	// Audited, without the bundle.
	var meta string
	if err := h.db.QueryRowContext(context.Background(), `SELECT metadata::text FROM audit_logs WHERE tenant_id = $1 AND action = 'ai_agent.analysis_job_queued'`,
		h.org).Scan(&meta); err != nil {
		t.Fatalf("audit row: %v", err)
	}
	if !strings.Contains(meta, run.ID.String()) || strings.Contains(meta, job.Bundle.Text[:40]) {
		t.Fatalf("audit metadata: %s", meta)
	}
	if n := h.count(`SELECT count(*) FROM audit_logs WHERE tenant_id = $1 AND action = 'ai_agent.executor_changed'
		AND metadata->>'from' = 'builtin' AND metadata->>'to' = 'tenant_worker'`, h.org); n != 1 {
		t.Fatalf("%d executor change audit rows", n)
	}
}

func TestAIWorker_RefusesBeforeAnyJob_DB(t *testing.T) {
	h := newAIWorkerHarness(t)
	a := h.aiAgentOnWorkers("triage")
	jobs := func() int {
		return h.count(`SELECT count(*) FROM commands WHERE type = 'analyze' AND tenant_id = $1`, h.org)
	}
	// Outside the AI agent's scope: not found, no run, no job.
	outside := uuid.NewString()
	h.exec(`INSERT INTO findings (id, tenant_id, source, tool_name, message, severity, fingerprint, status)
		VALUES ($1::uuid, $2, 'sast', 'ai-exec', 'm', 'low', $1::text, 'new')`, outside, h.org)
	if _, err := h.ask(a, h.org, outside); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("finding outside the scope: %v", err)
	}
	// Another organization's finding, asked for in this organization.
	other := h.tenantWithFindings()
	foreign := uuid.NewString()
	h.exec(`INSERT INTO findings (id, tenant_id, source, tool_name, message, severity, fingerprint, status)
		VALUES ($1::uuid, $2, 'sast', 'ai-exec', 'm', 'low', $1::text, 'new')`, foreign, other)
	if _, err := h.ask(a, h.org, foreign); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("another organization's finding: %v", err)
	}
	if n := h.count(`SELECT count(*) FROM ai_runs WHERE tenant_id = $1`, h.org); n != 0 {
		t.Fatalf("%d runs recorded for findings the AI agent may not read", n)
	}
	if n := jobs(); n != 0 {
		t.Fatalf("%d jobs queued for findings the AI agent may not read", n)
	}
	// AI off for the organization: the run is refused before any job.
	h.aiOff = true
	f := h.findingFor(a, "low")
	d, err := h.ask(a, h.org, f)
	if !errors.Is(err, aianalysis.ErrRunRefused) || d == nil || d.Run.Status != aidom.RunRefused || d.Run.ErrorCode != aianalysis.RunErrNotConfigured {
		t.Fatalf("AI off: err=%v run=%+v", err, d)
	}
	if n := jobs(); n != 0 {
		t.Fatalf("%d jobs queued with AI off", n)
	}
	h.aiOff = false
	// The kill switch on the AI agent.
	if _, err := h.svc.Disable(context.Background(), a.ID, auditapp.AuditContext{TenantID: h.org, ActorID: h.owner.id}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.ask(a, h.org, f); err == nil {
		t.Fatal("a disabled AI agent queued a job")
	}
	if n := jobs(); n != 0 {
		t.Fatalf("%d jobs queued by a disabled AI agent", n)
	}
}

// A bundle larger than a job may carry is fitted by its encoded size: the
// job stays within the document limit and says what was shortened.
func TestAIWorker_OversizeBundleIsFittedNotSentOversize_DB(t *testing.T) {
	h := newAIWorkerHarness(t)
	a := h.aiAgentOnWorkers("triage")
	f := h.findingFor(a, "high")
	// Free-text fields are capped at 10 KB in the bundle, but '<' takes six
	// bytes once encoded; with a long priority reason the bundle passes the
	// job's limit.
	h.exec(`UPDATE findings SET description = repeat('<', 10000), snippet = repeat('<', 5000),
		cwe_ids = ARRAY[repeat('<', 10000)], owasp_ids = ARRAY[repeat('<', 10000)],
		compliance_impact = ARRAY[repeat('<', 10000)], priority_class = 'P1',
		priority_class_reason = repeat('reachable from the internet; ', 12000) WHERE id = $1`, f)
	d, err := h.ask(a, h.org, f)
	if err != nil {
		t.Fatal(err)
	}
	p, _, _, _ := h.jobOf(d.Run.CommandID.String())
	if len(p.Job) > analyze.MaxDocumentBytes {
		t.Fatalf("job is %d bytes, over the %d limit", len(p.Job), analyze.MaxDocumentBytes)
	}
	var job analyze.Job
	if err := json.Unmarshal(p.Job, &job); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(job.Bundle.Text, aibundle.ShortenedMark) || !strings.Contains(job.Bundle.Text, "shortened the value of finding.") {
		t.Fatal("the shortened fields are not stated in the job")
	}
	if err := analyze.Validate(analyze.SchemaJob, p.Job); err != nil {
		t.Fatalf("the fitted job does not satisfy its schema: %v", err)
	}
	var meta string
	if err := h.db.QueryRowContext(context.Background(), `SELECT metadata::text FROM audit_logs WHERE tenant_id = $1 AND action = 'ai_agent.analysis_job_queued'`,
		h.org).Scan(&meta); err != nil || !strings.Contains(meta, `"fields_shortened": ["finding.`) {
		t.Fatalf("audit does not record the shortened field: %s (%v)", meta, err)
	}
}

// A run whose worker never answers ends by its deadline (and its open job is
// canceled); a run whose job the command system expired or failed ends too.
// None waits forever, and a new run of the finding can start.
func TestAIWorker_RunsEndWithoutAWorker_DB(t *testing.T) {
	h := newAIWorkerHarness(t)
	ctx := context.Background()
	a := h.aiAgentOnWorkers("triage")
	dispatch := func() *aidom.Run {
		t.Helper()
		d, err := h.ask(a, h.org, h.findingFor(a, "high"))
		if err != nil {
			t.Fatal(err)
		}
		return d.Run
	}
	runState := func(r *aidom.Run) (string, string) {
		t.Helper()
		var st, code string
		if err := h.db.QueryRowContext(context.Background(), `SELECT status, COALESCE(error_code, '') FROM ai_runs WHERE tenant_id = $1 AND id = $2`,
			h.org, r.ID.String()).Scan(&st, &code); err != nil {
			t.Fatal(err)
		}
		return st, code
	}
	cmdState := func(r *aidom.Run) string {
		t.Helper()
		var st string
		if err := h.db.QueryRowContext(context.Background(), `SELECT status FROM commands WHERE tenant_id = $1 AND id = $2`, h.org, r.CommandID.String()).Scan(&st); err != nil {
			t.Fatal(err)
		}
		return st
	}

	overdue := dispatch()
	h.exec(`UPDATE ai_runs SET deadline_at = now() - interval '1 second' WHERE id = $1`, overdue.ID.String())

	// Expired by the command expiry, as the expiration checker does it.
	expired := dispatch()
	cmdRepo := postgres.NewCommandRepository(&postgres.DB{DB: h.db})
	h.exec(`UPDATE commands SET expires_at = now() - interval '1 second' WHERE id = $1`, expired.CommandID.String())
	stale, err := cmdRepo.GetByTenantAndID(ctx, expired.TenantID, *expired.CommandID)
	if err != nil {
		t.Fatal(err)
	}
	if won, err := cmdRepo.ExpireIfUnchanged(ctx, stale, "Command expired without being executed"); err != nil || !won {
		t.Fatalf("expire the job: %v %v", won, err)
	}

	failedJob := dispatch()
	h.exec(`UPDATE commands SET status = 'failed', completed_at = now() WHERE id = $1`, failedJob.CommandID.String())

	waiting := dispatch() // in time, job pending: left alone

	n, err := h.svc.EndStaleWorkerRuns(ctx)
	if err != nil || n < 3 {
		t.Fatalf("settled %d runs: %v", n, err)
	}
	for _, c := range []struct {
		run        *aidom.Run
		status     string
		code       string
		commandNow string
	}{
		{overdue, "failed", aidom.ErrorDeadlineExceeded, "canceled"},
		{expired, "failed", aidom.ErrorDeadlineExceeded, "expired"},
		{failedJob, "failed", aidom.ErrorWorkerError, "failed"},
		{waiting, "queued", "", "pending"},
	} {
		if st, code := runState(c.run); st != c.status || code != c.code {
			t.Errorf("run %s: %s/%s, want %s/%s", c.run.ID, st, code, c.status, c.code)
		}
		if st := cmdState(c.run); st != c.commandNow {
			t.Errorf("job of run %s: %s, want %s", c.run.ID, st, c.commandNow)
		}
	}
	// A second sweep finds nothing more, and the finding can be asked again.
	if n, err := h.svc.EndStaleWorkerRuns(ctx); err != nil || n != 0 {
		t.Fatalf("second sweep settled %d (%v)", n, err)
	}
	if _, err := h.ask(a, h.org, overdue.SubjectID.String()); err != nil {
		t.Fatalf("a new run after the overdue one ended: %v", err)
	}
}

func TestAIWorker_ChangeExecutor_DB(t *testing.T) {
	h := newAIWorkerHarness(t)
	ctx := context.Background()
	a := h.aiAgent("suggest")
	actx := auditapp.AuditContext{TenantID: h.org, ActorID: h.owner.id}
	for _, bad := range []string{"platform_worker", "external", "", "anything"} {
		if _, err := h.svc.ChangeExecutor(ctx, a.ID, bad, actx); !errors.Is(err, shared.ErrValidation) {
			t.Fatalf("executor %q: %v, want a validation error", bad, err)
		}
	}
	// Another organization cannot move this AI agent.
	other := h.tenantWithFindings()
	if _, err := h.svc.ChangeExecutor(ctx, a.ID, "tenant_worker", auditapp.AuditContext{TenantID: other, ActorID: h.owner.id}); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("another organization moved the AI agent: %v", err)
	}
	got, err := h.svc.Get(ctx, shared.MustIDFromString(h.org), a.ID)
	if err != nil || got.Executor != aidom.ExecutorBuiltin {
		t.Fatalf("executor after refused changes: %v %v", got, err)
	}
	// Setting the same executor again is not a change.
	if _, err := h.svc.ChangeExecutor(ctx, a.ID, "builtin", actx); err != nil {
		t.Fatal(err)
	}
	if n := h.count(`SELECT count(*) FROM audit_logs WHERE tenant_id = $1 AND action = 'ai_agent.executor_changed'`, h.org); n != 0 {
		t.Fatalf("%d audit rows for no change", n)
	}
}
