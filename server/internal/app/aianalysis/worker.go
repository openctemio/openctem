package aianalysis

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"
	"unicode/utf8"

	"github.com/openctemio/openctem/server/internal/app/aibundle"
	auditapp "github.com/openctemio/openctem/server/internal/app/audit"
	aidom "github.com/openctemio/openctem/server/pkg/domain/aianalysis"
	"github.com/openctemio/openctem/server/pkg/domain/audit"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/domain/tenant"
	"github.com/openctemio/openctem/server/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/server/pkg/logger"
	"github.com/openctemio/openctem/server/pkg/sensorproto/analyze"
)

// Runs on an AI worker (docs/architecture/ai-analysis.md, "Runs on an AI
// worker"): for an AI agent that runs on the organization's AI workers, the
// platform does everything the built-in executor does before a model is
// called (principal, permissions, data scope, AI settings, use case, data
// class ceiling, masked bundle with the mapping kept on the platform, budget
// pre-check), records the run as queued, and sends an analysis job
// (`analyze` command) to the command queue. Only a sensor of the
// organization on the ai-worker grant profile that advertises the job's kind
// takes it, signed like every command. The worker never receives the
// placeholder mapping or a secret value: the job carries the masked text
// only. The result is applied when the worker completes the job.

// Fixed run error code of a bundle that does not fit an analysis job.
const RunErrBundleTooLarge = "bundle_too_large"

// ErrNoWorkerExecutor: the AI agent runs on AI workers, but this platform
// has no worker executor.
var ErrNoWorkerExecutor = fmt.Errorf("%w: runs on AI workers are not available", shared.ErrConflict)

const (
	// WorkerJobDeadline is how long an AI worker has for an analysis job,
	// from when it is queued: the job's deadline and its command's expiry.
	WorkerJobDeadline = 15 * time.Minute
	// workerRunGrace keeps the run open a little past the job's deadline,
	// so a result sent at the deadline is still received; then the deadline
	// sweep ends the run.
	workerRunGrace = time.Minute
	// workerJobTokens is the token budget of one analysis job (prompt and
	// output), lowered to what is left of the AI agent's monthly tokens.
	workerJobTokens = 40000
	// maxBundleTextChars is the job schema's limit on bundle.text.
	maxBundleTextChars = 196608
	// jobSizeMargin is kept free under the job size limit for the fields
	// lists, which grow when Fit withholds a field.
	jobSizeMargin = 4096
)

// AnalysisJob is one analysis job for the command queue.
type AnalysisJob struct {
	TenantID  shared.ID
	CommandID shared.ID
	// Priority is a command priority: high for a job a person asked for.
	Priority  string
	Payload   json.RawMessage
	ExpiresAt time.Time
}

// AnalysisJobQueue queues analysis jobs as `analyze` commands of the
// organization (the command queue), and cancels them.
type AnalysisJobQueue interface {
	QueueAnalysisJob(ctx context.Context, job AnalysisJob) error
	// CancelAnalysisJob cancels a job that is still open; a job already
	// ended is left as it is.
	CancelAnalysisJob(ctx context.Context, tenantID, commandID shared.ID) error
}

// JobPayload is the command payload of an analysis job: the
// openctem.analyze/v1 job as analyze.MarshalJob validated it, and the platform's
// routing key next to it (the job schema is closed, so routing stays
// outside it). A worker reads the job; the claim reads required_capabilities.
type JobPayload struct {
	Job                  json.RawMessage `json:"job"`
	RequiredCapabilities []string        `json:"required_capabilities"`
}

// JobCapability is the capability a worker advertises to take jobs of kind.
func JobCapability(kind string) string { return "analyze." + kind }

// WorkerExecutor sends single-shot kinds to the organization's AI workers.
type WorkerExecutor struct {
	b      *BuiltinExecutor
	jobs   AnalysisJobQueue
	audit  *auditapp.AuditService
	logger *logger.Logger
}

// NewWorkerExecutor builds the worker executor on the built-in executor's
// checks and bundle steps, and wires it into it: an AI agent whose runs are
// on the organization's AI workers is dispatched here.
func NewWorkerExecutor(b *BuiltinExecutor, jobs AnalysisJobQueue, audit *auditapp.AuditService, log *logger.Logger) *WorkerExecutor {
	w := &WorkerExecutor{b: b, jobs: jobs, audit: audit, logger: log.With("component", "ai_worker_executor")}
	b.worker = w
	return w
}

// dispatch records a queued run and sends its analysis job. The caller has
// resolved the principal and checked findings:read and the data scope.
func (w *WorkerExecutor) dispatch(ctx context.Context, p *Principal, req AnalyzeRequest, finding *vulnerability.Finding,
	kind analyze.Kind, tpl PromptTemplate, useCase aidom.UseCase,
) (*RunDetail, error) {
	run, err := w.b.svc.StartRun(ctx, StartRunInput{
		Principal: p, UseCase: useCase, Kind: kind.Name, SubjectType: aidom.SubjectFinding, SubjectID: req.FindingID,
		Executor: aidom.ExecutorTenantWorker, DataClass: p.AIAgent.DataClassCeiling, Trigger: req.Trigger, TriggeredBy: req.TriggeredBy,
		Deadline: WorkerJobDeadline + workerRunGrace,
	})
	if err != nil {
		return nil, err
	}
	run.PromptTemplateID, run.PromptTemplateDigest, run.OutputSchema = tpl.ID, tpl.Digest, kind.OutputSchema
	deadline := w.b.now().Add(WorkerJobDeadline).UTC().Truncate(time.Second)
	payload, shortened, err := w.build(ctx, p, run, finding, kind, tpl, deadline)
	if err != nil {
		w.b.finish(ctx, run, aidom.RunFailed, err)
		return &RunDetail{Run: run}, ErrRunRefused
	}
	// What the run sends is on the run before the job exists, so the result
	// can be checked against it whenever it comes back.
	if err := w.b.svc.FinishRun(ctx, run); err != nil {
		w.b.finish(ctx, run, aidom.RunFailed, err)
		return &RunDetail{Run: run}, ErrRunRefused
	}
	cmdID := shared.NewID()
	bound, err := w.b.svc.runs.BindRunCommand(ctx, run.TenantID, run.ID, cmdID)
	if err == nil && !bound {
		err = errors.New("the run is no longer queued")
	}
	if err != nil {
		w.b.finish(ctx, run, aidom.RunFailed, err)
		return &RunDetail{Run: run}, ErrRunRefused
	}
	run.CommandID = &cmdID
	priority := "normal"
	if req.Trigger == aidom.TriggerOnDemand {
		priority = "high"
	}
	if err := w.jobs.QueueAnalysisJob(ctx, AnalysisJob{TenantID: run.TenantID, CommandID: cmdID, Priority: priority,
		Payload: payload, ExpiresAt: deadline}); err != nil {
		w.b.finish(ctx, run, aidom.RunFailed, err)
		return &RunDetail{Run: run}, ErrRunRefused
	}
	w.logAudit(ctx, p, run, finding, shortened)
	w.logger.Info("AI analysis job queued", "run_id", run.ID.String(), "command_id", cmdID.String(), "kind", kind.Name)
	return &RunDetail{Run: run, Actions: []Action{}}, nil
}

// build prepares the run as the built-in executor does (with the bundle
// fitted to the job's size limit by its encoded size) and returns the
// command payload: the schema-valid job and its required capability.
func (w *WorkerExecutor) build(ctx context.Context, p *Principal, run *aidom.Run, finding *vulnerability.Finding,
	kind analyze.Kind, tpl PromptTemplate, deadline time.Time,
) (json.RawMessage, []string, error) {
	var shortened []string
	fit := func(bd *aibundle.Bundle) error {
		frame, err := json.Marshal(newJob(run, finding, kind, tpl, bd, "", nil, nil, deadline))
		if err != nil {
			return err
		}
		room := analyze.MaxDocumentBytes - len(frame) - jobSizeMargin
		fields, ok := bd.Fit(func(text string) bool {
			if utf8.RuneCountInString(text) > maxBundleTextChars {
				return false
			}
			enc, err := json.Marshal(text)
			return err == nil && len(enc) <= room
		})
		if !ok {
			return refused(RunErrBundleTooLarge)
		}
		for _, f := range fields {
			shortened = append(shortened, string(f))
		}
		return nil
	}
	prep, err := w.b.prepare(ctx, p, run, finding, tpl, aidom.ExecutorTenantWorker, fit)
	if err != nil {
		return nil, nil, err
	}
	tokens, err := w.b.svc.jobTokens(ctx, p.AIAgent, workerJobTokens)
	if err != nil {
		return nil, nil, err
	}
	if tokens < 1 {
		return nil, nil, refused(RunErrBudgetExhausted)
	}
	budgets := &analyze.Budgets{Tokens: tokens, Seconds: int(WorkerJobDeadline / time.Second)}
	job := newJob(run, finding, kind, tpl, prep.bundle, prep.bundle.Text, modelPolicy(prep.settings), budgets, deadline)
	raw, err := analyze.MarshalJob(job)
	if err != nil {
		// Never an oversize or invalid job: the run fails without one.
		w.logger.Error("analysis job refused by its schema", "run_id", run.ID.String(), "error", logger.SanitizeError(err))
		return nil, nil, failed(RunErrInternal)
	}
	payload, err := json.Marshal(JobPayload{Job: raw, RequiredCapabilities: []string{JobCapability(kind.Name)}})
	if err != nil {
		return nil, nil, err
	}
	return payload, shortened, nil
}

// newJob is the analyze job of run (text may be empty to measure the frame).
func newJob(run *aidom.Run, finding *vulnerability.Finding, kind analyze.Kind, tpl PromptTemplate, bd *aibundle.Bundle,
	text string, policy *analyze.ModelPolicy, budgets *analyze.Budgets, deadline time.Time,
) *analyze.Job {
	subject := analyze.Subject{Type: string(aidom.SubjectFinding), ID: finding.ID().String()}
	if a := finding.AssetID(); !a.IsZero() {
		subject.AssetID = a.String()
	}
	sent := make([]string, 0, len(bd.FieldsSent))
	for _, f := range bd.FieldsSent {
		sent = append(sent, string(f))
	}
	withheld := make([]string, 0, len(bd.FieldsWithheld))
	for _, f := range bd.FieldsWithheld {
		withheld = append(withheld, string(f))
	}
	return &analyze.Job{
		Contract: analyze.ContractJob, JobID: run.ID.String(), TenantID: run.TenantID.String(), Kind: kind.Name,
		UseCase: kind.UseCase, Subject: subject,
		Bundle: analyze.Bundle{Digest: bd.Digest, DataClass: string(bd.DataClass), Fields: sent, FieldsWithheld: withheld,
			Masked: true, Text: text},
		OutputSchema: kind.OutputSchema, PromptTemplate: analyze.PromptTemplate{ID: tpl.ID, Digest: tpl.Digest},
		ModelPolicy: policy, Budgets: budgets, Deadline: deadline,
	}
}

// modelPolicy is the organization's model allowlist for a worker: the
// provider (and model) the organization chose for its own key, nothing
// otherwise. The key itself never leaves the platform.
func modelPolicy(s tenant.AISettings) *analyze.ModelPolicy {
	if s.Mode != tenant.AIModeBYOK || !s.Provider.IsValid() {
		return nil
	}
	p := &analyze.ModelPolicy{Providers: []string{string(s.Provider)}}
	if m := s.ModelOverride; m != "" && utf8.RuneCountInString(m) <= 128 {
		p.Models = []string{m}
	}
	return p
}

// logAudit records the job: who asked, which AI agent, the run and the job,
// what the bundle sent. Never the bundle text.
func (w *WorkerExecutor) logAudit(ctx context.Context, p *Principal, run *aidom.Run, finding *vulnerability.Finding, shortened []string) {
	if w.audit == nil {
		return
	}
	actx := auditapp.AuditContext{TenantID: run.TenantID.String(), ActorEmail: "system:ai-agent"}
	if run.TriggeredBy != nil {
		actx = auditapp.AuditContext{TenantID: run.TenantID.String(), ActorID: run.TriggeredBy.String()}
	}
	ev := auditapp.NewSuccessEvent(audit.ActionAIAnalysisJobQueued, audit.ResourceTypeAIAnalysis, p.AIAgent.ID.String()).
		WithResourceName(p.AIAgent.Name).
		WithMessage(fmt.Sprintf("AI agent %q queued an analysis job for an AI worker", p.AIAgent.Name)).
		WithMetadata("run_id", run.ID.String()).WithMetadata("command_id", run.CommandID.String()).
		WithMetadata("finding_id", finding.ID().String()).WithMetadata("kind", run.Kind).
		WithMetadata("executor", string(run.Executor)).WithMetadata("trigger", string(run.Trigger)).
		WithMetadata("data_class", string(run.DataClass)).WithMetadata("bundle_digest", run.BundleDigest).
		WithMetadata("fields_sent", run.FieldsSent).WithMetadata("fields_withheld", run.FieldsWithheld).
		WithMetadata("fields_shortened", shortened).WithMetadata("injection_suspected", run.InjectionSuspected)
	if err := w.audit.LogEvent(ctx, actx, ev); err != nil {
		w.logger.Error("failed to log audit event", "action", string(audit.ActionAIAnalysisJobQueued), "error", logger.SanitizeError(err))
	}
}
