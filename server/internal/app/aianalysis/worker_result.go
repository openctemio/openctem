package aianalysis

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"unicode"

	auditapp "github.com/openctemio/openctem/server/internal/app/audit"
	aidom "github.com/openctemio/openctem/server/pkg/domain/aianalysis"
	"github.com/openctemio/openctem/server/pkg/domain/audit"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/domain/tenant"
	"github.com/openctemio/openctem/server/pkg/logger"
	"github.com/openctemio/openctem/server/pkg/sensorproto/analyze"
)

// Applying a worker's result (docs/architecture/ai-analysis.md, "Applying a
// worker's result"). An AI worker completes its analysis job with an
// openctem.analyze.result/v1 document as the job's output. The command
// system has already checked, before the job could complete, that the
// request was signed by the worker's own key, that the worker holds the job
// under the lease epoch it states, and that the job belongs to the worker's
// organization. This step then trusts nothing in the result itself:
//
//   - the run is found from the platform's own job payload (job_id), never
//     from the result; the result must name that same job;
//   - the run must be of the same organization, still waiting for this job,
//     within its deadline and without a result: one result is taken once,
//     by one caller, and a replay or a late result changes nothing;
//   - the AI agent is resolved again and must still be able to act on the
//     finding; the organization's AI settings and use case are read again;
//   - the suggestions go through the same validation, evidence checks,
//     unmasking and governance as the built-in executor's output, against
//     the finding as the run saw it: a change someone made in between
//     turns the AI agent's changes into comments;
//   - everything the worker wrote is untrusted text: bounded, escaped,
//     checked for injection patterns, and never echoed into logs or audit.

// JobRecord is an analysis job as the command system stores it.
type JobRecord struct {
	TenantID shared.ID
	ID       shared.ID
	Type     string
	Status   string
	SensorID *shared.ID
	Payload  json.RawMessage
	Result   json.RawMessage
}

// AnalysisJobReader reads an analysis job of the organization.
type AnalysisJobReader interface {
	AnalysisJob(ctx context.Context, tenantID, commandID shared.ID) (*JobRecord, error)
}

// Job statuses and type the result step reads.
const (
	jobTypeAnalyze   = "analyze"
	jobStatusSuccess = "completed"
)

// maxModelText bounds the provider and model names taken from a result.
const (
	maxProviderRunes = 50
	maxModelRunes    = 128
)

// ApplyResult takes the result of the completed analysis job commandID of
// the organization tenantID for its run. It is called once the job
// completed (by the request that completed it, and by the sweep for a job
// whose request ended first). It returns the run as it ended, or nil when
// there was nothing to take (not an analysis job, the run already took a
// result, ended or is another organization's).
func (w *WorkerExecutor) ApplyResult(ctx context.Context, tenantID, commandID shared.ID) (*RunDetail, error) {
	ctx = context.WithoutCancel(ctx)
	job, err := w.reader.AnalysisJob(ctx, tenantID, commandID)
	if err != nil {
		if errors.Is(err, shared.ErrNotFound) {
			return nil, nil
		}
		return nil, err
	}
	if job.TenantID != tenantID || job.Type != jobTypeAnalyze || job.Status != jobStatusSuccess || job.SensorID == nil {
		return nil, nil
	}
	runID, ok := jobRunID(job.Payload, tenantID)
	if !ok {
		w.logger.Warn("completed analysis job without a readable run id", "command_id", commandID.String())
		return nil, nil
	}
	run, err := w.b.svc.runs.GetRun(ctx, tenantID, runID)
	if err != nil {
		if errors.Is(err, shared.ErrNotFound) {
			return nil, nil
		}
		return nil, err
	}
	if run.CommandID == nil || *run.CommandID != commandID || run.SubjectType != aidom.SubjectFinding ||
		(run.Executor != aidom.ExecutorTenantWorker && run.Executor != aidom.ExecutorPlatformWorker) {
		return nil, nil
	}

	output, outErr := resultOutput(job.Result)
	digest := resultDigest(output)
	claimed, err := w.b.svc.runs.ClaimWorkerResult(ctx, tenantID, run.ID, commandID, *job.SensorID, digest)
	if err != nil {
		return nil, err
	}
	if !claimed {
		// Taken already (a replay, the sweep and the request racing), ended
		// by its deadline, or no longer waiting: nothing applies twice.
		return nil, nil
	}
	now := w.b.now().UTC()
	run.Status, run.SensorID, run.ResultDigest = aidom.RunRunning, job.SensorID, digest
	if run.StartedAt == nil {
		run.StartedAt = &now
	}

	detail, code := w.take(ctx, run, output, outErr)
	if code != "" {
		w.logResult(ctx, run, audit.ActionAIAnalysisResultRefused, code, nil)
		return detail, nil
	}
	w.logResult(ctx, run, audit.ActionAIAnalysisResultApplied, "", detail.Actions)
	return detail, nil
}

// take validates and applies a claimed result. It returns the run as it
// ended and, when nothing was applied, the error code it ended with.
func (w *WorkerExecutor) take(ctx context.Context, run *aidom.Run, output []byte, outErr string) (*RunDetail, string) {
	end := func(status aidom.RunStatus, code string) (*RunDetail, string) {
		run.Status, run.ErrorCode = status, code
		if run.Outcome == "" {
			run.Outcome = aidom.OutcomeAbstained
		}
		w.b.finish(ctx, run, status, nil)
		return &RunDetail{Run: run, Actions: []Action{}}, code
	}
	if outErr != "" {
		return end(aidom.RunFailed, outErr)
	}
	res, err := analyze.ParseResult(output)
	if err != nil {
		return end(aidom.RunFailed, RunErrInvalidOutput)
	}
	if res.JobID != run.ID.String() {
		return end(aidom.RunRefused, aidom.ErrorJobMismatch)
	}
	w.recordUsage(ctx, run, res)

	switch res.Status {
	case "refused":
		return end(aidom.RunRefused, aidom.WorkerErrorCode(res.ErrorCode))
	case "failed":
		return end(aidom.RunFailed, aidom.WorkerErrorCode(res.ErrorCode))
	}

	// The AI agent acts now, so it is resolved now: paused, disabled or
	// deleted since, out of permissions, or the finding out of its scope,
	// and nothing applies.
	if run.AIAgentID == nil {
		return end(aidom.RunRefused, aidom.ErrorAIAgentUnavailable)
	}
	p, err := w.b.svc.Principal(ctx, run.TenantID, *run.AIAgentID)
	if err != nil || p.Require("findings:read") != nil || p.AssertFinding(ctx, run.SubjectID) != nil {
		return end(aidom.RunRefused, aidom.ErrorAIAgentUnavailable)
	}
	settings, err := w.b.settings.Get(ctx, run.TenantID, tenant.AISettings{})
	if err != nil || settings.EffectiveMode() == tenant.AIModeDisabled {
		return end(aidom.RunRefused, RunErrNotConfigured)
	}
	uc, err := w.b.useCase(ctx, run.TenantID, run.UseCase)
	if err != nil {
		return end(aidom.RunFailed, RunErrInternal)
	}
	if uc.Mode == aidom.UseCaseOff {
		return end(aidom.RunRefused, RunErrUseCaseOff)
	}
	kind, ok := analyze.LookupKind(run.Kind)
	if !ok {
		return end(aidom.RunFailed, RunErrInvalidOutput)
	}
	finding, err := w.b.findings.GetByID(ctx, run.TenantID, run.SubjectID)
	if err != nil {
		return end(aidom.RunRefused, aidom.ErrorAIAgentUnavailable)
	}
	doc, err := json.Marshal(analyze.Output{Suggestions: nonNilSuggestions(res.Suggestions)})
	if err != nil {
		return end(aidom.RunFailed, RunErrInternal)
	}
	in := applyInput{content: doc, injection: run.InjectionSuspected, knowledgeRefs: w.knowledgeRefs(ctx, run),
		seenVersion: run.SubjectRowVersion,
		provenance: func(pv aidom.Provenance) aidom.Provenance {
			pv.ModelFamily, pv.SensorID, pv.ResultDigest = run.ModelFamily, run.SensorID, run.ResultDigest
			return pv
		}}
	actions, _, err := w.b.apply(ctx, p, run, finding, kind, in, uc)
	if err != nil {
		var re *runError
		if errors.As(err, &re) {
			return end(re.status, re.code)
		}
		w.logger.Error("AI worker result not applied", "run_id", run.ID.String(), "error", logger.SanitizeError(err))
		return end(aidom.RunFailed, RunErrInternal)
	}
	run.ErrorCode = ""
	if res.Status == "incomplete" {
		// What validated is applied; the run says why it is partial.
		run.ErrorCode = aidom.WorkerErrorCode(res.ErrorCode)
	}
	w.b.finish(ctx, run, aidom.RunCompleted, nil)
	return &RunDetail{Run: run, Actions: actions}, ""
}

// recordUsage puts the worker's account of the run on it (provider, model,
// family, tokens, template, run record) and the tokens on the
// organization's budget. Names are cleaned and bounded; they are shown as
// text only.
func (w *WorkerExecutor) recordUsage(ctx context.Context, run *aidom.Run, res *analyze.Result) {
	run.Provider = cleanName(res.Usage.Provider, maxProviderRunes)
	run.Model = cleanName(res.Usage.Model, maxModelRunes)
	run.ModelFamily = res.Usage.ModelFamily // schema: ^[a-z0-9][a-z0-9._-]{0,63}$
	run.TokensIn, run.TokensOut = res.Usage.TokensIn, res.Usage.TokensOut
	run.Steps, run.ToolCalls = res.Usage.Steps, res.Usage.ToolCalls
	if res.Template.ID != "" {
		run.PromptTemplateID, run.PromptTemplateDigest = cleanName(res.Template.ID, 64), res.Template.Digest
	}
	if total := res.Usage.TokensIn + res.Usage.TokensOut; w.b.budget != nil && total > 0 {
		if err := w.b.budget.Record(ctx, run.TenantID, total); err != nil {
			w.logger.Warn("failed to record AI token usage", "run_id", run.ID.String(), "error", logger.SanitizeError(err))
		}
	}
}

// knowledgeRefs are the knowledge excerpts the run's bundle carried, so a
// worker's citation of one resolves (nil when knowledge is not wired).
func (w *WorkerExecutor) knowledgeRefs(ctx context.Context, run *aidom.Run) []string {
	r, ok := w.b.knowledge.(RunKnowledgeReader)
	if !ok || w.b.knowledge == nil {
		return nil
	}
	ords, err := r.RunExcerptOrdinals(ctx, run.TenantID, run.ID)
	if err != nil {
		w.logger.Warn("AI run knowledge unreadable; its citations do not resolve", "run_id", run.ID.String(), "error", logger.SanitizeError(err))
		return nil
	}
	out := make([]string, 0, len(ords))
	for _, o := range ords {
		out = append(out, fmt.Sprintf("kb:%d", o))
	}
	return out
}

// RunKnowledgeReader lists the excerpt ordinals a run's bundle carried.
type RunKnowledgeReader interface {
	RunExcerptOrdinals(ctx context.Context, tenantID, runID shared.ID) ([]int, error)
}

// logResult audits the result: the run, the job, the worker, the model, the
// result digest, and what each suggestion became. Never model text.
func (w *WorkerExecutor) logResult(ctx context.Context, run *aidom.Run, action audit.Action, code string, actions []Action) {
	if w.audit == nil {
		return
	}
	name := ""
	if run.AIAgentID != nil {
		if a, err := w.b.svc.aiAgents.Get(ctx, run.TenantID, *run.AIAgentID); err == nil {
			name = a.Name
		}
	}
	resource := run.ID.String()
	if run.AIAgentID != nil {
		resource = run.AIAgentID.String()
	}
	msg := fmt.Sprintf("AI agent %q applied an AI worker's analysis result", name)
	if action == audit.ActionAIAnalysisResultRefused {
		msg = fmt.Sprintf("An AI worker's analysis result for AI agent %q was not applied", name)
	}
	ev := auditapp.NewSuccessEvent(action, audit.ResourceTypeAIAnalysis, resource).WithResourceName(name).WithMessage(msg).
		WithMetadata("run_id", run.ID.String()).WithMetadata("finding_id", run.SubjectID.String()).
		WithMetadata("kind", run.Kind).WithMetadata("executor", string(run.Executor)).
		WithMetadata("result_digest", run.ResultDigest).WithMetadata("status", string(run.Status)).
		WithMetadata("outcome", string(run.Outcome)).WithMetadata("injection_suspected", run.InjectionSuspected)
	if run.CommandID != nil {
		ev = ev.WithMetadata("command_id", run.CommandID.String())
	}
	if run.SensorID != nil {
		ev = ev.WithMetadata("sensor_id", run.SensorID.String())
	}
	if run.Provider != "" {
		ev = ev.WithMetadata("provider", run.Provider).WithMetadata("model", run.Model)
	}
	if run.ModelFamily != "" {
		ev = ev.WithMetadata("model_family", run.ModelFamily)
	}
	if code != "" {
		ev = ev.WithMetadata("error_code", code)
	}
	if len(actions) > 0 {
		ev = ev.WithMetadata("actions", actionLog(actions))
	}
	actx := auditapp.AuditContext{TenantID: run.TenantID.String(), ActorEmail: "system:ai-agent"}
	if err := w.audit.LogEvent(ctx, actx, ev); err != nil {
		w.logger.Error("failed to log audit event", "action", string(action), "error", logger.SanitizeError(err))
	}
}

// jobRunID is the run id the platform put in its own job payload (the job's
// job_id); the payload's tenant must be the job's organization.
func jobRunID(payload json.RawMessage, tenantID shared.ID) (shared.ID, bool) {
	var p JobPayload
	if json.Unmarshal(payload, &p) != nil || len(p.Job) == 0 {
		return shared.ID{}, false
	}
	var j struct {
		JobID    string `json:"job_id"`
		TenantID string `json:"tenant_id"`
	}
	if json.Unmarshal(p.Job, &j) != nil || j.TenantID != tenantID.String() {
		return shared.ID{}, false
	}
	id, err := shared.IDFromString(j.JobID)
	if err != nil {
		return shared.ID{}, false
	}
	return id, true
}

// resultOutput is the result document a worker completed its job with: the
// job's typed output ("output"), or "metadata.output" for an older worker.
// It returns the error code when there is none or it is too large.
func resultOutput(raw json.RawMessage) ([]byte, string) {
	var r struct {
		Output   json.RawMessage `json:"output"`
		Metadata struct {
			Output json.RawMessage `json:"output"`
		} `json:"metadata"`
	}
	if len(raw) == 0 || json.Unmarshal(raw, &r) != nil {
		return nil, aidom.ErrorNoResult
	}
	out := r.Output
	if isNull(out) {
		out = r.Metadata.Output
	}
	if isNull(out) {
		return nil, aidom.ErrorNoResult
	}
	var buf bytes.Buffer
	if err := json.Compact(&buf, out); err != nil {
		return nil, aidom.ErrorNoResult
	}
	if buf.Len() > analyze.MaxDocumentBytes {
		return nil, aidom.ErrorResultTooLarge
	}
	return buf.Bytes(), ""
}

func isNull(b json.RawMessage) bool {
	t := bytes.TrimSpace(b)
	return len(t) == 0 || bytes.Equal(t, []byte("null"))
}

// resultDigest is the sha256 of the result document as stored (compact
// JSON); the digest of an empty document when there is none.
func resultDigest(doc []byte) string {
	sum := sha256.Sum256(doc)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// cleanName drops control and format characters and bounds a name.
func cleanName(s string, limit int) string {
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return -1
		}
		return r
	}, strings.TrimSpace(s))
	if r := []rune(s); len(r) > limit {
		s = string(r[:limit])
	}
	return s
}

func nonNilSuggestions(s []analyze.Suggestion) []analyze.Suggestion {
	if s == nil {
		return []analyze.Suggestion{}
	}
	return s
}

// ApplyPendingResults takes the results of completed analysis jobs whose
// runs are still waiting (the request that completed the job ended before
// it applied the result). The sweep calls it before it ends stale runs.
func (w *WorkerExecutor) ApplyPendingResults(ctx context.Context) (int, error) {
	pending, err := w.b.svc.runs.PendingWorkerResults(ctx, pendingBatch)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, p := range pending {
		d, err := w.ApplyResult(ctx, p.TenantID, p.CommandID)
		if err != nil {
			w.logger.Warn("pending AI worker result not applied", "command_id", p.CommandID.String(), "error", logger.SanitizeError(err))
			continue
		}
		if d != nil {
			n++
		}
	}
	return n, nil
}

// pendingBatch bounds one pass over pending results.
const pendingBatch = 50
