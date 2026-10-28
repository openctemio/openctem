package aianalysis

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/openctemio/openctem/api/internal/app/aibundle"
	"github.com/openctemio/openctem/api/internal/app/aipolicy"
	"github.com/openctemio/openctem/api/internal/infra/llm"
	"github.com/openctemio/openctem/api/pkg/aimask"
	aidom "github.com/openctemio/openctem/api/pkg/domain/aianalysis"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/tenant"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/sensorproto/analyze"
)

// The built-in executor runs single-shot kinds (one model call, no tools) in
// the API process, through the same contract as an analyst worker. It acts as
// an AI analyst: the model's output becomes the finding commands a person
// would call (comment, status, severity, false-positive request), with the
// analyst as the actor, after its effective permissions and data scope are
// checked. Multi-step kinds never run here.

// Fixed run error codes (never provider or model text).
const (
	RunErrPolicyRestricted = "policy_restricted"
	RunErrNothingToSend    = "nothing_to_send"
	RunErrNotConfigured    = "not_configured"
	RunErrBudgetExhausted  = "budget_exhausted"
	RunErrProvider         = "provider_error"
	RunErrInvalidOutput    = "invalid_output"
	RunErrInternal         = "internal_error"
)

// Errors of Analyze.
var (
	ErrKindNotBuiltin = fmt.Errorf("%w: this kind does not run on the built-in executor", shared.ErrValidation)
	// ErrRunRefused: the run was recorded as refused or failed; the run id
	// in the returned detail says why (error_code).
	ErrRunRefused = errors.New("ai_run_refused")
)

// ProviderFactory builds the model provider of an organization (*llm.Factory).
type ProviderFactory interface {
	CreateProviderForTenant(tenantID string, aiSettings tenant.AISettings) (llm.Provider, error)
}

// FindingReader reads a finding of the tenant.
type FindingReader interface {
	GetByID(ctx context.Context, tenantID, id shared.ID) (*vulnerability.Finding, error)
}

// FindingCommands are the finding commands an analyst calls, as itself
// (finding.AIAnalystCommands). A change that lowers risk becomes a request.
type FindingCommands interface {
	Comment(ctx context.Context, tenantID, findingID, actorID shared.ID, text string) error
	SetStatus(ctx context.Context, tenantID, findingID, actorID shared.ID, status string) error
	// ChangeSeverity reports whether the change became a request.
	ChangeSeverity(ctx context.Context, tenantID, findingID, actorID shared.ID, severity, reason string) (bool, error)
	RequestFalsePositive(ctx context.Context, tenantID, findingID, actorID shared.ID, justification string) error
}

// BundleInputs assembles a bundle input under the organization's masking
// policy (tenantai.MaskingService).
type BundleInputs interface {
	BundleInput(ctx context.Context, tenantID shared.ID, f *vulnerability.Finding, ceiling aipolicy.Class, runKey []byte) (aibundle.Input, error)
}

// BundleBuilder builds the masked context bundle (aibundle.Builder); it runs
// the organization's AI egress policy first.
type BundleBuilder interface {
	Build(ctx context.Context, in aibundle.Input) (*aibundle.Bundle, error)
}

// MaskMaps keeps a run's placeholder map on the platform (aimaskmap.Store).
type MaskMaps interface {
	Save(ctx context.Context, tenantID, runID shared.ID, runKey []byte, snap aimask.Snapshot) error
	Load(ctx context.Context, tenantID, runID shared.ID) ([]byte, aimask.Snapshot, error)
}

// TokenBudget is the organization's monthly AI token budget.
type TokenBudget interface {
	Check(ctx context.Context, tenantID shared.ID, estimatedTokens int) error
	Record(ctx context.Context, tenantID shared.ID, tokens int) error
}

// ExecutorConfig bounds the model call.
type ExecutorConfig struct {
	MaxTokens   int
	Temperature float64
	Timeout     time.Duration
}

// BuiltinExecutor runs single-shot kinds in the API process.
type BuiltinExecutor struct {
	svc      *Service
	findings FindingReader
	commands FindingCommands
	settings tenant.AISettingsRepository
	llm      ProviderFactory
	inputs   BundleInputs
	bundles  BundleBuilder
	maps     MaskMaps
	budget   TokenBudget
	// ownProviderAllowed is the platform policy on organizations' own
	// providers (nil: allowed).
	ownProviderAllowed func(context.Context) bool
	cfg                ExecutorConfig
	logger             *logger.Logger
	now                func() time.Time
}

// NewBuiltinExecutor builds the executor; SetAnalysts wires the analyst
// service before it runs.
func NewBuiltinExecutor(findings FindingReader, commands FindingCommands, settings tenant.AISettingsRepository, llmFactory ProviderFactory,
	inputs BundleInputs, bundles BundleBuilder, maps MaskMaps, cfg ExecutorConfig, log *logger.Logger) *BuiltinExecutor {
	if cfg.MaxTokens <= 0 {
		cfg.MaxTokens = 2000
	}
	if cfg.Temperature <= 0 {
		cfg.Temperature = 0.1
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 90 * time.Second
	}
	return &BuiltinExecutor{findings: findings, commands: commands, settings: settings, llm: llmFactory, inputs: inputs,
		bundles: bundles, maps: maps, cfg: cfg, logger: log.With("component", "ai_builtin_executor"), now: time.Now}
}

// SetAnalysts wires the analyst service (principals and the run ledger).
func (e *BuiltinExecutor) SetAnalysts(svc *Service) { e.svc = svc }

// SetBudget wires the token budget (nil: no budget check).
func (e *BuiltinExecutor) SetBudget(b TokenBudget) { e.budget = b }

// SetOwnProviderPolicy wires the platform policy on organizations' own providers.
func (e *BuiltinExecutor) SetOwnProviderPolicy(allowed func(context.Context) bool) {
	e.ownProviderAllowed = allowed
}

// AnalyzeRequest asks for one single-shot analysis of a finding by an
// analyst (AnalystID; nil: the first active analyst that may read the
// finding).
type AnalyzeRequest struct {
	TenantID    shared.ID
	FindingID   shared.ID
	Kind        string
	AnalystID   *shared.ID
	TriggeredBy *shared.ID
	Trigger     aidom.Trigger
}

// ActionOutcome is what became of one item of model output.
type ActionOutcome string

const (
	// ActionApplied: the analyst changed the finding through the command.
	ActionApplied ActionOutcome = "applied"
	// ActionRequested: the change became a request a person decides.
	ActionRequested ActionOutcome = "requested"
	// ActionCommented: the analyst wrote a comment (analysis, plan, or a
	// change it may not make itself).
	ActionCommented ActionOutcome = "commented"
	// ActionSkipped: nothing was done.
	ActionSkipped ActionOutcome = "skipped"
)

// Action is one item of model output and what the analyst did with it.
type Action struct {
	Kind    string        `json:"kind"`
	Outcome ActionOutcome `json:"outcome"`
	Reason  string        `json:"reason,omitempty"`
}

// RunDetail is a run and the analyst's actions.
type RunDetail struct {
	Run     *aidom.Run
	Actions []Action
}

// Analyze runs one single-shot kind on a finding as an analyst. The caller
// has checked that the person who triggered it may see the finding.
func (e *BuiltinExecutor) Analyze(ctx context.Context, req AnalyzeRequest) (*RunDetail, error) {
	if e.svc == nil {
		return nil, fmt.Errorf("%w: AI analysts are not available", shared.ErrConflict)
	}
	kind, ok := analyze.LookupKind(req.Kind)
	if !ok || !kind.SingleShot {
		return nil, ErrKindNotBuiltin
	}
	useCase, err := aidom.ParseUseCase(kind.UseCase)
	if err != nil {
		return nil, err
	}
	tpl, err := TemplateFor(kind.Name)
	if err != nil {
		return nil, err
	}
	// The finding is read before a run is recorded: another tenant's id is
	// not found and leaves no trace in this tenant's runs.
	finding, err := e.findings.GetByID(ctx, req.TenantID, req.FindingID)
	if err != nil {
		return nil, err
	}
	var p *Principal
	if req.AnalystID != nil {
		p, err = e.svc.Principal(ctx, req.TenantID, *req.AnalystID)
	} else {
		p, err = e.svc.DefaultAnalyst(ctx, req.TenantID, req.FindingID)
	}
	if err != nil {
		return nil, err
	}
	if p.Analyst.Executor != aidom.ExecutorBuiltin {
		return nil, ErrKindNotBuiltin
	}
	if err := p.Require("findings:read"); err != nil {
		return nil, err
	}
	if err := p.AssertFinding(ctx, req.FindingID); err != nil {
		return nil, err
	}
	if req.Trigger == "" {
		req.Trigger = aidom.TriggerOnDemand
	}
	run, err := e.svc.StartRun(ctx, StartRunInput{
		Principal: p, UseCase: useCase, Kind: kind.Name, SubjectType: aidom.SubjectFinding, SubjectID: req.FindingID,
		Executor: aidom.ExecutorBuiltin, DataClass: p.Analyst.DataClassCeiling, Trigger: req.Trigger, TriggeredBy: req.TriggeredBy,
	})
	if err != nil {
		return nil, err
	}
	run.PromptTemplateID, run.PromptTemplateDigest, run.OutputSchema = tpl.ID, tpl.Digest, kind.OutputSchema
	actions, err := e.execute(ctx, p, run, finding, kind, tpl)
	if err != nil {
		e.finish(ctx, run, aidom.RunFailed, err)
		return &RunDetail{Run: run, Actions: actions}, ErrRunRefused
	}
	return &RunDetail{Run: run, Actions: actions}, nil
}

// runError carries a fixed run error code and the status it ends in.
type runError struct {
	code   string
	status aidom.RunStatus
}

func (e *runError) Error() string { return e.code }

func refused(code string) error { return &runError{code: code, status: aidom.RunRefused} }
func failed(code string) error  { return &runError{code: code, status: aidom.RunFailed} }

func (e *BuiltinExecutor) finish(ctx context.Context, run *aidom.Run, status aidom.RunStatus, err error) {
	var re *runError
	switch {
	case errors.As(err, &re):
		run.Status, run.ErrorCode = re.status, re.code
	case err != nil:
		run.Status, run.ErrorCode = aidom.RunFailed, RunErrInternal
		e.logger.Error("AI run failed", "run_id", run.ID.String(), "error", logger.SanitizeError(err))
	default:
		run.Status = status
	}
	done := e.now()
	run.CompletedAt = &done
	if run.StartedAt != nil {
		d := int(done.Sub(*run.StartedAt).Milliseconds())
		run.DurationMS = &d
	}
	// The run row is the audit trail of the attempt: record the outcome even
	// when the request was canceled.
	if uerr := e.svc.FinishRun(context.WithoutCancel(ctx), run); uerr != nil {
		e.logger.Error("failed to record the AI run outcome", "run_id", run.ID.String(), "error", logger.SanitizeError(uerr))
	}
}

func (e *BuiltinExecutor) execute(ctx context.Context, p *Principal, run *aidom.Run, finding *vulnerability.Finding, kind analyze.Kind, tpl PromptTemplate) ([]Action, error) {
	settings, err := e.settings.Get(ctx, run.TenantID, tenant.AISettings{})
	if err != nil {
		return nil, err
	}
	settings.Mode = settings.EffectiveMode()
	if settings.Mode == tenant.AIModeDisabled {
		return nil, refused(RunErrNotConfigured)
	}
	if settings.Mode == tenant.AIModeBYOK && e.ownProviderAllowed != nil && !e.ownProviderAllowed(ctx) {
		return nil, refused(RunErrNotConfigured)
	}
	ceiling, err := aipolicy.ParseClass(string(p.Analyst.DataClassCeiling))
	if err != nil || ceiling == aipolicy.ClassTenantOnly {
		return nil, refused(RunErrPolicyRestricted)
	}

	// The bundle: fields allowed by the ceiling, masked with a key made for
	// this run; the organization's AI egress policy runs first.
	key := make([]byte, aimask.KeySize)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	in, err := e.inputs.BundleInput(ctx, run.TenantID, finding, ceiling, key)
	if err != nil {
		return nil, err
	}
	bundle, err := e.bundles.Build(ctx, in)
	switch {
	case errors.Is(err, aipolicy.ErrRestricted):
		return nil, refused(RunErrPolicyRestricted)
	case errors.Is(err, aibundle.ErrEmpty):
		return nil, refused(RunErrNothingToSend)
	case err != nil:
		return nil, err
	}
	run.DataClass = aidom.DataClass(bundle.DataClass)
	run.BundleDigest = bundle.Digest
	for _, f := range bundle.FieldsSent {
		run.FieldsSent = append(run.FieldsSent, string(f))
	}
	for _, f := range bundle.FieldsWithheld {
		run.FieldsWithheld = append(run.FieldsWithheld, string(f))
	}
	// The mapping stays on the platform; result handling reads it back
	// through the store, the same path a worker's result takes.
	if err := e.maps.Save(ctx, run.TenantID, run.ID, key, bundle.Masker.Snapshot()); err != nil {
		return nil, err
	}

	if e.budget != nil {
		estimate := (len(tpl.Text)+len(bundle.Text))/4 + e.cfg.MaxTokens
		if err := e.budget.Check(ctx, run.TenantID, estimate); err != nil {
			return nil, refused(RunErrBudgetExhausted)
		}
	}
	provider, err := e.llm.CreateProviderForTenant(run.TenantID.String(), settings)
	if err != nil {
		return nil, refused(RunErrNotConfigured)
	}
	run.Provider, run.Model = provider.Name(), provider.Model()
	callCtx, cancel := context.WithTimeout(ctx, e.cfg.Timeout)
	defer cancel()
	resp, err := provider.Complete(callCtx, llm.CompletionRequest{
		SystemPrompt: tpl.Text, UserPrompt: bundle.Text, MaxTokens: e.cfg.MaxTokens,
		Temperature: e.cfg.Temperature, JSONMode: true,
	})
	if err != nil {
		e.logger.Warn("AI model call failed", "run_id", run.ID.String(), "provider", provider.Name(), "error", logger.SanitizeError(err))
		return nil, failed(RunErrProvider)
	}
	run.TokensIn, run.TokensOut = resp.PromptTokens, resp.CompletionTokens
	if e.budget != nil && resp.TotalTokens > 0 {
		if berr := e.budget.Record(ctx, run.TenantID, resp.TotalTokens); berr != nil {
			e.logger.Warn("failed to record AI token usage", "run_id", run.ID.String(), "error", logger.SanitizeError(berr))
		}
	}

	actions, err := e.act(ctx, p, run, finding, kind, bundle, resp.Content)
	if err != nil {
		return actions, err
	}
	e.finish(ctx, run, aidom.RunCompleted, nil)
	return actions, nil
}

// unmaskPayload puts real values back into every string of a validated
// payload. A placeholder the run did not issue stays as text and is reported:
// the model cannot invent a mapping. Secret placeholders are never resolved.
func unmaskPayload(u *aimask.Unmasker, raw json.RawMessage) (json.RawMessage, bool, error) {
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil, false, err
	}
	unknown := false
	var walk func(any) any
	walk = func(x any) any {
		switch t := x.(type) {
		case string:
			s, un := u.Unmask(t)
			unknown = unknown || len(un) > 0
			return s
		case []any:
			for i := range t {
				t[i] = walk(t[i])
			}
			return t
		case map[string]any:
			for k := range t {
				t[k] = walk(t[k])
			}
			return t
		}
		return x
	}
	v = walk(v)
	b, err := json.Marshal(v)
	return b, unknown, err
}

// act validates the model output against the kind's schema, maps
// placeholders back through the stored mapping, and turns each item into the
// command a person would call, as the analyst:
//
//   - summary, remediation steps, needs-info verdicts and anything the
//     analyst may not do itself become a comment by the analyst;
//   - a true-positive verdict confirms a new finding (findings:status);
//   - a severity proposal goes through the severity command; a downgrade
//     becomes a severity request (the analyst can never approve);
//   - a likely-false-positive verdict becomes a false-positive approval
//     request (findings:write), decided by a person.
//
// Output that cites nothing real, carries a placeholder the run did not
// issue, or comes from a bundle with injection markers is written as a
// comment only. Before each change the finding is read again: if someone
// else changed it since the analyst last saw it, the change is skipped (the
// analyst never overwrites a later decision), and every command carries the
// row version it expects.
func (e *BuiltinExecutor) act(ctx context.Context, p *Principal, run *aidom.Run, finding *vulnerability.Finding,
	kind analyze.Kind, bundle *aibundle.Bundle, content string,
) ([]Action, error) {
	out, err := analyze.ParseOutput(kind.Name, []byte(strings.TrimSpace(content)))
	if err != nil {
		return nil, failed(RunErrInvalidOutput)
	}
	_, snap, err := e.maps.Load(ctx, run.TenantID, run.ID)
	if err != nil {
		return nil, err
	}
	unm := aimask.NewUnmasker(snap)
	known := make(map[string]bool, len(run.FieldsSent))
	for _, f := range run.FieldsSent {
		known["bundle:"+f] = true
	}

	actx := aidom.WithProvenance(ctx, p.Provenance(run))
	ac := &actor{e: e, p: p, run: run, finding: finding.ID(), version: finding.RowVersion(), versioned: finding.HasRowVersion()}
	actions := make([]Action, 0, len(out.Suggestions))
	for _, sg := range out.Suggestions {
		payload, unknown, err := unmaskPayload(unm, sg.Payload)
		if err != nil {
			actions = append(actions, Action{Kind: sg.Kind, Outcome: ActionSkipped, Reason: "invalid_payload"})
			continue
		}
		k, err := aidom.ParseKind(sg.Kind)
		if err != nil {
			actions = append(actions, Action{Kind: sg.Kind, Outcome: ActionSkipped, Reason: "unknown_kind"})
			continue
		}
		norm, err := aidom.NormalizePayload(k, payload)
		if err != nil {
			actions = append(actions, Action{Kind: sg.Kind, Outcome: ActionSkipped, Reason: "invalid_payload"})
			continue
		}
		ev := make([]aidom.Evidence, 0, len(sg.Evidence))
		for _, x := range sg.Evidence {
			q, u := unm.Unmask(x.Quote)
			unknown = unknown || len(u) > 0
			ev = append(ev, aidom.Evidence{Ref: x.Ref, Quote: q})
		}
		_, reasons := aidom.CheckEvidence(ev, known)
		if unknown {
			reasons = append(reasons, aidom.ReviewUnknownPlaceholder)
		}
		if bundle.InjectionSuspected {
			reasons = append(reasons, aidom.ReviewInjectionSuspected)
		}
		actions = append(actions, ac.do(actx, k, norm, sg.Confidence, reasons))
	}
	run.Actions = ac.done
	return actions, nil
}

// minActConfidence is the confidence below which a verdict or severity is
// written as a comment rather than acted on.
const minActConfidence = 0.5

// actor carries one run's state while the analyst acts.
type actor struct {
	e         *BuiltinExecutor
	p         *Principal
	run       *aidom.Run
	finding   shared.ID
	version   int64
	versioned bool
	conflict  bool
	done      int
}

func (a *actor) do(ctx context.Context, k aidom.Kind, payload json.RawMessage, confidence float64, reasons []string) Action {
	// Only a clean, confident item may change the finding.
	mayChange := len(reasons) == 0 && confidence >= minActConfidence && !a.conflict
	switch k {
	case aidom.KindSummary:
		var v aidom.SummaryPayload
		_ = json.Unmarshal(payload, &v)
		return a.comment(ctx, k, "AI analysis: "+v.Text, "")
	case aidom.KindRemediationSteps:
		var v aidom.RemediationPayload
		_ = json.Unmarshal(payload, &v)
		var b strings.Builder
		b.WriteString("AI remediation plan:")
		for i, st := range v.Steps {
			fmt.Fprintf(&b, "\n%d. %s", i+1, st.Description)
		}
		return a.comment(ctx, k, b.String(), "")
	case aidom.KindVerdict:
		var v aidom.VerdictPayload
		_ = json.Unmarshal(payload, &v)
		text := "AI verdict: " + v.Verdict + ". " + v.Reason
		switch {
		case !mayChange:
			return a.comment(ctx, k, text, firstReason(reasons, a.conflict, confidence))
		case v.Verdict == aidom.VerdictLikelyFalsePositive && a.userTriggered():
			// The person who started this run could otherwise approve the
			// request it files as the "second person" (RFC-132 D7).
			return a.comment(ctx, k, text, reasonTriggeredByUser)
		case v.Verdict == aidom.VerdictLikelyFalsePositive && a.p.Can("findings:write"):
			return a.change(ctx, k, text, func() (ActionOutcome, error) {
				err := a.e.commands.RequestFalsePositive(ctx, a.run.TenantID, a.finding, a.p.Analyst.ID, aiJustification(v.Reason))
				return ActionRequested, err
			})
		case v.Verdict == aidom.VerdictTruePositive && a.p.Can("findings:status"):
			f, err := a.e.findings.GetByID(ctx, a.run.TenantID, a.finding)
			if err != nil || f.Status() != vulnerability.FindingStatusNew {
				return a.comment(ctx, k, text, "not_new")
			}
			return a.change(ctx, k, text, func() (ActionOutcome, error) {
				return ActionApplied, a.e.commands.SetStatus(ctx, a.run.TenantID, a.finding, a.p.Analyst.ID,
					string(vulnerability.FindingStatusConfirmed))
			})
		}
		return a.comment(ctx, k, text, "not_permitted")
	case aidom.KindSeverity:
		var v aidom.SeverityPayload
		_ = json.Unmarshal(payload, &v)
		text := "AI severity: " + v.Severity + ". " + v.Reason
		if !mayChange || !a.p.Can("findings:severity") {
			return a.comment(ctx, k, text, firstReason(reasons, a.conflict, confidence))
		}
		if a.userTriggered() {
			// A downgrade becomes a request the triggering person could
			// approve themselves (RFC-132 D7): leave it as a comment. When the
			// finding cannot be read, fail closed the same way.
			f, err := a.e.findings.GetByID(ctx, a.run.TenantID, a.finding)
			to, perr := vulnerability.ParseSeverity(v.Severity)
			if err != nil || perr != nil || vulnerability.IsSeverityDowngrade(f.Severity(), to) {
				return a.comment(ctx, k, text, reasonTriggeredByUser)
			}
		}
		return a.change(ctx, k, text, func() (ActionOutcome, error) {
			requested, err := a.e.commands.ChangeSeverity(ctx, a.run.TenantID, a.finding, a.p.Analyst.ID, v.Severity, aiJustification(v.Reason))
			if requested {
				return ActionRequested, err
			}
			return ActionApplied, err
		})
	}
	return Action{Kind: string(k), Outcome: ActionSkipped, Reason: "unknown_kind"}
}

// reasonTriggeredByUser: a run a person started never files a risk-lowering
// request (false positive, severity downgrade), because that person could
// approve it as the second person. The suggestion is left as a comment.
const reasonTriggeredByUser = "triggered_by_user"

// userTriggered reports whether a person started this run (on demand), as
// opposed to a schedule or an event.
func (a *actor) userTriggered() bool { return a.run.TriggeredBy != nil && !a.run.TriggeredBy.IsZero() }

func firstReason(reasons []string, conflict bool, confidence float64) string {
	switch {
	case len(reasons) > 0:
		return reasons[0]
	case conflict:
		return "finding_changed"
	case confidence < minActConfidence:
		return "low_confidence"
	}
	return "not_permitted"
}

// aiJustification bounds the model's reason as a request justification.
func aiJustification(reason string) string {
	reason = strings.TrimSpace(reason)
	if reason == "" {
		reason = "Proposed by the AI analyst."
	}
	if r := []rune(reason); len(r) > 1900 {
		reason = string(r[:1900])
	}
	return reason
}

// comment writes text as the analyst's comment (when it may comment).
func (a *actor) comment(ctx context.Context, k aidom.Kind, text, reason string) Action {
	if !a.p.Can("findings:comment") {
		return Action{Kind: string(k), Outcome: ActionSkipped, Reason: "not_permitted"}
	}
	if r := []rune(text); len(r) > 9000 {
		text = string(r[:9000])
	}
	// A comment may move the finding's row version; the analyst keeps track
	// of its own writes so they never read as someone else's change.
	unchanged := a.unchangedSinceSeen(ctx)
	if err := a.e.commands.Comment(ctx, a.run.TenantID, a.finding, a.p.Analyst.ID, text); err != nil {
		a.e.logger.Warn("AI analyst comment failed", "run_id", a.run.ID.String(), "error", logger.SanitizeError(err))
		return Action{Kind: string(k), Outcome: ActionSkipped, Reason: "command_refused"}
	}
	a.done++
	if unchanged {
		a.refreshSeen(ctx)
	} else {
		a.conflict = true
	}
	return Action{Kind: string(k), Outcome: ActionCommented, Reason: reason}
}

// change runs one finding change as the analyst after checking nobody changed
// the finding since the analyst last saw it; the command carries that row
// version. A refusal (pending request, lifecycle, conflict) is written as a
// comment instead.
func (a *actor) change(ctx context.Context, k aidom.Kind, text string, cmd func() (ActionOutcome, error)) Action {
	cur, err := a.e.findings.GetByID(ctx, a.run.TenantID, a.finding)
	if err != nil {
		return Action{Kind: string(k), Outcome: ActionSkipped, Reason: "finding_unavailable"}
	}
	if a.versioned && cur.HasRowVersion() && cur.RowVersion() != a.version {
		a.conflict = true
		return a.comment(ctx, k, text, "finding_changed")
	}
	if cur.HasRowVersion() {
		ctx = vulnerability.WithExpectedRowVersion(ctx, a.finding, cur.RowVersion())
	}
	outcome, err := cmd()
	if err != nil {
		var conflict *vulnerability.FindingConflictError
		if errors.As(err, &conflict) {
			a.conflict = true
			return a.comment(ctx, k, text, "finding_changed")
		}
		a.e.logger.Info("AI analyst command refused", "run_id", a.run.ID.String(), "kind", string(k), "error", logger.SanitizeError(err))
		return a.comment(ctx, k, text, "command_refused")
	}
	a.done++
	a.refreshSeen(ctx)
	return Action{Kind: string(k), Outcome: outcome}
}

// unchangedSinceSeen reports whether the finding's row version is still the
// one the analyst last saw.
func (a *actor) unchangedSinceSeen(ctx context.Context) bool {
	if !a.versioned {
		return true
	}
	cur, err := a.e.findings.GetByID(ctx, a.run.TenantID, a.finding)
	if err != nil || !cur.HasRowVersion() {
		return true
	}
	return cur.RowVersion() == a.version
}

// refreshSeen records the row version after the analyst's own write.
func (a *actor) refreshSeen(ctx context.Context) {
	if after, err := a.e.findings.GetByID(ctx, a.run.TenantID, a.finding); err == nil && after.HasRowVersion() {
		a.version, a.versioned = after.RowVersion(), true
	}
}
