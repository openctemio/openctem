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
// the API process, through the same contract, provenance and governance path
// as an analyst worker. Multi-step kinds never run here.

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
	ErrUseCaseOff     = fmt.Errorf("%w: this AI use case is off for the organization", shared.ErrValidation)
	ErrKindNotBuiltin = fmt.Errorf("%w: this kind does not run on the built-in executor", shared.ErrValidation)
	// ErrRunRefused: the run was recorded as refused or failed; the run id
	// in the returned detail says why (error_code).
	ErrRunRefused = errors.New("ai_run_refused")
)

// ProviderFactory builds the model provider of an organization (*llm.Factory).
type ProviderFactory interface {
	CreateProviderForTenant(tenantID string, aiSettings tenant.AISettings) (llm.Provider, error)
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

// NewBuiltinExecutor builds the executor.
func NewBuiltinExecutor(svc *Service, settings tenant.AISettingsRepository, llmFactory ProviderFactory, inputs BundleInputs,
	bundles BundleBuilder, maps MaskMaps, cfg ExecutorConfig, log *logger.Logger) *BuiltinExecutor {
	if cfg.MaxTokens <= 0 {
		cfg.MaxTokens = 2000
	}
	if cfg.Temperature <= 0 {
		cfg.Temperature = 0.1
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 90 * time.Second
	}
	return &BuiltinExecutor{svc: svc, settings: settings, llm: llmFactory, inputs: inputs, bundles: bundles, maps: maps,
		cfg: cfg, logger: log.With("component", "ai_builtin_executor"), now: time.Now}
}

// SetBudget wires the token budget (nil: no budget check).
func (e *BuiltinExecutor) SetBudget(b TokenBudget) { e.budget = b }

// SetOwnProviderPolicy wires the platform policy on organizations' own providers.
func (e *BuiltinExecutor) SetOwnProviderPolicy(allowed func(context.Context) bool) {
	e.ownProviderAllowed = allowed
}

// AnalyzeRequest asks for one single-shot analysis of a finding.
type AnalyzeRequest struct {
	TenantID    shared.ID
	FindingID   shared.ID
	Kind        string
	RequestedBy *shared.ID
	Trigger     aidom.Trigger
}

// Analyze runs one single-shot kind on a finding and records the run and its
// suggestions. The caller has checked the person's access to the finding.
func (e *BuiltinExecutor) Analyze(ctx context.Context, req AnalyzeRequest) (*RunDetail, error) {
	kind, ok := analyze.LookupKind(req.Kind)
	if !ok || !kind.SingleShot {
		return nil, ErrKindNotBuiltin
	}
	useCase, err := aidom.ParseUseCase(kind.UseCase)
	if err != nil {
		return nil, err
	}
	policy, err := e.svc.Policy(ctx, req.TenantID, useCase)
	if err != nil {
		return nil, err
	}
	if policy.EffectiveMode == aidom.ModeOff {
		return nil, ErrUseCaseOff
	}
	if policy.Executor != aidom.ExecutorBuiltin {
		return nil, ErrKindNotBuiltin
	}
	tpl, err := TemplateFor(kind.Name)
	if err != nil {
		return nil, err
	}
	// The finding is read before a run is recorded: another tenant's id is
	// not found and leaves no trace in this tenant's runs.
	finding, err := e.svc.findings.GetByID(ctx, req.TenantID, req.FindingID)
	if err != nil {
		return nil, err
	}
	if req.Trigger == "" {
		req.Trigger = aidom.TriggerOnDemand
	}
	start := e.now()
	run := &aidom.Run{
		TenantID: req.TenantID, UseCase: useCase, Kind: kind.Name, SubjectType: aidom.SubjectFinding, SubjectID: req.FindingID,
		Executor: aidom.ExecutorBuiltin, Status: aidom.RunRunning, DataClass: policy.DataClassCeiling,
		PromptTemplateID: tpl.ID, PromptTemplateDigest: tpl.Digest, OutputSchema: kind.OutputSchema,
		RequestedBy: req.RequestedBy, Trigger: req.Trigger, StartedAt: &start,
	}
	if err := e.svc.repo.CreateRun(ctx, run); err != nil {
		return nil, err
	}
	if err := e.execute(ctx, run, finding, kind, policy, tpl); err != nil {
		e.finish(ctx, run, aidom.RunFailed, err)
		return e.detail(ctx, run, ErrRunRefused)
	}
	return e.detail(ctx, run, nil)
}

// runError carries a fixed run error code and the status it ends in.
type runError struct {
	code   string
	status aidom.RunStatus
}

func (e *runError) Error() string { return e.code }

func refused(code string) error { return &runError{code: code, status: aidom.RunRefused} }
func failed(code string) error  { return &runError{code: code, status: aidom.RunFailed} }

func (e *BuiltinExecutor) detail(ctx context.Context, run *aidom.Run, err error) (*RunDetail, error) {
	items, lerr := e.svc.repo.ListSuggestionsByRun(ctx, run.TenantID, run.ID)
	if lerr != nil {
		return nil, lerr
	}
	return &RunDetail{Run: run, Suggestions: items}, err
}

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
	if uerr := e.svc.repo.UpdateRun(context.WithoutCancel(ctx), run); uerr != nil {
		e.logger.Error("failed to record the AI run outcome", "run_id", run.ID.String(), "error", logger.SanitizeError(uerr))
	}
}

func (e *BuiltinExecutor) execute(ctx context.Context, run *aidom.Run, finding *vulnerability.Finding, kind analyze.Kind, policy PolicyView, tpl PromptTemplate) error {
	settings, err := e.settings.Get(ctx, run.TenantID, tenant.AISettings{})
	if err != nil {
		return err
	}
	settings.Mode = settings.EffectiveMode()
	if settings.Mode == tenant.AIModeDisabled {
		return refused(RunErrNotConfigured)
	}
	if settings.Mode == tenant.AIModeBYOK && e.ownProviderAllowed != nil && !e.ownProviderAllowed(ctx) {
		return refused(RunErrNotConfigured)
	}
	ceiling, err := aipolicy.ParseClass(string(policy.DataClassCeiling))
	if err != nil || ceiling == aipolicy.ClassTenantOnly {
		return refused(RunErrPolicyRestricted)
	}

	// The bundle: fields allowed by the ceiling, masked with a key made for
	// this run; the organization's AI egress policy runs first.
	key := make([]byte, aimask.KeySize)
	if _, err := rand.Read(key); err != nil {
		return err
	}
	in, err := e.inputs.BundleInput(ctx, run.TenantID, finding, ceiling, key)
	if err != nil {
		return err
	}
	bundle, err := e.bundles.Build(ctx, in)
	switch {
	case errors.Is(err, aipolicy.ErrRestricted):
		return refused(RunErrPolicyRestricted)
	case errors.Is(err, aibundle.ErrEmpty):
		return refused(RunErrNothingToSend)
	case err != nil:
		return err
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
		return err
	}

	if e.budget != nil {
		estimate := (len(tpl.Text)+len(bundle.Text))/4 + e.cfg.MaxTokens
		if err := e.budget.Check(ctx, run.TenantID, estimate); err != nil {
			return refused(RunErrBudgetExhausted)
		}
	}
	provider, err := e.llm.CreateProviderForTenant(run.TenantID.String(), settings)
	if err != nil {
		return refused(RunErrNotConfigured)
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
		return failed(RunErrProvider)
	}
	run.TokensIn, run.TokensOut = resp.PromptTokens, resp.CompletionTokens
	if e.budget != nil && resp.TotalTokens > 0 {
		if berr := e.budget.Record(ctx, run.TenantID, resp.TotalTokens); berr != nil {
			e.logger.Warn("failed to record AI token usage", "run_id", run.ID.String(), "error", logger.SanitizeError(berr))
		}
	}

	if err := e.recordOutput(ctx, run, kind, bundle, resp.Content); err != nil {
		return err
	}
	e.finish(ctx, run, aidom.RunCompleted, nil)
	return nil
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

// recordOutput validates the model output against the kind's schema, maps
// placeholders back through the stored mapping and records the suggestions.
func (e *BuiltinExecutor) recordOutput(ctx context.Context, run *aidom.Run, kind analyze.Kind, bundle *aibundle.Bundle, content string) error {
	out, err := analyze.ParseOutput(kind.Name, []byte(strings.TrimSpace(content)))
	if err != nil {
		return failed(RunErrInvalidOutput)
	}
	_, snap, err := e.maps.Load(ctx, run.TenantID, run.ID)
	if err != nil {
		return err
	}
	unm := aimask.NewUnmasker(snap)
	known := make(map[string]bool, len(run.FieldsSent))
	for _, f := range run.FieldsSent {
		known["bundle:"+f] = true
	}
	var runReasons []string
	if bundle.InjectionSuspected {
		runReasons = append(runReasons, aidom.ReviewInjectionSuspected)
	}
	proposals := make([]Proposal, 0, len(out.Suggestions))
	for _, sg := range out.Suggestions {
		payload, unknown, err := unmaskPayload(unm, sg.Payload)
		if err != nil {
			continue
		}
		p := Proposal{Kind: sg.Kind, Payload: payload, Confidence: &sg.Confidence}
		for _, ev := range sg.Evidence {
			q, u := unm.Unmask(ev.Quote)
			unknown = unknown || len(u) > 0
			p.Evidence = append(p.Evidence, aidom.Evidence{Ref: ev.Ref, Quote: q})
		}
		if unknown {
			p.ReviewReasons = append(p.ReviewReasons, aidom.ReviewUnknownPlaceholder)
		}
		proposals = append(proposals, p)
	}
	if _, err := e.svc.Record(ctx, RecordInput{
		Run: run, Proposals: proposals, KnownRefs: known, RunReviewReasons: runReasons, SchemaVersion: kind.OutputSchema,
	}); err != nil {
		return err
	}
	return nil
}
