package handler

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/openctemio/openctem/api/internal/app/aianalysis"
	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
	aidom "github.com/openctemio/openctem/api/pkg/domain/aianalysis"
	"github.com/openctemio/openctem/api/pkg/domain/permission"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// AIAnalysisHandler serves the AI use-case policy and the AI suggestions
// (docs/architecture/ai-analysis.md).
type AIAnalysisHandler struct {
	svc    *aianalysis.Service
	logger *logger.Logger
}

// NewAIAnalysisHandler creates the handler.
func NewAIAnalysisHandler(svc *aianalysis.Service, log *logger.Logger) *AIAnalysisHandler {
	return &AIAnalysisHandler{svc: svc, logger: log.With("handler", "ai-analysis")}
}

const (
	aiErrConsentRequiredCode apierror.Code = "AI_CONSENT_REQUIRED"
	aiErrUndoConflictCode    apierror.Code = "AI_UNDO_CONFLICT"
	aiErrDecidedCode         apierror.Code = "AI_SUGGESTION_DECIDED"
)

// AIUseCaseResponse is one AI use case's policy.
type AIUseCaseResponse struct {
	UseCase          string     `json:"use_case"`
	Mode             string     `json:"mode"`
	EffectiveMode    string     `json:"effective_mode"`
	Consented        bool       `json:"consented"`
	Executor         string     `json:"executor"`
	DataClassCeiling string     `json:"data_class_ceiling"`
	MinConfidence    float64    `json:"min_confidence"`
	Triggers         []string   `json:"triggers"`
	BudgetShare      int        `json:"budget_share"`
	DowngradedAt     *time.Time `json:"downgraded_at,omitempty"`
	DowngradeReason  string     `json:"downgrade_reason,omitempty"`
	UpdatedAt        *time.Time `json:"updated_at,omitempty"`
	UpdatedBy        string     `json:"updated_by,omitempty"`
}

// AIUseCaseListResponse lists the use cases.
type AIUseCaseListResponse struct {
	Data []AIUseCaseResponse `json:"data"`
	// DowngradeThreshold and DowngradeWindow describe the automatic fall
	// back from auto-apply to suggest.
	DowngradeThreshold float64 `json:"downgrade_threshold"`
	DowngradeWindow    int     `json:"downgrade_window"`
}

// UpdateAIUseCaseRequest changes one use case; omitted fields keep their value.
type UpdateAIUseCaseRequest struct {
	Mode             *string  `json:"mode,omitempty"`
	DataClassCeiling *string  `json:"data_class_ceiling,omitempty"`
	MinConfidence    *float64 `json:"min_confidence,omitempty"`
	Triggers         []string `json:"triggers,omitempty"`
	BudgetShare      *int     `json:"budget_share,omitempty"`
}

// AISuggestionResponse is one AI suggestion.
type AISuggestionResponse struct {
	ID            string             `json:"id"`
	RunID         string             `json:"run_id"`
	UseCase       string             `json:"use_case"`
	SubjectType   string             `json:"subject_type"`
	SubjectID     string             `json:"subject_id"`
	Kind          string             `json:"kind"`
	Payload       json.RawMessage    `json:"payload"`
	SchemaVersion string             `json:"schema_version"`
	Direction     string             `json:"direction"`
	Confidence    *float64           `json:"confidence,omitempty"`
	Evidence      []aidom.Evidence   `json:"evidence"`
	State         string             `json:"state"`
	ReviewReasons []string           `json:"review_reasons"`
	ApprovalKind  string             `json:"approval_kind,omitempty"`
	ApprovalID    string             `json:"approval_id,omitempty"`
	AppliedBy     string             `json:"applied_by,omitempty"`
	AppliedAt     *time.Time         `json:"applied_at,omitempty"`
	UndoneBy      string             `json:"undone_by,omitempty"`
	UndoneAt      *time.Time         `json:"undone_at,omitempty"`
	CreatedAt     time.Time          `json:"created_at"`
	Origin        string             `json:"origin"`
	Run           *AIRunSummaryShort `json:"run,omitempty"`
}

// AIRunSummaryShort is the provenance shown on a suggestion card.
type AIRunSummaryShort struct {
	Executor         string `json:"executor"`
	Provider         string `json:"provider,omitempty"`
	Model            string `json:"model,omitempty"`
	PromptTemplateID string `json:"prompt_template_id,omitempty"`
}

// AIRunResponse is a run's full provenance and its suggestions.
type AIRunResponse struct {
	ID                   string                 `json:"id"`
	UseCase              string                 `json:"use_case"`
	Kind                 string                 `json:"kind"`
	SubjectType          string                 `json:"subject_type"`
	SubjectID            string                 `json:"subject_id"`
	Executor             string                 `json:"executor"`
	Status               string                 `json:"status"`
	DataClass            string                 `json:"data_class"`
	FieldsSent           []string               `json:"fields_sent"`
	FieldsWithheld       []string               `json:"fields_withheld"`
	BundleDigest         string                 `json:"bundle_digest,omitempty"`
	PromptTemplateID     string                 `json:"prompt_template_id,omitempty"`
	PromptTemplateDigest string                 `json:"prompt_template_digest,omitempty"`
	OutputSchema         string                 `json:"output_schema,omitempty"`
	Provider             string                 `json:"provider,omitempty"`
	Model                string                 `json:"model,omitempty"`
	TokensIn             int                    `json:"tokens_in"`
	TokensOut            int                    `json:"tokens_out"`
	CostMicroUSD         int64                  `json:"cost_micro_usd"`
	DurationMS           *int                   `json:"duration_ms,omitempty"`
	ErrorCode            string                 `json:"error_code,omitempty"`
	Trigger              string                 `json:"trigger"`
	RequestedBy          string                 `json:"requested_by,omitempty"`
	CreatedAt            time.Time              `json:"created_at"`
	CompletedAt          *time.Time             `json:"completed_at,omitempty"`
	Suggestions          []AISuggestionResponse `json:"suggestions"`
}

// AISuggestionListResponse lists suggestions.
type AISuggestionListResponse struct {
	Data []AISuggestionResponse `json:"data"`
}

// ApplyAISuggestionRequest carries what a person adds when applying.
type ApplyAISuggestionRequest struct {
	// ClosureReason is required for a false-positive verdict.
	ClosureReason string `json:"closure_reason,omitempty"`
}

// AIDecisionResponse is the result of apply, dismiss or undo.
type AIDecisionResponse struct {
	Suggestion      AISuggestionResponse `json:"suggestion"`
	PendingApproval bool                 `json:"pending_approval"`
}

// AIUndoRunResponse reports a bulk undo.
type AIUndoRunResponse struct {
	Undone    int `json:"undone"`
	Conflicts int `json:"conflicts"`
	Pending   int `json:"pending"`
}

func idStr(id *shared.ID) string {
	if id == nil {
		return ""
	}
	return id.String()
}

func toAIUseCase(p aianalysis.PolicyView) AIUseCaseResponse {
	out := AIUseCaseResponse{
		UseCase: string(p.UseCase), Mode: string(p.Mode), EffectiveMode: string(p.EffectiveMode), Consented: p.Consented,
		Executor: string(p.Executor), DataClassCeiling: string(p.DataClassCeiling), MinConfidence: p.MinConfidence,
		BudgetShare: p.BudgetShare, DowngradedAt: p.DowngradedAt, DowngradeReason: p.DowngradeReason,
		UpdatedBy: idStr(p.UpdatedBy), Triggers: make([]string, 0, len(p.Triggers)),
	}
	for _, t := range p.Triggers {
		out.Triggers = append(out.Triggers, string(t))
	}
	if p.Stored {
		at := p.UpdatedAt
		out.UpdatedAt = &at
	}
	return out
}

func toAISuggestion(s *aidom.Suggestion, run *aidom.Run) AISuggestionResponse {
	out := AISuggestionResponse{
		ID: s.ID.String(), RunID: s.RunID.String(), UseCase: string(s.UseCase), SubjectType: string(s.SubjectType),
		SubjectID: s.SubjectID.String(), Kind: string(s.Kind), Payload: s.Payload, SchemaVersion: s.SchemaVersion,
		Direction: string(s.Direction), Confidence: s.Confidence, Evidence: s.Evidence, State: string(s.State),
		ReviewReasons: s.ReviewReasons, ApprovalKind: string(s.ApprovalKind), ApprovalID: idStr(s.ApprovalID),
		AppliedBy: idStr(s.AppliedBy), AppliedAt: s.AppliedAt, UndoneBy: idStr(s.UndoneBy), UndoneAt: s.UndoneAt,
		CreatedAt: s.CreatedAt, Origin: "ai",
	}
	if out.Evidence == nil {
		out.Evidence = []aidom.Evidence{}
	}
	if out.ReviewReasons == nil {
		out.ReviewReasons = []string{}
	}
	if run != nil {
		out.Run = &AIRunSummaryShort{Executor: string(run.Executor), Provider: run.Provider, Model: run.Model, PromptTemplateID: run.PromptTemplateID}
	}
	return out
}

func (h *AIAnalysisHandler) actx(r *http.Request) auditapp.AuditContext {
	ctx := r.Context()
	actx := auditapp.AuditContext{
		TenantID: middleware.GetTenantID(ctx), ActorID: middleware.GetUserID(ctx), ActorIP: getClientIP(r),
		UserAgent: r.UserAgent(), RequestID: middleware.GetRequestID(ctx),
	}
	if lu := middleware.GetLocalUser(ctx); lu != nil {
		actx.ActorID, actx.ActorEmail = lu.ID().String(), lu.Email()
	}
	return actx
}

func (h *AIAnalysisHandler) fail(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, aianalysis.ErrConsentRequired):
		apierror.New(http.StatusBadRequest, aiErrConsentRequiredCode, "Turn AI on for the organization first.").WriteJSON(w)
	case errors.Is(err, aidom.ErrUndoConflict):
		apierror.New(http.StatusConflict, aiErrUndoConflictCode,
			"The field changed after the AI suggestion was applied; edit it by hand.").WriteJSON(w)
	case errors.Is(err, aidom.ErrStateChanged):
		apierror.New(http.StatusConflict, aiErrDecidedCode, "The AI suggestion was already decided.").WriteJSON(w)
	case errors.Is(err, shared.ErrNotFound):
		apierror.NotFound("AI suggestion").WriteJSON(w)
	case errors.Is(err, shared.ErrForbidden):
		apierror.Forbidden("You do not have the permission this change needs.").WriteJSON(w)
	case errors.Is(err, shared.ErrConflict):
		apierror.Conflict("The finding changed; reload and try again.").WriteJSON(w)
	case errors.Is(err, shared.ErrValidation):
		apierror.BadRequest(easmValidationMessage(err)).WriteJSON(w)
	default:
		h.logger.Error("ai analysis failed", "error", logger.SanitizeError(err))
		apierror.InternalServerError("failed to process the AI request").WriteJSON(w)
	}
}

func writeAIJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func aiPathID(w http.ResponseWriter, r *http.Request, name string) (shared.ID, bool) {
	id, err := shared.IDFromString(r.PathValue(name))
	if err != nil {
		apierror.BadRequest("Invalid id").WriteJSON(w)
		return shared.ID{}, false
	}
	return id, true
}

func aiTenantOf(w http.ResponseWriter, r *http.Request) (shared.ID, bool) {
	id, err := shared.IDFromString(middleware.MustGetTenantID(r.Context()))
	if err != nil {
		apierror.Unauthorized("Invalid tenant").WriteJSON(w)
		return shared.ID{}, false
	}
	return id, true
}

// ListUseCases handles GET /api/v1/organization/settings/ai/use-cases.
//
// @Summary      List the organization's AI use cases
// @Description  Per use case (triage, remediation, summary): mode (off, suggest, auto_apply), the mode in force (off until the organization consents to AI), executor, data class ceiling, minimum confidence for auto-apply, triggers, budget share, and an automatic downgrade to suggest when people overrode too many suggestions. Owners and administrators.
// @Tags         Tenants
// @Produce      json
// @Security     BearerAuth
// @Success      200  {object}  AIUseCaseListResponse
// @Router       /organization/settings/ai/use-cases [get]
func (h *AIAnalysisHandler) ListUseCases(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := aiTenantOf(w, r)
	if !ok {
		return
	}
	views, err := h.svc.ListPolicies(r.Context(), tenantID)
	if err != nil {
		h.fail(w, err)
		return
	}
	out := AIUseCaseListResponse{Data: make([]AIUseCaseResponse, 0, len(views)),
		DowngradeThreshold: aidom.DowngradeThreshold, DowngradeWindow: aidom.DowngradeWindow}
	for _, v := range views {
		out.Data = append(out.Data, toAIUseCase(v))
	}
	writeAIJSON(w, http.StatusOK, out)
}

// UpdateUseCase handles PUT /api/v1/organization/settings/ai/use-cases/{use_case}.
//
// @Summary      Change an AI use case
// @Description  A partial change of one use case. auto_apply applies additive suggestions on its own (undo available); risk-lowering suggestions always become approval requests and severity or priority changes always wait for a person, whatever the mode. Turning auto-apply on or raising the data class above internal needs a recent sign-in. Re-enabling auto-apply clears an automatic downgrade. Owners and administrators; audited as critical.
// @Tags         Tenants
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        use_case path string true "Use case"
// @Param        body body UpdateAIUseCaseRequest true "Changes"
// @Success      200  {object}  AIUseCaseResponse
// @Failure      400  {object}  apierror.Error
// @Router       /organization/settings/ai/use-cases/{use_case} [put]
func (h *AIAnalysisHandler) UpdateUseCase(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := aiTenantOf(w, r)
	if !ok {
		return
	}
	actor, err := shared.IDFromString(middleware.GetUserID(r.Context()))
	if err != nil {
		apierror.Unauthorized("A person must make this change").WriteJSON(w)
		return
	}
	var req UpdateAIUseCaseRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10)).Decode(&req); err != nil && !errors.Is(err, io.EOF) {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}
	v, err := h.svc.UpdatePolicy(r.Context(), aianalysis.UpdatePolicyInput{
		TenantID: tenantID, ActorID: actor, UseCase: r.PathValue("use_case"), Mode: req.Mode,
		DataClassCeiling: req.DataClassCeiling, MinConfidence: req.MinConfidence, Triggers: req.Triggers,
		BudgetShare: req.BudgetShare, Audit: h.actx(r),
	})
	if err != nil {
		h.fail(w, err)
		return
	}
	writeAIJSON(w, http.StatusOK, toAIUseCase(v))
}

// ListFindingSuggestions handles GET /api/v1/findings/{id}/ai/suggestions.
//
// @Summary      List a finding's AI suggestions
// @Description  Every AI suggestion about the finding, newest first, with its direction (computed by the platform), state, confidence, evidence references and the run's provenance (executor, provider, model, prompt template). Free text in a payload is model output: display it as plain text. Applies the caller's data scope.
// @Tags         Findings
// @Produce      json
// @Security     BearerAuth
// @Param        id path string true "Finding ID"
// @Success      200  {object}  AISuggestionListResponse
// @Router       /findings/{id}/ai/suggestions [get]
func (h *AIAnalysisHandler) ListFindingSuggestions(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := aiTenantOf(w, r)
	if !ok {
		return
	}
	findingID, ok := aiPathID(w, r, "id")
	if !ok {
		return
	}
	items, runs, err := h.svc.ListForFinding(r.Context(), tenantID, findingID)
	if err != nil {
		h.fail(w, err)
		return
	}
	out := AISuggestionListResponse{Data: make([]AISuggestionResponse, 0, len(items))}
	for _, s := range items {
		out.Data = append(out.Data, toAISuggestion(s, runs[s.RunID]))
	}
	writeAIJSON(w, http.StatusOK, out)
}

// GetRun handles GET /api/v1/ai/runs/{id}.
//
// @Summary      Read an AI run
// @Description  The "why" of AI suggestions: executor, model, prompt template id and digest, output schema, bundle digest, the fields sent and withheld, usage and cost, and the run's suggestions. Applies the caller's data scope to the run's subject (out of scope answers 404).
// @Tags         Findings
// @Produce      json
// @Security     BearerAuth
// @Param        id path string true "Run ID"
// @Success      200  {object}  AIRunResponse
// @Router       /ai/runs/{id} [get]
func (h *AIAnalysisHandler) GetRun(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := aiTenantOf(w, r)
	if !ok {
		return
	}
	runID, ok := aiPathID(w, r, "id")
	if !ok {
		return
	}
	d, err := h.svc.GetRun(r.Context(), tenantID, runID)
	if err != nil {
		h.fail(w, err)
		return
	}
	run := d.Run
	out := AIRunResponse{
		ID: run.ID.String(), UseCase: string(run.UseCase), Kind: run.Kind, SubjectType: string(run.SubjectType),
		SubjectID: run.SubjectID.String(), Executor: string(run.Executor), Status: string(run.Status),
		DataClass: string(run.DataClass), FieldsSent: nonNilStrings(run.FieldsSent), FieldsWithheld: nonNilStrings(run.FieldsWithheld),
		BundleDigest: run.BundleDigest, PromptTemplateID: run.PromptTemplateID, PromptTemplateDigest: run.PromptTemplateDigest,
		OutputSchema: run.OutputSchema, Provider: run.Provider, Model: run.Model, TokensIn: run.TokensIn,
		TokensOut: run.TokensOut, CostMicroUSD: run.CostMicroUSD, DurationMS: run.DurationMS, ErrorCode: run.ErrorCode,
		Trigger: string(run.Trigger), RequestedBy: idStr(run.RequestedBy), CreatedAt: run.CreatedAt,
		CompletedAt: run.CompletedAt, Suggestions: make([]AISuggestionResponse, 0, len(d.Suggestions)),
	}
	for _, s := range d.Suggestions {
		out.Suggestions = append(out.Suggestions, toAISuggestion(s, nil))
	}
	writeAIJSON(w, http.StatusOK, out)
}

func (h *AIAnalysisHandler) decide(w http.ResponseWriter, r *http.Request) (aianalysis.DecideInput, bool) {
	tenantID, ok := aiTenantOf(w, r)
	if !ok {
		return aianalysis.DecideInput{}, false
	}
	id, ok := aiPathID(w, r, "id")
	if !ok {
		return aianalysis.DecideInput{}, false
	}
	actor, err := shared.IDFromString(middleware.GetUserID(r.Context()))
	if err != nil {
		apierror.Unauthorized("A person must make this decision").WriteJSON(w)
		return aianalysis.DecideInput{}, false
	}
	ctx := r.Context()
	return aianalysis.DecideInput{
		TenantID: tenantID, SuggestionID: id, ActorID: actor,
		CanApprove: middleware.HasPermission(ctx, permission.FindingsApprove.String()),
		Can:        func(p string) bool { return middleware.HasPermission(ctx, p) },
		Audit:      h.actx(r),
	}, true
}

// ApplySuggestion handles POST /api/v1/ai/suggestions/{id}/apply.
//
// @Summary      Apply an AI suggestion
// @Description  Makes the change as the caller through the same path as a change made by hand: a severity uses the severity rules (a downgrade may become a request), a false-positive verdict opens a status request with the caller as requester (closure_reason required), a plan or summary becomes part of the finding's record. Needs the permission of the change (findings:severity for a severity, findings:write otherwise).
// @Tags         Findings
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        id path string true "Suggestion ID"
// @Param        body body ApplyAISuggestionRequest false "Apply options"
// @Success      200  {object}  AIDecisionResponse
// @Failure      409  {object}  apierror.Error
// @Router       /ai/suggestions/{id}/apply [post]
func (h *AIAnalysisHandler) ApplySuggestion(w http.ResponseWriter, r *http.Request) {
	in, ok := h.decide(w, r)
	if !ok {
		return
	}
	var req ApplyAISuggestionRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 2<<10)).Decode(&req); err != nil && !errors.Is(err, io.EOF) {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}
	in.ClosureReason = req.ClosureReason
	res, err := h.svc.Apply(r.Context(), in)
	if err != nil {
		h.fail(w, err)
		return
	}
	writeAIJSON(w, http.StatusOK, AIDecisionResponse{Suggestion: toAISuggestion(res.Suggestion, nil), PendingApproval: res.PendingApproval})
}

// DismissSuggestion handles POST /api/v1/ai/suggestions/{id}/dismiss.
//
// @Summary      Dismiss an AI suggestion
// @Description  Declines a suggestion. Counts as an override: when people override 20 percent of the last 50 decisions of an auto-apply use case, it falls back to suggest.
// @Tags         Findings
// @Produce      json
// @Security     BearerAuth
// @Param        id path string true "Suggestion ID"
// @Success      200  {object}  AIDecisionResponse
// @Router       /ai/suggestions/{id}/dismiss [post]
func (h *AIAnalysisHandler) DismissSuggestion(w http.ResponseWriter, r *http.Request) {
	in, ok := h.decide(w, r)
	if !ok {
		return
	}
	s, err := h.svc.Dismiss(r.Context(), in)
	if err != nil {
		h.fail(w, err)
		return
	}
	writeAIJSON(w, http.StatusOK, AIDecisionResponse{Suggestion: toAISuggestion(s, nil)})
}

// UndoSuggestion handles POST /api/v1/ai/suggestions/{id}/undo.
//
// @Summary      Undo an applied AI suggestion
// @Description  Restores the previous value when the field has not changed since (otherwise 409 AI_UNDO_CONFLICT and nothing changes). Restoring a lower severity may need approval (pending_approval). Counts as an override.
// @Tags         Findings
// @Produce      json
// @Security     BearerAuth
// @Param        id path string true "Suggestion ID"
// @Success      200  {object}  AIDecisionResponse
// @Failure      409  {object}  apierror.Error
// @Router       /ai/suggestions/{id}/undo [post]
func (h *AIAnalysisHandler) UndoSuggestion(w http.ResponseWriter, r *http.Request) {
	in, ok := h.decide(w, r)
	if !ok {
		return
	}
	res, err := h.svc.Undo(r.Context(), in)
	if err != nil {
		h.fail(w, err)
		return
	}
	writeAIJSON(w, http.StatusOK, AIDecisionResponse{Suggestion: toAISuggestion(res.Suggestion, nil), PendingApproval: res.PendingApproval})
}

// UndoRun handles POST /api/v1/ai/runs/{id}/undo.
//
// @Summary      Undo everything an AI run applied
// @Description  Undoes every applied suggestion of the run the caller may undo; reports how many were undone, conflicted or wait for approval.
// @Tags         Findings
// @Produce      json
// @Security     BearerAuth
// @Param        id path string true "Run ID"
// @Success      200  {object}  AIUndoRunResponse
// @Router       /ai/runs/{id}/undo [post]
func (h *AIAnalysisHandler) UndoRun(w http.ResponseWriter, r *http.Request) {
	in, ok := h.decide(w, r)
	if !ok {
		return
	}
	res, err := h.svc.UndoRun(r.Context(), in, in.SuggestionID)
	if err != nil {
		h.fail(w, err)
		return
	}
	writeAIJSON(w, http.StatusOK, AIUndoRunResponse{Undone: res.Undone, Conflicts: res.Conflicts, Pending: res.Pending})
}
