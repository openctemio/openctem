package handler

import (
	"encoding/json"
	"errors"
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

// AIAnalysisHandler serves AI analysts (service accounts that triage like a
// person, with accountable owners) and their runs
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
	aiErrPausedCode apierror.Code = "AI_ANALYST_PAUSED"
	aiErrBudgetCode apierror.Code = "AI_ANALYST_LIMIT"
)

// AIOwnerResponse is one accountable owner.
type AIOwnerResponse struct {
	Kind string `json:"kind"`
	ID   string `json:"id"`
	Name string `json:"name"`
}

// AIAnalystResponse is one AI analyst.
type AIAnalystResponse struct {
	ID               string            `json:"id"`
	Name             string            `json:"name"`
	Description      string            `json:"description"`
	Preset           string            `json:"preset"`
	Status           string            `json:"status"`
	PauseReason      string            `json:"pause_reason,omitempty"`
	DataClassCeiling string            `json:"data_class_ceiling"`
	Executor         string            `json:"executor"`
	RunsPerHour      int               `json:"runs_per_hour"`
	ActionsPerHour   int               `json:"actions_per_hour"`
	TokensMonth      int               `json:"tokens_month"`
	AttestedAt       time.Time         `json:"attested_at"`
	AttestDueAt      time.Time         `json:"attest_due_at"`
	Owners           []AIOwnerResponse `json:"owners"`
	CreatedAt        time.Time         `json:"created_at"`
}

// AIAnalystListResponse lists AI analysts.
type AIAnalystListResponse struct {
	Data []AIAnalystResponse `json:"data"`
}

// AIRunResponse is one run with its provenance.
type AIRunResponse struct {
	ID                   string            `json:"id"`
	AnalystID            string            `json:"analyst_id,omitempty"`
	UseCase              string            `json:"use_case"`
	Kind                 string            `json:"kind"`
	SubjectType          string            `json:"subject_type"`
	SubjectID            string            `json:"subject_id"`
	Executor             string            `json:"executor"`
	Status               string            `json:"status"`
	DataClass            string            `json:"data_class"`
	FieldsSent           []string          `json:"fields_sent"`
	FieldsWithheld       []string          `json:"fields_withheld"`
	BundleDigest         string            `json:"bundle_digest,omitempty"`
	PromptTemplateID     string            `json:"prompt_template_id,omitempty"`
	PromptTemplateDigest string            `json:"prompt_template_digest,omitempty"`
	OutputSchema         string            `json:"output_schema,omitempty"`
	Provider             string            `json:"provider,omitempty"`
	Model                string            `json:"model,omitempty"`
	Actions              int               `json:"actions"`
	TokensIn             int               `json:"tokens_in"`
	TokensOut            int               `json:"tokens_out"`
	CostMicroUSD         int64             `json:"cost_micro_usd"`
	DurationMS           *int              `json:"duration_ms,omitempty"`
	ErrorCode            string            `json:"error_code,omitempty"`
	Trigger              string            `json:"trigger"`
	TriggeredBy          string            `json:"triggered_by,omitempty"`
	Accountable          []AIOwnerResponse `json:"accountable"`
	LegacyOutput         map[string]any    `json:"legacy_output,omitempty"`
	CreatedAt            time.Time         `json:"created_at"`
	CompletedAt          *time.Time        `json:"completed_at,omitempty"`
}

// AIRunListResponse lists runs.
type AIRunListResponse struct {
	Data []AIRunResponse `json:"data"`
}

// SetAIAnalystOwnersRequest replaces the accountable owners.
type SetAIAnalystOwnersRequest struct {
	Owners []aianalysis.OwnerInput `json:"owners" validate:"required,min=1,max=20,dive"`
}

// SetAIAnalystPresetRequest moves an analyst to another preset role.
type SetAIAnalystPresetRequest struct {
	Preset string `json:"preset" validate:"required,oneof=suggest triage"`
}

func toAIOwners(o []aidom.OwnerRef) []AIOwnerResponse {
	out := make([]AIOwnerResponse, 0, len(o))
	for _, x := range o {
		out = append(out, AIOwnerResponse{Kind: string(x.Kind), ID: x.ID.String(), Name: x.Name})
	}
	return out
}

func toAIAnalyst(a *aidom.Analyst) AIAnalystResponse {
	return AIAnalystResponse{
		ID: a.ID.String(), Name: a.Name, Description: a.Description, Preset: string(a.Preset), Status: string(a.Status),
		PauseReason: string(a.PauseReason), DataClassCeiling: string(a.DataClassCeiling), Executor: string(a.Executor),
		RunsPerHour: a.RunsPerHour, ActionsPerHour: a.ActionsPerHour, TokensMonth: a.TokensMonth,
		AttestedAt: a.AttestedAt, AttestDueAt: a.AttestDueAt, Owners: toAIOwners(a.Owners), CreatedAt: a.CreatedAt,
	}
}

func idStr(id *shared.ID) string {
	if id == nil {
		return ""
	}
	return id.String()
}

func toAIRun(run *aidom.Run) AIRunResponse {
	return AIRunResponse{
		ID: run.ID.String(), AnalystID: idStr(run.AnalystID), UseCase: string(run.UseCase), Kind: run.Kind,
		SubjectType: string(run.SubjectType), SubjectID: run.SubjectID.String(), Executor: string(run.Executor),
		Status: string(run.Status), DataClass: string(run.DataClass), FieldsSent: nonNilStrings(run.FieldsSent),
		FieldsWithheld: nonNilStrings(run.FieldsWithheld), BundleDigest: run.BundleDigest,
		PromptTemplateID: run.PromptTemplateID, PromptTemplateDigest: run.PromptTemplateDigest,
		OutputSchema: run.OutputSchema, Provider: run.Provider, Model: run.Model, Actions: run.Actions,
		TokensIn: run.TokensIn, TokensOut: run.TokensOut, CostMicroUSD: run.CostMicroUSD, DurationMS: run.DurationMS,
		ErrorCode: run.ErrorCode, Trigger: string(run.Trigger), TriggeredBy: idStr(run.TriggeredBy),
		Accountable: toAIOwners(run.Accountable), LegacyOutput: run.LegacyOutput, CreatedAt: run.CreatedAt,
		CompletedAt: run.CompletedAt,
	}
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
	var paused *aidom.PausedError
	switch {
	case errors.As(err, &paused):
		apierror.New(http.StatusConflict, aiErrPausedCode, "The AI analyst is paused: "+string(paused.Reason)+".").WriteJSON(w)
	case errors.Is(err, aianalysis.ErrBudget):
		apierror.New(http.StatusTooManyRequests, aiErrBudgetCode, "The AI analyst reached its limit for now.").WriteJSON(w)
	case errors.Is(err, shared.ErrNotFound):
		apierror.NotFound("AI analyst").WriteJSON(w)
	case errors.Is(err, shared.ErrForbidden):
		apierror.Forbidden("You may not do this to this AI analyst.").WriteJSON(w)
	case errors.Is(err, shared.ErrConflict):
		apierror.Conflict("The AI analyst changed; reload and try again.").WriteJSON(w)
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

func aiViewerOf(w http.ResponseWriter, r *http.Request) (shared.ID, bool) {
	id, err := shared.IDFromString(middleware.GetUserID(r.Context()))
	if err != nil {
		apierror.Unauthorized("A person must make this request").WriteJSON(w)
		return shared.ID{}, false
	}
	return id, true
}

func decodeAIBody(w http.ResponseWriter, r *http.Request, v any) bool {
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(v); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return false
	}
	return true
}

// ListAnalysts handles GET /api/v1/ai/analysts.
//
// @Summary      List AI analysts
// @Description  The organization's AI analysts: service accounts that triage like a person, with their preset role, status, accountable owners and attestation.
// @Tags         AI
// @Produce      json
// @Success      200  {object}  AIAnalystListResponse
// @Security     BearerAuth
// @Router       /ai/analysts [get]
func (h *AIAnalysisHandler) ListAnalysts(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := aiTenantOf(w, r)
	if !ok {
		return
	}
	list, err := h.svc.List(r.Context(), tenantID)
	if err != nil {
		h.fail(w, err)
		return
	}
	out := AIAnalystListResponse{Data: make([]AIAnalystResponse, 0, len(list))}
	for _, a := range list {
		out.Data = append(out.Data, toAIAnalyst(a))
	}
	writeAIJSON(w, http.StatusOK, out)
}

// GetAnalyst handles GET /api/v1/ai/analysts/{id}.
//
// @Summary      Get an AI analyst
// @Tags         AI
// @Produce      json
// @Param        id path string true "Analyst ID"
// @Success      200  {object}  AIAnalystResponse
// @Security     BearerAuth
// @Router       /ai/analysts/{id} [get]
func (h *AIAnalysisHandler) GetAnalyst(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := aiTenantOf(w, r)
	if !ok {
		return
	}
	id, ok := aiPathID(w, r, "id")
	if !ok {
		return
	}
	a, err := h.svc.Get(r.Context(), tenantID, id)
	if err != nil {
		h.fail(w, err)
		return
	}
	writeAIJSON(w, http.StatusOK, toAIAnalyst(a))
}

// CreateAnalyst handles POST /api/v1/ai/analysts.
//
// @Summary      Create an AI analyst
// @Description  Creates a service account with the preset role (suggest or triage) and its accountable owners (people or teams, at least one). The preset's permissions must be held by an accountable person and grantable by the caller. Needs a recent sign-in.
// @Tags         AI
// @Accept       json
// @Produce      json
// @Param        request body aianalysis.CreateInput true "Analyst"
// @Success      201  {object}  AIAnalystResponse
// @Failure      400  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /ai/analysts [post]
func (h *AIAnalysisHandler) CreateAnalyst(w http.ResponseWriter, r *http.Request) {
	var in aianalysis.CreateInput
	if !decodeAIBody(w, r, &in) {
		return
	}
	a, err := h.svc.Create(r.Context(), in, h.actx(r))
	if err != nil {
		h.fail(w, err)
		return
	}
	writeAIJSON(w, http.StatusCreated, toAIAnalyst(a))
}

// SetOwners handles PUT /api/v1/ai/analysts/{id}/owners.
//
// @Summary      Replace an AI analyst's accountable owners
// @Description  People or teams, at least one; the analyst's role must stay within what they hold. Needs a recent sign-in.
// @Tags         AI
// @Accept       json
// @Produce      json
// @Param        id path string true "Analyst ID"
// @Param        request body SetAIAnalystOwnersRequest true "Owners"
// @Success      200  {object}  AIAnalystResponse
// @Security     BearerAuth
// @Router       /ai/analysts/{id}/owners [put]
func (h *AIAnalysisHandler) SetOwners(w http.ResponseWriter, r *http.Request) {
	id, ok := aiPathID(w, r, "id")
	if !ok {
		return
	}
	var in SetAIAnalystOwnersRequest
	if !decodeAIBody(w, r, &in) {
		return
	}
	a, err := h.svc.ReplaceOwners(r.Context(), id, in.Owners, h.actx(r))
	if err != nil {
		h.fail(w, err)
		return
	}
	writeAIJSON(w, http.StatusOK, toAIAnalyst(a))
}

// SetPreset handles PUT /api/v1/ai/analysts/{id}/preset.
//
// @Summary      Move an AI analyst to another preset role
// @Description  suggest (comments and approval requests only) or triage (also status, severity raise, duplicates, assignment). Needs a recent sign-in.
// @Tags         AI
// @Accept       json
// @Produce      json
// @Param        id path string true "Analyst ID"
// @Param        request body SetAIAnalystPresetRequest true "Preset"
// @Success      200  {object}  AIAnalystResponse
// @Security     BearerAuth
// @Router       /ai/analysts/{id}/preset [put]
func (h *AIAnalysisHandler) SetPreset(w http.ResponseWriter, r *http.Request) {
	id, ok := aiPathID(w, r, "id")
	if !ok {
		return
	}
	var in SetAIAnalystPresetRequest
	if !decodeAIBody(w, r, &in) {
		return
	}
	a, err := h.svc.ChangePreset(r.Context(), id, in.Preset, h.actx(r))
	if err != nil {
		h.fail(w, err)
		return
	}
	writeAIJSON(w, http.StatusOK, toAIAnalyst(a))
}

// Attest handles POST /api/v1/ai/analysts/{id}/attest.
//
// @Summary      Attest an AI analyst
// @Description  An accountable owner (or an administrator) confirms the analyst's role, scope and behavior for another 90 days.
// @Tags         AI
// @Produce      json
// @Param        id path string true "Analyst ID"
// @Success      200  {object}  AIAnalystResponse
// @Security     BearerAuth
// @Router       /ai/analysts/{id}/attest [post]
func (h *AIAnalysisHandler) Attest(w http.ResponseWriter, r *http.Request) {
	id, ok := aiPathID(w, r, "id")
	if !ok {
		return
	}
	a, err := h.svc.Attest(r.Context(), id, middleware.IsAdmin(r.Context()), h.actx(r))
	if err != nil {
		h.fail(w, err)
		return
	}
	writeAIJSON(w, http.StatusOK, toAIAnalyst(a))
}

// Pause handles POST /api/v1/ai/analysts/{id}/pause.
//
// @Summary      Pause an AI analyst
// @Description  An accountable owner or a holder of service_accounts:manage stops the analyst until it is resumed.
// @Tags         AI
// @Produce      json
// @Param        id path string true "Analyst ID"
// @Success      200  {object}  AIAnalystResponse
// @Security     BearerAuth
// @Router       /ai/analysts/{id}/pause [post]
func (h *AIAnalysisHandler) Pause(w http.ResponseWriter, r *http.Request) {
	id, ok := aiPathID(w, r, "id")
	if !ok {
		return
	}
	canManage := middleware.HasPermission(r.Context(), string(permission.ServiceAccountsManage))
	a, err := h.svc.Pause(r.Context(), id, canManage, h.actx(r))
	if err != nil {
		h.fail(w, err)
		return
	}
	writeAIJSON(w, http.StatusOK, toAIAnalyst(a))
}

// Resume handles POST /api/v1/ai/analysts/{id}/resume.
//
// @Summary      Resume an AI analyst
// @Description  Runs a paused or disabled analyst again once it has an active owner and a fresh attestation. Needs a recent sign-in.
// @Tags         AI
// @Produce      json
// @Param        id path string true "Analyst ID"
// @Success      200  {object}  AIAnalystResponse
// @Security     BearerAuth
// @Router       /ai/analysts/{id}/resume [post]
func (h *AIAnalysisHandler) Resume(w http.ResponseWriter, r *http.Request) {
	id, ok := aiPathID(w, r, "id")
	if !ok {
		return
	}
	a, err := h.svc.Resume(r.Context(), id, h.actx(r))
	if err != nil {
		h.fail(w, err)
		return
	}
	writeAIJSON(w, http.StatusOK, toAIAnalyst(a))
}

// Disable handles POST /api/v1/ai/analysts/{id}/disable.
//
// @Summary      Disable an AI analyst (kill switch)
// @Tags         AI
// @Produce      json
// @Param        id path string true "Analyst ID"
// @Success      200  {object}  AIAnalystResponse
// @Security     BearerAuth
// @Router       /ai/analysts/{id}/disable [post]
func (h *AIAnalysisHandler) Disable(w http.ResponseWriter, r *http.Request) {
	id, ok := aiPathID(w, r, "id")
	if !ok {
		return
	}
	a, err := h.svc.Disable(r.Context(), id, h.actx(r))
	if err != nil {
		h.fail(w, err)
		return
	}
	writeAIJSON(w, http.StatusOK, toAIAnalyst(a))
}

// DeleteAnalyst handles DELETE /api/v1/ai/analysts/{id}.
//
// @Summary      Delete an AI analyst
// @Description  Removes the analyst and its service account; its runs and changes stay in the history. Needs a recent sign-in.
// @Tags         AI
// @Param        id path string true "Analyst ID"
// @Success      204
// @Security     BearerAuth
// @Router       /ai/analysts/{id} [delete]
func (h *AIAnalysisHandler) DeleteAnalyst(w http.ResponseWriter, r *http.Request) {
	id, ok := aiPathID(w, r, "id")
	if !ok {
		return
	}
	if err := h.svc.Delete(r.Context(), id, h.actx(r)); err != nil {
		h.fail(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// GetRun handles GET /api/v1/ai/runs/{id}.
//
// @Summary      Get an AI run
// @Description  A run's provenance: analyst, accountable owners at that moment, model, prompt template and digest, fields sent and withheld, usage. Only for a caller who can see the run's subject.
// @Tags         AI
// @Produce      json
// @Param        id path string true "Run ID"
// @Success      200  {object}  AIRunResponse
// @Security     BearerAuth
// @Router       /ai/runs/{id} [get]
func (h *AIAnalysisHandler) GetRun(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := aiTenantOf(w, r)
	if !ok {
		return
	}
	viewer, ok := aiViewerOf(w, r)
	if !ok {
		return
	}
	runID, ok := aiPathID(w, r, "id")
	if !ok {
		return
	}
	run, err := h.svc.GetRun(r.Context(), tenantID, viewer, runID)
	if err != nil {
		h.fail(w, err)
		return
	}
	writeAIJSON(w, http.StatusOK, toAIRun(run))
}

// ListFindingRuns handles GET /api/v1/findings/{id}/ai/runs.
//
// @Summary      List a finding's AI runs
// @Tags         AI
// @Produce      json
// @Param        id path string true "Finding ID"
// @Success      200  {object}  AIRunListResponse
// @Security     BearerAuth
// @Router       /findings/{id}/ai/runs [get]
func (h *AIAnalysisHandler) ListFindingRuns(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := aiTenantOf(w, r)
	if !ok {
		return
	}
	viewer, ok := aiViewerOf(w, r)
	if !ok {
		return
	}
	findingID, ok := aiPathID(w, r, "id")
	if !ok {
		return
	}
	runs, err := h.svc.ListRunsForFinding(r.Context(), tenantID, viewer, findingID)
	if err != nil {
		h.fail(w, err)
		return
	}
	out := AIRunListResponse{Data: make([]AIRunResponse, 0, len(runs))}
	for _, run := range runs {
		out.Data = append(out.Data, toAIRun(run))
	}
	writeAIJSON(w, http.StatusOK, out)
}
