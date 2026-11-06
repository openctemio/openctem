package handler

// Settings > AI > Use cases (docs/architecture/ai-use-cases.md).

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	authapp "github.com/openctemio/openctem/api/internal/app/auth"
	"github.com/openctemio/openctem/api/internal/app/tenantai"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// AIUseCaseStore is the organization's per-use-case AI settings
// (*tenantai.Service).
type AIUseCaseStore interface {
	UseCases(ctx context.Context, tenantID string) ([]tenantai.UseCaseView, error)
	SaveUseCase(ctx context.Context, tenantID, useCase string, in tenantai.UseCaseInput, actx auditapp.AuditContext) (tenantai.UseCaseView, error)
}

// AIUseCaseDowngrade describes the last automatic fall-back from auto-apply
// to suggest.
type AIUseCaseDowngrade struct {
	At *time.Time `json:"at"`
	// Reason is a fixed code: override_rate.
	Reason string `json:"reason"`
	// Decisions and Overrides are the person decisions counted and how many
	// of them overrode the AI.
	Decisions int `json:"decisions"`
	Overrides int `json:"overrides"`
}

// AIUseCaseResponse is one use case's settings.
type AIUseCaseResponse struct {
	// UseCase is triage, remediation or summary.
	UseCase string `json:"use_case"`
	// Mode is off, suggest or auto_apply (as saved).
	Mode string `json:"mode"`
	// EffectiveMode is the mode in force: off while AI is turned off for the
	// organization.
	EffectiveMode string `json:"effective_mode"`
	// Ceiling is the most sensitive data class sent: public, internal or
	// restricted.
	Ceiling string `json:"ceiling"`
	// MinConfidence is the confidence (0.50 to 0.99) from which a result may
	// apply on its own.
	MinConfidence float64 `json:"min_confidence"`
	// AutoApplySince is when auto-apply was turned on.
	AutoApplySince *time.Time          `json:"auto_apply_since,omitempty"`
	Downgrade      *AIUseCaseDowngrade `json:"downgrade,omitempty"`
	UpdatedAt      *time.Time          `json:"updated_at,omitempty"`
	UpdatedBy      string              `json:"updated_by,omitempty"`
	// Loosened (answer of a change) lists why the change was a loosening
	// (auto_apply_on, ceiling_raised, confidence_lowered): it needed a recent
	// sign-in, was audited critical and the owners and administrators were
	// told.
	Loosened []string `json:"loosened,omitempty"`
}

// AIUseCasesResponse lists every use case in display order.
type AIUseCasesResponse struct {
	Items []AIUseCaseResponse `json:"items"`
}

// UpdateAIUseCaseRequest replaces one use case's settings.
type UpdateAIUseCaseRequest struct {
	Mode          string  `json:"mode" validate:"required,oneof=off suggest auto_apply"`
	Ceiling       string  `json:"ceiling" validate:"required,oneof=public internal restricted"`
	MinConfidence float64 `json:"min_confidence" validate:"min=0.5,max=0.99"`
}

func toAIUseCaseResponse(v tenantai.UseCaseView) AIUseCaseResponse {
	out := AIUseCaseResponse{
		UseCase: string(v.UseCase), Mode: string(v.Mode), EffectiveMode: string(v.Effective), Ceiling: string(v.Ceiling),
		MinConfidence: v.MinConfidence, AutoApplySince: v.AutoApplySince, UpdatedAt: v.UpdatedAt, UpdatedBy: v.UpdatedBy,
		Loosened: v.Loosened,
	}
	if v.DowngradedAt != nil {
		out.Downgrade = &AIUseCaseDowngrade{At: v.DowngradedAt, Reason: v.DowngradeReason,
			Decisions: v.DowngradeDecisions, Overrides: v.DowngradeOverrides}
	}
	return out
}

func (h *AISettingsHandler) useCases(w http.ResponseWriter, r *http.Request) (AIUseCaseStore, string, bool) {
	store, ok := h.store.(AIUseCaseStore)
	if !ok {
		apierror.NotFound("AI use cases").WriteJSON(w)
		return nil, "", false
	}
	tenantID := middleware.GetTenantID(r.Context())
	if tenantID == "" {
		apierror.BadRequest("Tenant context required").WriteJSON(w)
		return nil, "", false
	}
	return store, tenantID, true
}

// ListUseCases handles GET /api/v1/organization/settings/ai/use-cases
// @Summary      Read the AI use case settings
// @Description  For triage, remediation steps and summary: the mode (off, suggest, auto_apply) and the mode in force (off while AI is turned off), the most sensitive data class sent, the minimum confidence to apply on its own, and the last automatic downgrade. Anyone with settings:read.
// @Tags         Tenants
// @Produce      json
// @Security     BearerAuth
// @Success      200  {object}  AIUseCasesResponse
// @Router       /organization/settings/ai/use-cases [get]
func (h *AISettingsHandler) ListUseCases(w http.ResponseWriter, r *http.Request) {
	store, tenantID, ok := h.useCases(w, r)
	if !ok {
		return
	}
	list, err := store.UseCases(r.Context(), tenantID)
	if err != nil {
		h.fail(w, err)
		return
	}
	out := AIUseCasesResponse{Items: make([]AIUseCaseResponse, 0, len(list))}
	for _, v := range list {
		out.Items = append(out.Items, toAIUseCaseResponse(v))
	}
	writeJSON(w, http.StatusOK, out)
}

// UpdateUseCase handles PUT /api/v1/organization/settings/ai/use-cases/{use_case}
// @Summary      Change one AI use case
// @Description  Replaces the mode, the data class ceiling and the minimum confidence of triage, remediation or summary. Turning auto-apply on (also after an automatic downgrade, which it clears), raising the ceiling above internal, or lowering the minimum confidence while auto-applying needs a recent sign-in (403 STEP_UP_REQUIRED), is audited critical and every owner and administrator is told. Turning a use case off or to suggest and lowering the ceiling apply at once. Auto-apply never applies a severity change, a risk-lowering change or a flagged result. Owners and administrators with settings:write.
// @Tags         Tenants
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        use_case path string true "triage, remediation or summary"
// @Param        body body UpdateAIUseCaseRequest true "Settings"
// @Success      200  {object}  AIUseCaseResponse
// @Failure      400  {object}  apierror.Error
// @Failure      403  {object}  apierror.Error
// @Router       /organization/settings/ai/use-cases/{use_case} [put]
func (h *AISettingsHandler) UpdateUseCase(w http.ResponseWriter, r *http.Request) {
	store, tenantID, ok := h.useCases(w, r)
	if !ok {
		return
	}
	var req UpdateAIUseCaseRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10)).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}
	if err := h.validator.Validate(req); err != nil {
		apierror.BadRequest("Invalid request: mode is off, suggest or auto_apply; ceiling is public, internal or restricted; min_confidence is 0.50 to 0.99").WriteJSON(w)
		return
	}
	v, err := store.SaveUseCase(r.Context(), tenantID, r.PathValue("use_case"),
		tenantai.UseCaseInput{Mode: req.Mode, Ceiling: req.Ceiling, MinConfidence: req.MinConfidence}, h.actx(r))
	if err != nil {
		if middleware.WriteStepUpError(w, err, authapp.StepUpWindow) {
			return
		}
		if errors.Is(err, tenantai.ErrNoActor) {
			apierror.Forbidden("A signed-in owner or administrator must make this change.").WriteJSON(w)
			return
		}
		if errors.Is(err, shared.ErrValidation) {
			apierror.BadRequest("Invalid AI use case settings: the use case is triage, remediation or summary").WriteJSON(w)
			return
		}
		h.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, toAIUseCaseResponse(v))
}
