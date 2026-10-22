package handler

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/internal/app/tenantai"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/validator"
)

// AISettingsStore is the organization's AI settings (*tenantai.Service).
type AISettingsStore interface {
	Get(ctx context.Context, tenantID string) (tenantai.View, error)
	Save(ctx context.Context, tenantID string, in tenantai.Update, actx auditapp.AuditContext) (tenantai.View, error)
	Test(ctx context.Context, tenantID string, in tenantai.Update, actx auditapp.AuditContext) (tenantai.TestResult, error)
}

// AISettingsHandler serves /api/v1/organization/settings/ai.
type AISettingsHandler struct {
	store     AISettingsStore
	validator *validator.Validator
	logger    *logger.Logger
}

// NewAISettingsHandler builds the handler.
func NewAISettingsHandler(store AISettingsStore, v *validator.Validator, log *logger.Logger) *AISettingsHandler {
	return &AISettingsHandler{store: store, validator: v, logger: log.With("handler", "ai-settings")}
}

const aiErrOwnProviderNotAllowedCode apierror.Code = "AI_OWN_PROVIDER_NOT_ALLOWED"

// AIKeyInfo describes the own provider's key without revealing it.
type AIKeyInfo struct {
	// Set: a key is stored.
	Set bool `json:"set"`
	// Last4 is the last four characters of the key.
	Last4     string     `json:"last4,omitempty"`
	UpdatedAt *time.Time `json:"updated_at,omitempty"`
	// UpdatedBy is the user who set it.
	UpdatedBy string `json:"updated_by,omitempty"`
}

// AISettingsResponse is the organization's AI settings. The key is never in it.
type AISettingsResponse struct {
	// Enabled: an administrator turned AI triage on; finding content may be
	// sent to the AI provider (within the AI data policy).
	Enabled bool `json:"enabled"`
	// EnabledAt is when it was turned on.
	EnabledAt *time.Time `json:"enabled_at,omitempty"`
	// EnabledBy is the user who turned it on, or "upgrade" for an
	// organization that used AI triage before consent existed.
	EnabledBy string `json:"enabled_by,omitempty"`
	// Source is platform, own or off.
	Source string `json:"source"`
	// Provider, BaseURL and Model are the own provider's (source own).
	Provider string    `json:"provider"`
	BaseURL  string    `json:"base_url"`
	Model    string    `json:"model"`
	Key      AIKeyInfo `json:"key"`
	// OwnProviderAllowed is the platform policy on own providers.
	OwnProviderAllowed bool       `json:"own_provider_allowed"`
	Providers          []string   `json:"providers"`
	UpdatedAt          *time.Time `json:"updated_at,omitempty"`
	UpdatedBy          string     `json:"updated_by,omitempty"`
}

// UpdateAISettingsRequest is a partial change: omitted fields keep their value.
type UpdateAISettingsRequest struct {
	// Enabled turns AI triage on or off (the organization's consent).
	Enabled *bool `json:"enabled"`
	// Source: platform, own or off.
	Source *string `json:"source" validate:"omitempty,oneof=platform own off"`
	// Provider of the own source: claude, openai, gemini or openai_compatible.
	Provider *string `json:"provider" validate:"omitempty,max=32"`
	// BaseURL of an OpenAI-compatible server: public https only.
	BaseURL *string `json:"base_url" validate:"omitempty,max=512"`
	Model   *string `json:"model" validate:"omitempty,max=128"`
	// APIKey is write-only: omit to keep the stored key, "" to remove it.
	APIKey *string `json:"api_key" validate:"omitempty,max=512"`
}

// TestAIConnectionResponse is the result of a connection test.
type TestAIConnectionResponse struct {
	OK bool `json:"ok"`
	// Code: ok, invalid_url, blocked_address, key_required, not_configured,
	// auth_failed, rate_limited, timeout, unreachable or provider_error.
	Code string `json:"code"`
}

func toAISettingsResponse(v tenantai.View) AISettingsResponse {
	return AISettingsResponse{
		Enabled: v.Enabled, EnabledAt: v.EnabledAt, EnabledBy: v.EnabledBy, Source: v.Source,
		Provider: v.Provider, BaseURL: v.BaseURL, Model: v.Model,
		Key:                AIKeyInfo{Set: v.KeySet, Last4: v.KeyLast4, UpdatedAt: v.KeyUpdatedAt, UpdatedBy: v.KeyUpdatedBy},
		OwnProviderAllowed: v.OwnProviderAllowed, Providers: tenantai.Providers, UpdatedAt: v.UpdatedAt, UpdatedBy: v.UpdatedBy,
	}
}

func (r UpdateAISettingsRequest) update() tenantai.Update {
	return tenantai.Update{Enabled: r.Enabled, Source: r.Source, Provider: r.Provider, BaseURL: r.BaseURL, Model: r.Model, APIKey: r.APIKey}
}

func (h *AISettingsHandler) actx(r *http.Request) auditapp.AuditContext {
	ctx := r.Context()
	actx := auditapp.AuditContext{
		ActorID: middleware.GetUserID(ctx), ActorIP: getClientIP(r), UserAgent: r.UserAgent(), RequestID: middleware.GetRequestID(r.Context()),
	}
	if lu := middleware.GetLocalUser(ctx); lu != nil {
		actx.ActorID, actx.ActorEmail = lu.ID().String(), lu.Email()
	}
	return actx
}

func (h *AISettingsHandler) fail(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, tenantai.ErrOwnProviderNotAllowed):
		apierror.New(http.StatusForbidden, aiErrOwnProviderNotAllowedCode,
			"The platform does not allow organizations to use their own AI provider.").WriteJSON(w)
	case errors.Is(err, tenantai.ErrTooManyTests):
		apierror.TooManyRequests(err.Error()).WriteJSON(w)
	case errors.Is(err, shared.ErrConflict):
		apierror.Conflict("The AI settings changed while you were editing; reload and try again.").WriteJSON(w)
	case errors.Is(err, shared.ErrValidation):
		apierror.BadRequest(easmValidationMessage(err)).WriteJSON(w)
	default:
		h.logger.Error("ai settings failed", "error", logger.SanitizeError(err))
		apierror.InternalServerError("failed to process the AI settings").WriteJSON(w)
	}
}

func (h *AISettingsHandler) decode(w http.ResponseWriter, r *http.Request) (UpdateAISettingsRequest, bool) {
	var req UpdateAISettingsRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10)).Decode(&req); err != nil && !errors.Is(err, io.EOF) {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return req, false
	}
	if err := h.validator.Validate(req); err != nil {
		apierror.BadRequest("Invalid request: check the field lengths and the source").WriteJSON(w)
		return req, false
	}
	return req, true
}

// Get handles GET /api/v1/organization/settings/ai
// @Summary      Read the organization's AI settings
// @Description  Whether AI triage is on, where the AI comes from (platform, own provider, off) and the own provider's kind, base URL, model and key status (set, last four characters, when and by whom; never the key). Owners and administrators.
// @Tags         Tenants
// @Produce      json
// @Security     BearerAuth
// @Success      200  {object}  AISettingsResponse
// @Router       /organization/settings/ai [get]
func (h *AISettingsHandler) Get(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.GetTenantID(r.Context())
	if tenantID == "" {
		apierror.BadRequest("Tenant context required").WriteJSON(w)
		return
	}
	v, err := h.store.Get(r.Context(), tenantID)
	if err != nil {
		h.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, toAISettingsResponse(v))
}

// Update handles PUT /api/v1/organization/settings/ai
// @Summary      Change the organization's AI settings
// @Description  A partial change: turn AI triage on or off (the organization's consent to send finding content, within its AI data policy), choose the source (platform, own provider, off) and set the own provider (kind, base URL for an OpenAI-compatible server, model, write-only API key). An own provider's base URL must be public https; the stored key is dropped when the provider or base URL changes. Owners and administrators; needs a recent sign-in; audited as critical (never the key). Refused with AI_OWN_PROVIDER_NOT_ALLOWED when the platform forbids own providers.
// @Tags         Tenants
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        body body UpdateAISettingsRequest true "Settings"
// @Success      200  {object}  AISettingsResponse
// @Failure      400  {object}  apierror.Error
// @Failure      403  {object}  apierror.Error
// @Router       /organization/settings/ai [put]
func (h *AISettingsHandler) Update(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.GetTenantID(r.Context())
	if tenantID == "" {
		apierror.BadRequest("Tenant context required").WriteJSON(w)
		return
	}
	req, ok := h.decode(w, r)
	if !ok {
		return
	}
	v, err := h.store.Save(r.Context(), tenantID, req.update(), h.actx(r))
	if err != nil {
		h.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, toAISettingsResponse(v))
}

// Test handles POST /api/v1/organization/settings/ai/test
// @Summary      Test the organization's own AI provider
// @Description  Calls the provider from the server with one tiny prompt (no finding data) using the values in the body over the stored ones; the stored key is used only when the provider and base URL are the stored ones. Answers ok or a fixed error code, never the provider's text. At most a few tests a minute per organization. Owners and administrators.
// @Tags         Tenants
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        body body UpdateAISettingsRequest false "Values to test"
// @Success      200  {object}  TestAIConnectionResponse
// @Failure      403  {object}  apierror.Error
// @Failure      429  {object}  apierror.Error
// @Router       /organization/settings/ai/test [post]
func (h *AISettingsHandler) Test(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.GetTenantID(r.Context())
	if tenantID == "" {
		apierror.BadRequest("Tenant context required").WriteJSON(w)
		return
	}
	req, ok := h.decode(w, r)
	if !ok {
		return
	}
	res, err := h.store.Test(r.Context(), tenantID, req.update(), h.actx(r))
	if err != nil {
		h.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, TestAIConnectionResponse{OK: res.OK, Code: res.Code})
}
