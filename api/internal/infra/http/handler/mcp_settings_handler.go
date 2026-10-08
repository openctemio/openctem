package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	mcpoauthapp "github.com/openctemio/openctem/api/internal/app/mcpoauth"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/mcpoauth"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/tenant"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// MCPSettingsStore reads and writes the organization's MCP policy
// (*tenant.TenantService).
type MCPSettingsStore interface {
	GetMCPSettings(ctx context.Context, tenantID string) (*tenant.MCPSettings, error)
	UpdateMCPSettings(ctx context.Context, tenantID string, ms tenant.MCPSettings, actx auditapp.AuditContext) (*tenant.MCPSettings, error)
}

// MCPSettingsHandler serves /api/v1/mcp-access/settings: the organization's
// policy for AI applications on the MCP server (RFC-062 §8).
type MCPSettingsHandler struct {
	store        MCPSettingsStore
	trustedHosts []string
	logger       *logger.Logger
}

// NewMCPSettingsHandler builds the handler. trustedHosts is the platform
// list shown read-only next to the organization's own.
func NewMCPSettingsHandler(store MCPSettingsStore, trustedHosts []string, log *logger.Logger) *MCPSettingsHandler {
	return &MCPSettingsHandler{store: store, trustedHosts: mcpoauthapp.NormalizeTrustedHosts(trustedHosts), logger: log.With("handler", "mcp-settings")}
}

// MCPScopeInfo describes one scope for the settings page.
type MCPScopeInfo struct {
	Scope string `json:"scope"`
	Title string `json:"title"`
	Write bool   `json:"write"`
}

// MCPSettingsResponse is the organization's MCP policy.
type MCPSettingsResponse struct {
	Enabled bool `json:"enabled"`
	// AnyClient: members may connect applications nobody vouches for.
	AnyClient   bool     `json:"any_client"`
	ClientHosts []string `json:"client_hosts"`
	// Scopes members may grant; empty means every read scope.
	Scopes         []string `json:"scopes"`
	APIKeysAllowed bool     `json:"api_keys_allowed"`
	// RefreshDays: 0 means 90.
	RefreshDays          int            `json:"refresh_days"`
	EffectiveRefreshDays int            `json:"effective_refresh_days"`
	PlatformClientHosts  []string       `json:"platform_client_hosts"`
	AvailableScopes      []MCPScopeInfo `json:"available_scopes"`
}

// MCPSettingsUpdateRequest replaces the policy.
type MCPSettingsUpdateRequest struct {
	Enabled        bool     `json:"enabled"`
	AnyClient      bool     `json:"any_client"`
	ClientHosts    []string `json:"client_hosts"`
	Scopes         []string `json:"scopes"`
	APIKeysAllowed bool     `json:"api_keys_allowed"`
	RefreshDays    int      `json:"refresh_days"`
}

func (h *MCPSettingsHandler) response(s tenant.MCPSettings) MCPSettingsResponse {
	out := MCPSettingsResponse{
		Enabled: !s.Disabled, AnyClient: s.AnyClient, ClientHosts: s.ClientHosts, Scopes: s.Scopes,
		APIKeysAllowed: !s.APIKeysDisabled, RefreshDays: s.RefreshDays, EffectiveRefreshDays: s.RefreshLimitDays(),
		PlatformClientHosts: h.trustedHosts,
	}
	if out.ClientHosts == nil {
		out.ClientHosts = []string{}
	}
	if out.Scopes == nil {
		out.Scopes = []string{}
	}
	if out.PlatformClientHosts == nil {
		out.PlatformClientHosts = []string{}
	}
	for _, sc := range mcpoauth.AllScopes() {
		out.AvailableScopes = append(out.AvailableScopes, MCPScopeInfo{Scope: string(sc), Title: mcpoauth.Title(sc), Write: mcpoauth.IsWrite(sc)})
	}
	return out
}

// Get serves GET /api/v1/mcp-access/settings.
// @Summary      Read the organization policy for AI applications
// @Description  Whether the MCP server is on for the organization, which applications may connect (verified only, or any), the organization's trusted client hosts and the platform's, the scopes members may grant, whether oct_ keys work on MCP, and how long a connection lasts (RFC-062).
// @Tags         MCP
// @Produce      json
// @Security     BearerAuth
// @Success      200  {object}  MCPSettingsResponse
// @Router       /mcp-access/settings [get]
func (h *MCPSettingsHandler) Get(w http.ResponseWriter, r *http.Request) {
	s, err := h.store.GetMCPSettings(r.Context(), middleware.GetTenantID(r.Context()))
	if err != nil {
		h.logger.Error("mcp settings: read", "error", logger.SanitizeError(err))
		apierror.InternalServerError("failed to read the settings").WriteJSON(w)
		return
	}
	writeJSON(w, http.StatusOK, h.response(*s))
}

// Update serves PUT /api/v1/mcp-access/settings.
// @Summary      Change the organization policy for AI applications
// @Description  Replaces the policy. It applies to the next request of every existing connection. Needs a recent sign-in. Audited.
// @Tags         MCP
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        body body MCPSettingsUpdateRequest true "Policy"
// @Success      200  {object}  MCPSettingsResponse
// @Failure      400  {object}  apierror.Error
// @Failure      409  {object}  apierror.Error
// @Router       /mcp-access/settings [put]
func (h *MCPSettingsHandler) Update(w http.ResponseWriter, r *http.Request) {
	limitBody(w, r)
	var req MCPSettingsUpdateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("invalid request body").WriteJSON(w)
		return
	}
	s := tenant.MCPSettings{
		Disabled: !req.Enabled, AnyClient: req.AnyClient, ClientHosts: req.ClientHosts, Scopes: req.Scopes,
		APIKeysDisabled: !req.APIKeysAllowed, RefreshDays: req.RefreshDays,
	}
	if err := mcpoauthapp.ValidatePolicy(&s); err != nil {
		apierror.BadRequest(easmValidationMessage(err)).WriteJSON(w)
		return
	}
	ctx := r.Context()
	saved, err := h.store.UpdateMCPSettings(ctx, middleware.GetTenantID(ctx), s, auditapp.AuditContext{
		ActorID: middleware.GetUserID(ctx), ActorIP: getClientIP(r), UserAgent: r.UserAgent(), RequestID: r.Header.Get("X-Request-ID"),
	})
	if err != nil {
		switch {
		case errors.Is(err, shared.ErrValidation):
			apierror.BadRequest(easmValidationMessage(err)).WriteJSON(w)
		case errors.Is(err, shared.ErrConflict):
			apierror.Conflict("The settings changed meanwhile; reload and try again").WriteJSON(w)
		default:
			h.logger.Error("mcp settings: write", "error", logger.SanitizeError(err))
			apierror.InternalServerError("failed to save the settings").WriteJSON(w)
		}
		return
	}
	writeJSON(w, http.StatusOK, h.response(*saved))
}
