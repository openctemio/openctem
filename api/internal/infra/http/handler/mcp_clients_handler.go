package handler

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	mcpoauthapp "github.com/openctemio/openctem/api/internal/app/mcpoauth"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/mcpoauth"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// MCPClientsHandler serves the clients an organization registers in advance
// (/api/v1/mcp-access/clients) and dynamic registration (POST
// /oauth/register) of RFC-062 §5.
type MCPClientsHandler struct {
	svc *mcpoauthapp.Service
	log *logger.Logger
}

// NewMCPClientsHandler builds the handler.
func NewMCPClientsHandler(svc *mcpoauthapp.Service, log *logger.Logger) *MCPClientsHandler {
	return &MCPClientsHandler{svc: svc, log: log.With("handler", "mcp-clients")}
}

// MCPOrganizationClient is a client the organization registered.
type MCPOrganizationClient struct {
	ID           string    `json:"id"`
	ClientID     string    `json:"client_id"`
	Name         string    `json:"name"`
	RedirectURIs []string  `json:"redirect_uris"`
	CreatedAt    time.Time `json:"created_at"`
}

// MCPOrganizationClientList lists the organization's clients.
type MCPOrganizationClientList struct {
	Data []MCPOrganizationClient `json:"data"`
}

// MCPOrganizationClientCreate registers a client.
type MCPOrganizationClientCreate struct {
	Name         string   `json:"name"`
	RedirectURIs []string `json:"redirect_uris"`
}

func toOrgClient(c mcpoauth.Client) MCPOrganizationClient {
	return MCPOrganizationClient{ID: c.ID.String(), ClientID: c.ClientID, Name: c.Name, RedirectURIs: c.RedirectURIs, CreatedAt: c.CreatedAt}
}

func (h *MCPClientsHandler) caller(r *http.Request) (tenantID, userID shared.ID, ok bool) {
	t, err1 := shared.IDFromString(middleware.GetTenantID(r.Context()))
	u, err2 := shared.IDFromString(middleware.GetUserID(r.Context()))
	return t, u, err1 == nil && err2 == nil
}

// List serves GET /api/v1/mcp-access/clients.
// @Summary      List the organization's registered AI applications
// @Description  MCP clients the organization registered in advance: their client id (not a secret; clients prove themselves with PKCE) and the exact redirect URIs they may use (RFC-062).
// @Tags         MCP
// @Produce      json
// @Security     BearerAuth
// @Success      200  {object}  MCPOrganizationClientList
// @Router       /mcp-access/clients [get]
func (h *MCPClientsHandler) List(w http.ResponseWriter, r *http.Request) {
	tenantID, _, ok := h.caller(r)
	if !ok {
		apierror.Unauthorized("Invalid credentials").WriteJSON(w)
		return
	}
	list, err := h.svc.ListOrganizationClients(r.Context(), tenantID)
	if err != nil {
		h.log.Error("list organization mcp clients", "error", logger.SanitizeError(err))
		apierror.InternalServerError("failed to list clients").WriteJSON(w)
		return
	}
	out := MCPOrganizationClientList{Data: make([]MCPOrganizationClient, 0, len(list))}
	for _, c := range list {
		out.Data = append(out.Data, toOrgClient(c))
	}
	writeJSON(w, http.StatusOK, out)
}

// Create serves POST /api/v1/mcp-access/clients.
// @Summary      Register an AI application for the organization
// @Description  Registers an MCP client the organization vouches for: members see it as registered by the organization, and no other organization can use it. Redirect URIs must be https, or http on a loopback address (any port). Needs a recent sign-in. Audited.
// @Tags         MCP
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        body body MCPOrganizationClientCreate true "Client"
// @Success      201  {object}  MCPOrganizationClient
// @Failure      400  {object}  apierror.Error
// @Router       /mcp-access/clients [post]
func (h *MCPClientsHandler) Create(w http.ResponseWriter, r *http.Request) {
	tenantID, userID, ok := h.caller(r)
	if !ok {
		apierror.Unauthorized("Invalid credentials").WriteJSON(w)
		return
	}
	limitBody(w, r)
	var req MCPOrganizationClientCreate
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("invalid request body").WriteJSON(w)
		return
	}
	c, err := h.svc.CreateOrganizationClient(r.Context(), tenantID, userID, req.Name, req.RedirectURIs, oauthActor(r))
	if err != nil {
		if errors.Is(err, shared.ErrValidation) {
			apierror.BadRequest(easmValidationMessage(err)).WriteJSON(w)
			return
		}
		h.log.Error("create organization mcp client", "error", logger.SanitizeError(err))
		apierror.InternalServerError("failed to register the client").WriteJSON(w)
		return
	}
	writeJSON(w, http.StatusCreated, toOrgClient(*c))
}

// Delete serves DELETE /api/v1/mcp-access/clients/{id}.
// @Summary      Delete a registered AI application
// @Description  Removes the client; every connection made with it ends at once. Needs a recent sign-in. Audited.
// @Tags         MCP
// @Security     BearerAuth
// @Param        id   path  string  true  "Client id"
// @Success      204
// @Failure      404  {object}  apierror.Error
// @Router       /mcp-access/clients/{id} [delete]
func (h *MCPClientsHandler) Delete(w http.ResponseWriter, r *http.Request) {
	tenantID, userID, ok := h.caller(r)
	if !ok {
		apierror.Unauthorized("Invalid credentials").WriteJSON(w)
		return
	}
	id, err := shared.IDFromString(chi.URLParam(r, "id"))
	if err != nil {
		apierror.NotFound("Client").WriteJSON(w)
		return
	}
	err = h.svc.DeleteOrganizationClient(r.Context(), tenantID, userID, id, oauthActor(r))
	switch {
	case err == nil:
		w.WriteHeader(http.StatusNoContent)
	case errors.Is(err, mcpoauth.ErrNotFound):
		apierror.NotFound("Client").WriteJSON(w)
	default:
		h.log.Error("delete organization mcp client", "error", logger.SanitizeError(err))
		apierror.InternalServerError("failed to delete the client").WriteJSON(w)
	}
}

// Register serves POST /oauth/register (RFC 7591), only when the operator
// enabled dynamic registration; otherwise 404.
func (h *MCPClientsHandler) Register(w http.ResponseWriter, r *http.Request) {
	if !h.svc.DynamicRegistrationEnabled() {
		http.NotFound(w, r)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxOAuthFormBytes)
	var req mcpoauthapp.DynamicRegistration
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeOAuthError(w, http.StatusBadRequest, &mcpoauthapp.OAuthError{Code: "invalid_client_metadata", Description: "the body must be a JSON object"})
		return
	}
	out, oerr := h.svc.RegisterDynamicClient(r.Context(), req)
	if oerr != nil {
		status := http.StatusBadRequest
		if oerr.Code == "server_error" {
			status = http.StatusInternalServerError
		}
		writeOAuthError(w, status, oerr)
		return
	}
	noStoreJSON(w, http.StatusCreated, out)
}
