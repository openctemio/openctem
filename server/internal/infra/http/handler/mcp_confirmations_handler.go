package handler

import (
	"errors"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/mcpoauth"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// MCPConfirmation is a write action an AI application asked to run, as the
// confirmation page shows it (RFC-062 §10).
type MCPConfirmation struct {
	ID         string    `json:"id"`
	Tool       string    `json:"tool"`
	Summary    string    `json:"summary"`
	ClientName string    `json:"client_name"`
	Status     string    `json:"status"`
	Expired    bool      `json:"expired"`
	ExpiresAt  time.Time `json:"expires_at"`
}

func (h *MCPConnectionsHandler) confirmationCaller(r *http.Request) (tenantID, userID, id shared.ID, ok bool) {
	t, u, ok := h.caller(r)
	if !ok {
		return t, u, id, false
	}
	id, err := shared.IDFromString(chi.URLParam(r, "id"))
	return t, u, id, err == nil
}

// GetConfirmation serves GET /api/v1/mcp-access/confirmations/{id}.
// @Summary      Read a write action waiting for your confirmation
// @Description  What an AI application asked to change, described by the server. Only the person the connection belongs to sees it; for anyone else it is not found.
// @Tags         MCP
// @Produce      json
// @Security     BearerAuth
// @Param        id   path      string  true  "Confirmation id"
// @Success      200  {object}  MCPConfirmation
// @Failure      404  {object}  apierror.Error
// @Router       /mcp-access/confirmations/{id} [get]
func (h *MCPConnectionsHandler) GetConfirmation(w http.ResponseWriter, r *http.Request) {
	tenantID, userID, id, ok := h.confirmationCaller(r)
	if !ok {
		apierror.NotFound("Confirmation").WriteJSON(w)
		return
	}
	v, err := h.svc.GetConfirmation(r.Context(), tenantID, userID, id)
	if err != nil {
		h.confirmationError(w, err)
		return
	}
	noStoreJSON(w, http.StatusOK, MCPConfirmation{
		ID: v.ID, Tool: v.Tool, Summary: v.Summary, ClientName: v.ClientName, Status: string(v.Status),
		Expired: v.Expired, ExpiresAt: v.ExpiresAt,
	})
}

func (h *MCPConnectionsHandler) decide(w http.ResponseWriter, r *http.Request, approve bool) {
	tenantID, userID, id, ok := h.confirmationCaller(r)
	if !ok {
		apierror.NotFound("Confirmation").WriteJSON(w)
		return
	}
	if err := h.svc.DecideConfirmation(r.Context(), tenantID, userID, id, approve, oauthActor(r)); err != nil {
		h.confirmationError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ApproveConfirmation serves POST /api/v1/mcp-access/confirmations/{id}/approve.
// @Summary      Confirm a write action
// @Description  Allows the AI application to run this exact action once, within five minutes. Audited.
// @Tags         MCP
// @Security     BearerAuth
// @Param        id   path  string  true  "Confirmation id"
// @Success      204
// @Failure      404  {object}  apierror.Error
// @Router       /mcp-access/confirmations/{id}/approve [post]
func (h *MCPConnectionsHandler) ApproveConfirmation(w http.ResponseWriter, r *http.Request) {
	h.decide(w, r, true)
}

// DenyConfirmation serves POST /api/v1/mcp-access/confirmations/{id}/deny.
// @Summary      Refuse a write action
// @Description  The action will not run. Audited.
// @Tags         MCP
// @Security     BearerAuth
// @Param        id   path  string  true  "Confirmation id"
// @Success      204
// @Failure      404  {object}  apierror.Error
// @Router       /mcp-access/confirmations/{id}/deny [post]
func (h *MCPConnectionsHandler) DenyConfirmation(w http.ResponseWriter, r *http.Request) {
	h.decide(w, r, false)
}

func (h *MCPConnectionsHandler) confirmationError(w http.ResponseWriter, err error) {
	if errors.Is(err, mcpoauth.ErrNotFound) {
		apierror.NotFound("Confirmation").WriteJSON(w)
		return
	}
	h.log.Error("mcp confirmation", "error", logger.SanitizeError(err))
	apierror.InternalServerError("Could not complete the request").WriteJSON(w)
}
