package handler

import (
	"errors"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	mcpoauthapp "github.com/openctemio/openctem/api/internal/app/mcpoauth"
	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/mcpoauth"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// Access requests to approve an AI application publisher
// (docs/architecture/mcp-authorization.md, "Access requests"), served on
// /api/v1/mcp-access/requests for the organization's administrators.

// MCPAccessRequestCreated answers a member's request.
type MCPAccessRequestCreated struct {
	ID     string `json:"id"`
	Status string `json:"status"`
}

// MCPAccessRequest is a pending request to approve a publisher.
type MCPAccessRequest struct {
	ID         string `json:"id"`
	ClientHost string `json:"client_host"`
	ClientName string `json:"client_name"`
	ClientID   string `json:"client_id"`
	// Scopes the application asked for.
	Scopes []string `json:"scopes"`
	// RequesterName is the first member who asked (empty once deleted).
	RequesterName string `json:"requester_name"`
	// RequestCount is how many times members asked.
	RequestCount int       `json:"request_count"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// MCPAccessRequestList lists pending requests.
type MCPAccessRequestList struct {
	Data []MCPAccessRequest `json:"data"`
}

// ListAccessRequests serves GET /api/v1/mcp-access/requests.
// @Summary      List requests to approve AI applications
// @Description  The organization's waiting requests from members to approve an AI application's publisher: the application, its publisher host, the access it asked for, the first requester's name and how many times members asked. Requests whose publisher is already approved are left out.
// @Tags         MCP
// @Produce      json
// @Security     BearerAuth
// @Success      200  {object}  MCPAccessRequestList
// @Router       /mcp-access/requests [get]
func (h *MCPClientsHandler) ListAccessRequests(w http.ResponseWriter, r *http.Request) {
	tenantID, _, ok := h.caller(r)
	if !ok {
		apierror.Unauthorized("Invalid credentials").WriteJSON(w)
		return
	}
	list, err := h.svc.ListAccessRequests(r.Context(), tenantID)
	if err != nil {
		h.log.Error("list mcp access requests", "error", logger.SanitizeError(err))
		apierror.InternalServerError("failed to list requests").WriteJSON(w)
		return
	}
	out := MCPAccessRequestList{Data: make([]MCPAccessRequest, 0, len(list))}
	for _, a := range list {
		scopes := make([]string, 0, len(a.Scopes))
		for _, sc := range a.Scopes {
			scopes = append(scopes, string(sc))
		}
		out.Data = append(out.Data, MCPAccessRequest{
			ID: a.ID.String(), ClientHost: a.ClientHost, ClientName: a.ClientName, ClientID: a.ClientID, Scopes: scopes,
			RequesterName: a.RequesterName, RequestCount: a.RequestCount, CreatedAt: a.CreatedAt, UpdatedAt: a.UpdatedAt,
		})
	}
	writeJSON(w, http.StatusOK, out)
}

// ApproveAccessRequest serves POST /api/v1/mcp-access/requests/{id}/approve.
// @Summary      Approve an AI application's publisher
// @Description  Adds the request's publisher host to the organization's approved publishers, so members can connect applications published there (each person still approves what it may do). Closes the request and notifies the requester. Needs a recent sign-in. Audited.
// @Tags         MCP
// @Security     BearerAuth
// @Param        id   path  string  true  "Request id"
// @Success      204
// @Failure      400  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Router       /mcp-access/requests/{id}/approve [post]
func (h *MCPClientsHandler) ApproveAccessRequest(w http.ResponseWriter, r *http.Request) {
	h.decideAccessRequest(w, r, true)
}

// DenyAccessRequest serves POST /api/v1/mcp-access/requests/{id}/deny.
// @Summary      Decline a request to approve an AI application
// @Description  Closes the request without changing the policy and notifies the requester. Audited.
// @Tags         MCP
// @Security     BearerAuth
// @Param        id   path  string  true  "Request id"
// @Success      204
// @Failure      404  {object}  apierror.Error
// @Router       /mcp-access/requests/{id}/deny [post]
func (h *MCPClientsHandler) DenyAccessRequest(w http.ResponseWriter, r *http.Request) {
	h.decideAccessRequest(w, r, false)
}

func (h *MCPClientsHandler) decideAccessRequest(w http.ResponseWriter, r *http.Request, approve bool) {
	tenantID, userID, ok := h.caller(r)
	if !ok {
		apierror.Unauthorized("Invalid credentials").WriteJSON(w)
		return
	}
	id, err := shared.IDFromString(chi.URLParam(r, "id"))
	if err != nil {
		apierror.NotFound("Request").WriteJSON(w)
		return
	}
	if approve {
		err = h.svc.ApproveAccessRequest(r.Context(), tenantID, id, userID, oauthActor(r))
	} else {
		err = h.svc.DenyAccessRequest(r.Context(), tenantID, id, userID, oauthActor(r))
	}
	switch {
	case err == nil:
		w.WriteHeader(http.StatusNoContent)
	case errors.Is(err, mcpoauth.ErrNotFound), errors.Is(err, mcpoauthapp.ErrAccessRequestsUnavailable):
		apierror.NotFound("Request").WriteJSON(w)
	case errors.Is(err, shared.ErrValidation):
		apierror.BadRequest(easmValidationMessage(err)).WriteJSON(w)
	default:
		h.log.Error("decide mcp access request", "error", logger.SanitizeError(err))
		apierror.InternalServerError("failed to decide the request").WriteJSON(w)
	}
}
