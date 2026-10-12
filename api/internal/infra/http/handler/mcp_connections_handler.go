package handler

import (
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

// MCPConnectionsHandler serves the connected applications of RFC-062 §12:
// /api/v1/mcp-access/connections (a person's own, and the organization's
// for administrators) and /api/v1/admin/mcp-clients (platform console).
type MCPConnectionsHandler struct {
	svc *mcpoauthapp.Service
	log *logger.Logger
}

// NewMCPConnectionsHandler builds the handler.
func NewMCPConnectionsHandler(svc *mcpoauthapp.Service, log *logger.Logger) *MCPConnectionsHandler {
	return &MCPConnectionsHandler{svc: svc, log: log.With("handler", "mcp-connections")}
}

// MCPConnection is one connected application.
type MCPConnection struct {
	ID         string     `json:"id"`
	ClientName string     `json:"client_name"`
	ClientID   string     `json:"client_id"`
	ClientKind string     `json:"client_kind"`
	ClientHost string     `json:"client_host,omitempty"`
	UserID     string     `json:"user_id"`
	UserName   string     `json:"user_name,omitempty"`
	UserEmail  string     `json:"user_email,omitempty"`
	Scopes     []string   `json:"scopes"`
	CreatedAt  time.Time  `json:"created_at"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
	LastUsedIP string     `json:"last_used_ip,omitempty"`
	ExpiresAt  time.Time  `json:"expires_at"`
}

// MCPConnectionList is a list of connections.
type MCPConnectionList struct {
	Data []MCPConnection `json:"data"`
}

func toMCPConnections(list []mcpoauthapp.ConnectionView, withUser bool) MCPConnectionList {
	out := MCPConnectionList{Data: make([]MCPConnection, 0, len(list))}
	for _, c := range list {
		scopes := make([]string, len(c.Scopes))
		for i, s := range c.Scopes {
			scopes[i] = string(s)
		}
		m := MCPConnection{
			ID: c.ID, ClientName: c.ClientName, ClientID: c.ClientID, ClientKind: string(c.ClientKind),
			ClientHost: c.ClientHost, UserID: c.UserID, Scopes: scopes, CreatedAt: c.CreatedAt,
			LastUsedAt: c.LastUsedAt, LastUsedIP: c.LastUsedIP, ExpiresAt: c.ExpiresAt,
		}
		if withUser {
			m.UserName, m.UserEmail = c.UserName, c.UserEmail
		}
		out.Data = append(out.Data, m)
	}
	return out
}

func (h *MCPConnectionsHandler) caller(r *http.Request) (tenantID, userID shared.ID, ok bool) {
	t, err1 := shared.IDFromString(middleware.GetTenantID(r.Context()))
	u, err2 := shared.IDFromString(middleware.GetUserID(r.Context()))
	return t, u, err1 == nil && err2 == nil
}

func (h *MCPConnectionsHandler) list(w http.ResponseWriter, r *http.Request, mine bool) {
	tenantID, userID, ok := h.caller(r)
	if !ok {
		apierror.Unauthorized("Invalid credentials").WriteJSON(w)
		return
	}
	var only *shared.ID
	if mine {
		only = &userID
	}
	list, err := h.svc.ListConnections(r.Context(), tenantID, only)
	if err != nil {
		h.log.Error("list mcp connections", "error", logger.SanitizeError(err))
		apierror.InternalServerError("failed to list connections").WriteJSON(w)
		return
	}
	writeJSON(w, http.StatusOK, toMCPConnections(list, !mine))
}

func (h *MCPConnectionsHandler) revoke(w http.ResponseWriter, r *http.Request, asAdmin bool) {
	tenantID, userID, ok := h.caller(r)
	if !ok {
		apierror.Unauthorized("Invalid credentials").WriteJSON(w)
		return
	}
	grantID, err := shared.IDFromString(chi.URLParam(r, "id"))
	if err != nil {
		apierror.NotFound("Connection").WriteJSON(w)
		return
	}
	err = h.svc.RevokeConnection(r.Context(), tenantID, grantID, userID, asAdmin, oauthActor(r))
	switch {
	case err == nil:
		w.WriteHeader(http.StatusNoContent)
	case errors.Is(err, mcpoauth.ErrNotFound):
		apierror.NotFound("Connection").WriteJSON(w)
	default:
		h.log.Error("revoke mcp connection", "error", logger.SanitizeError(err))
		apierror.InternalServerError("failed to revoke the connection").WriteJSON(w)
	}
}

// ListMine serves GET /api/v1/mcp-access/my-connections.
// @Summary      List my connected AI applications
// @Description  The caller's active connections in the current organization: which application, what it may read, since when and when it was last used (RFC-062).
// @Tags         MCP
// @Produce      json
// @Security     BearerAuth
// @Success      200  {object}  MCPConnectionList
// @Router       /mcp-access/my-connections [get]
func (h *MCPConnectionsHandler) ListMine(w http.ResponseWriter, r *http.Request) { h.list(w, r, true) }

// RevokeMine serves DELETE /api/v1/mcp-access/my-connections/{id}.
// @Summary      Disconnect one of my AI applications
// @Description  Ends the connection at once: its tokens stop working. Someone else's connection is not found. Audited.
// @Tags         MCP
// @Security     BearerAuth
// @Param        id   path  string  true  "Connection id"
// @Success      204
// @Failure      404  {object}  apierror.Error
// @Router       /mcp-access/my-connections/{id} [delete]
func (h *MCPConnectionsHandler) RevokeMine(w http.ResponseWriter, r *http.Request) {
	h.revoke(w, r, false)
}

// ListAll serves GET /api/v1/mcp-access/connections.
// @Summary      List the organization's connected AI applications
// @Description  Every active connection in the organization, with the person it belongs to. Owners and administrators.
// @Tags         MCP
// @Produce      json
// @Security     BearerAuth
// @Success      200  {object}  MCPConnectionList
// @Router       /mcp-access/connections [get]
func (h *MCPConnectionsHandler) ListAll(w http.ResponseWriter, r *http.Request) { h.list(w, r, false) }

// RevokeAny serves DELETE /api/v1/mcp-access/connections/{id}.
// @Summary      Disconnect an AI application in the organization
// @Description  Ends any connection of the organization at once. Owners and administrators. Audited.
// @Tags         MCP
// @Security     BearerAuth
// @Param        id   path  string  true  "Connection id"
// @Success      204
// @Failure      404  {object}  apierror.Error
// @Router       /mcp-access/connections/{id} [delete]
func (h *MCPConnectionsHandler) RevokeAny(w http.ResponseWriter, r *http.Request) {
	h.revoke(w, r, true)
}

// AdminMCPClient is a client as the platform console lists it.
type AdminMCPClient struct {
	ID                string     `json:"id"`
	ClientID          string     `json:"client_id"`
	Name              string     `json:"name"`
	Kind              string     `json:"kind"`
	Host              string     `json:"host,omitempty"`
	RedirectURIs      []string   `json:"redirect_uris"`
	Blocked           bool       `json:"blocked"`
	CreatedAt         time.Time  `json:"created_at"`
	ActiveConnections int        `json:"active_connections"`
	Organizations     int        `json:"organizations"`
	LastUsedAt        *time.Time `json:"last_used_at,omitempty"`
}

// AdminMCPClientList is the console's client list.
type AdminMCPClientList struct {
	Data []AdminMCPClient `json:"data"`
}

// AdminListClients serves GET /api/v1/admin/mcp-clients.
// @Summary      List AI applications (MCP clients)
// @Description  Every MCP client known to the platform with its active connections and how many organizations use it. Counts only; no organization data (RFC-062).
// @Tags         Admin
// @Produce      json
// @Success      200  {object}  AdminMCPClientList
// @Router       /admin/mcp-clients [get]
func (h *MCPConnectionsHandler) AdminListClients(w http.ResponseWriter, r *http.Request) {
	list, err := h.svc.ListAllClients(r.Context())
	if err != nil {
		h.log.Error("list mcp clients", "error", logger.SanitizeError(err))
		apierror.InternalServerError("failed to list clients").WriteJSON(w)
		return
	}
	out := AdminMCPClientList{Data: make([]AdminMCPClient, 0, len(list))}
	for _, u := range list {
		out.Data = append(out.Data, AdminMCPClient{
			ID: u.Client.ID.String(), ClientID: u.Client.ClientID, Name: u.Client.Name, Kind: string(u.Client.Kind),
			Host: mcpoauthapp.ClientHost(u.Client), RedirectURIs: u.Client.RedirectURIs, Blocked: u.Client.BlockedAt != nil,
			CreatedAt: u.Client.CreatedAt, ActiveConnections: u.ActiveConnections, Organizations: u.Organizations, LastUsedAt: u.LastUsedAt,
		})
	}
	writeJSON(w, http.StatusOK, out)
}

func (h *MCPConnectionsHandler) setBlocked(w http.ResponseWriter, r *http.Request, blocked bool) {
	id, err := shared.IDFromString(chi.URLParam(r, "id"))
	if err != nil {
		apierror.NotFound("Client").WriteJSON(w)
		return
	}
	err = h.svc.SetClientBlocked(r.Context(), id, blocked)
	switch {
	case err == nil:
		w.WriteHeader(http.StatusNoContent)
	case errors.Is(err, mcpoauth.ErrNotFound):
		apierror.NotFound("Client").WriteJSON(w)
	default:
		h.log.Error("block mcp client", "error", logger.SanitizeError(err))
		apierror.InternalServerError("failed to update the client").WriteJSON(w)
	}
}

// AdminBlockClient serves POST /api/v1/admin/mcp-clients/{id}/block.
// @Summary      Block an AI application everywhere
// @Description  The client can no longer be authorized in any organization and its existing tokens stop working. Audited.
// @Tags         Admin
// @Param        id   path  string  true  "Client id"
// @Success      204
// @Failure      404  {object}  apierror.Error
// @Router       /admin/mcp-clients/{id}/block [post]
func (h *MCPConnectionsHandler) AdminBlockClient(w http.ResponseWriter, r *http.Request) {
	h.setBlocked(w, r, true)
}

// AdminUnblockClient serves POST /api/v1/admin/mcp-clients/{id}/unblock.
// @Summary      Unblock an AI application
// @Description  Lifts a platform block. Revoked connections stay revoked. Audited.
// @Tags         Admin
// @Param        id   path  string  true  "Client id"
// @Success      204
// @Failure      404  {object}  apierror.Error
// @Router       /admin/mcp-clients/{id}/unblock [post]
func (h *MCPConnectionsHandler) AdminUnblockClient(w http.ResponseWriter, r *http.Request) {
	h.setBlocked(w, r, false)
}
