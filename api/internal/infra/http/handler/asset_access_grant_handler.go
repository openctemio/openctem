package handler

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/accesscontrol"
	auditdom "github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Explicit per-user data-scope grants on an asset. Being an owner of an asset
// does not let a user see it; a group assignment or one of these grants does.
// The routes are gated with team:groups:read / team:groups:write, the
// permissions that already manage group data scope.

// AssetAccessGrantResponse is one explicit access grant.
type AssetAccessGrantResponse struct {
	ID            string    `json:"id"`
	UserID        string    `json:"user_id"`
	UserName      string    `json:"user_name,omitempty"`
	UserEmail     string    `json:"user_email,omitempty"`
	Source        string    `json:"source" enums:"manual,migration"`
	GrantedByName string    `json:"granted_by_name,omitempty"`
	GrantedAt     time.Time `json:"granted_at"`
}

// AssetAccessGrantListResponse lists an asset's explicit access grants.
type AssetAccessGrantListResponse struct {
	Data  []AssetAccessGrantResponse `json:"data"`
	Total int                        `json:"total"`
}

// CreateAssetAccessGrantRequest grants one member access to the asset.
type CreateAssetAccessGrantRequest struct {
	UserID string `json:"user_id" validate:"required,uuid"`
}

func toAssetAccessGrantResponse(g *accesscontrol.AssetAccessGrant) AssetAccessGrantResponse {
	return AssetAccessGrantResponse{
		ID:            g.ID.String(),
		UserID:        g.UserID.String(),
		UserName:      g.UserName,
		UserEmail:     g.UserEmail,
		Source:        g.Source,
		GrantedByName: g.GrantedByName,
		GrantedAt:     g.GrantedAt,
	}
}

func (h *AssetOwnerHandler) auditGrant(r *http.Request, action auditdom.Action, assetID shared.ID, g *accesscontrol.AssetAccessGrant, msg string) {
	if h.auditService == nil {
		return
	}
	actx := auditapp.AuditContext{
		TenantID:   middleware.GetTenantID(r.Context()),
		ActorID:    middleware.GetUserID(r.Context()),
		ActorEmail: auditActorEmail(r.Context()),
		ActorIP:    getClientIP(r),
		UserAgent:  r.UserAgent(),
		RequestID:  r.Header.Get("X-Request-ID"),
	}
	event := auditapp.NewSuccessEvent(action, auditdom.ResourceTypeAsset, assetID.String()).
		WithMessage(msg).
		WithMetadata("user_id", g.UserID.String()).
		WithMetadata("grant_id", g.ID.String()).
		WithSeverity(auditdom.SeverityMedium)
	if err := h.auditService.LogEvent(r.Context(), actx, event); err != nil {
		h.logger.Warn("failed to audit access grant change", "error", err)
	}
}

// ListAccessGrants handles GET /api/v1/assets/{id}/access-grants
// @Summary      List an asset's access grants
// @Description  Lists the users given explicit data-scope access to the asset. Owners are not listed: being an owner gives no access.
// @Tags         Assets
// @Produce      json
// @Security     BearerAuth
// @Param        id   path      string  true  "Asset ID"
// @Success      200  {object}  AssetAccessGrantListResponse
// @Failure      400  {object}  map[string]string
// @Failure      401  {object}  map[string]string
// @Failure      403  {object}  map[string]string
// @Failure      404  {object}  map[string]string
// @Router       /assets/{id}/access-grants [get]
func (h *AssetOwnerHandler) ListAccessGrants(w http.ResponseWriter, r *http.Request) {
	assetID, ok := h.requireAssetInTenant(w, r, r.PathValue("id"))
	if !ok {
		return
	}
	tenantID, err := shared.IDFromString(middleware.MustGetTenantID(r.Context()))
	if err != nil {
		apierror.BadRequest("Invalid tenant ID").WriteJSON(w)
		return
	}
	grants, err := h.repo.ListAssetAccessGrants(r.Context(), tenantID, assetID)
	if err != nil {
		h.logger.Error("failed to list access grants", "error", err)
		apierror.InternalServerError("Failed to list access grants").WriteJSON(w)
		return
	}
	resp := AssetAccessGrantListResponse{Data: make([]AssetAccessGrantResponse, 0, len(grants)), Total: len(grants)}
	for _, g := range grants {
		resp.Data = append(resp.Data, toAssetAccessGrantResponse(g))
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

// CreateAccessGrant handles POST /api/v1/assets/{id}/access-grants
// @Summary      Grant a member access to an asset
// @Description  Puts the asset in the user's data scope. The user must be a member of the organization. Audited.
// @Tags         Assets
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        id    path      string                         true  "Asset ID"
// @Param        body  body      CreateAssetAccessGrantRequest  true  "User to grant"
// @Success      201   {object}  AssetAccessGrantResponse
// @Failure      400   {object}  map[string]string
// @Failure      401   {object}  map[string]string
// @Failure      403   {object}  map[string]string
// @Failure      404   {object}  map[string]string
// @Failure      409   {object}  map[string]string
// @Router       /assets/{id}/access-grants [post]
func (h *AssetOwnerHandler) CreateAccessGrant(w http.ResponseWriter, r *http.Request) {
	assetID, ok := h.requireAssetInTenant(w, r, r.PathValue("id"))
	if !ok {
		return
	}
	tenantID, err := shared.IDFromString(middleware.MustGetTenantID(r.Context()))
	if err != nil {
		apierror.BadRequest("Invalid tenant ID").WriteJSON(w)
		return
	}
	var req CreateAssetAccessGrantRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}
	userID, err := shared.IDFromString(req.UserID)
	if err != nil {
		apierror.BadRequest("Invalid user_id").WriteJSON(w)
		return
	}
	var grantedBy *shared.ID
	if actor, err := shared.IDFromString(middleware.GetUserID(r.Context())); err == nil {
		grantedBy = &actor
	}

	g, err := h.repo.CreateAssetAccessGrant(r.Context(), tenantID, assetID, userID, grantedBy)
	if err != nil {
		switch {
		case errors.Is(err, accesscontrol.ErrAccessGrantExists):
			apierror.Conflict("This user already has an access grant for the asset").WriteJSON(w)
		case errors.Is(err, shared.ErrNotFound):
			// Same answer for "no such user" and "user of another tenant".
			apierror.NotFound("User").WriteJSON(w)
		default:
			h.logger.Error("failed to create access grant", "error", err)
			apierror.InternalServerError("Failed to create access grant").WriteJSON(w)
		}
		return
	}
	h.auditGrant(r, auditdom.ActionAssetAccessGranted, assetID, g, "Asset access granted to a user")

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(toAssetAccessGrantResponse(g))
}

// DeleteAccessGrant handles DELETE /api/v1/assets/{id}/access-grants/{grant_id}
// @Summary      Revoke an access grant
// @Description  Removes the asset from the user's data scope unless one of the user's groups still gives access. Audited.
// @Tags         Assets
// @Security     BearerAuth
// @Param        id       path  string  true  "Asset ID"
// @Param        grant_id path  string  true  "Grant ID"
// @Success      204  "No Content"
// @Failure      400  {object}  map[string]string
// @Failure      401  {object}  map[string]string
// @Failure      403  {object}  map[string]string
// @Failure      404  {object}  map[string]string
// @Router       /assets/{id}/access-grants/{grant_id} [delete]
func (h *AssetOwnerHandler) DeleteAccessGrant(w http.ResponseWriter, r *http.Request) {
	assetID, ok := h.requireAssetInTenant(w, r, r.PathValue("id"))
	if !ok {
		return
	}
	tenantID, err := shared.IDFromString(middleware.MustGetTenantID(r.Context()))
	if err != nil {
		apierror.BadRequest("Invalid tenant ID").WriteJSON(w)
		return
	}
	grantID, err := shared.IDFromString(r.PathValue("grant_id"))
	if err != nil {
		apierror.BadRequest("Invalid grant ID").WriteJSON(w)
		return
	}
	g, err := h.repo.DeleteAssetAccessGrant(r.Context(), tenantID, assetID, grantID)
	if err != nil {
		if errors.Is(err, accesscontrol.ErrAccessGrantNotFound) {
			apierror.NotFound("Access grant").WriteJSON(w)
			return
		}
		h.logger.Error("failed to revoke access grant", "error", err)
		apierror.InternalServerError("Failed to revoke access grant").WriteJSON(w)
		return
	}
	h.auditGrant(r, auditdom.ActionAssetAccessRevoked, assetID, g, "Asset access grant revoked")
	w.WriteHeader(http.StatusNoContent)
}
