package handler

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/openctemio/api/internal/infra/http/middleware"
	"github.com/openctemio/api/pkg/apierror"
	"github.com/openctemio/api/pkg/domain/accesscontrol"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
)

// AssetOwnerHandler handles asset ownership HTTP requests.
type AssetOwnerHandler struct {
	repo   accesscontrol.Repository
	logger *logger.Logger
}

// NewAssetOwnerHandler creates a new asset owner handler.
func NewAssetOwnerHandler(repo accesscontrol.Repository, log *logger.Logger) *AssetOwnerHandler {
	return &AssetOwnerHandler{
		repo:   repo,
		logger: log,
	}
}

// AddAssetOwnerRequest represents the request to add an owner to an asset.
type AddAssetOwnerRequest struct {
	UserID        *string `json:"user_id"`
	GroupID       *string `json:"group_id"`
	OwnershipType string  `json:"ownership_type" validate:"required"`
}

// AssetOwnerResponse represents an asset owner in API responses.
type AssetOwnerResponse struct {
	ID             string    `json:"id"`
	UserID         *string   `json:"user_id,omitempty"`
	UserName       *string   `json:"user_name,omitempty"`
	UserEmail      *string   `json:"user_email,omitempty"`
	GroupID        *string   `json:"group_id,omitempty"`
	GroupName      *string   `json:"group_name,omitempty"`
	OwnershipType  string    `json:"ownership_type"`
	AssignedAt     time.Time `json:"assigned_at"`
	AssignedByName *string   `json:"assigned_by_name,omitempty"`
}

// UpdateAssetOwnerRequest represents the request to update an owner's type.
type UpdateAssetOwnerRequest struct {
	OwnershipType string `json:"ownership_type" validate:"required"`
}

// ListOwners handles GET /api/v1/assets/{id}/owners
func (h *AssetOwnerHandler) ListOwners(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())
	assetID := r.PathValue("id")
	if assetID == "" {
		apierror.BadRequest("Asset ID is required").WriteJSON(w)
		return
	}

	parsedTenantID, err := shared.IDFromString(tenantID)
	if err != nil {
		apierror.BadRequest("Invalid tenant ID").WriteJSON(w)
		return
	}

	parsedAssetID, err := shared.IDFromString(assetID)
	if err != nil {
		apierror.BadRequest("Invalid asset ID").WriteJSON(w)
		return
	}

	owners, err := h.repo.ListAssetOwnersWithNames(r.Context(), parsedTenantID, parsedAssetID)
	if err != nil {
		h.logger.Error("failed to list asset owners", "error", err)
		apierror.InternalError(err).WriteJSON(w)
		return
	}

	data := make([]AssetOwnerResponse, 0, len(owners))
	for _, o := range owners {
		resp := AssetOwnerResponse{
			ID:            o.ID().String(),
			OwnershipType: o.OwnershipType().String(),
			AssignedAt:    o.AssignedAt(),
		}

		if o.UserID() != nil {
			uid := o.UserID().String()
			resp.UserID = &uid
			if o.UserName != "" {
				resp.UserName = &o.UserName
			}
			if o.UserEmail != "" {
				resp.UserEmail = &o.UserEmail
			}
		}

		if o.GroupID() != nil {
			gid := o.GroupID().String()
			resp.GroupID = &gid
			if o.GroupName != "" {
				resp.GroupName = &o.GroupName
			}
		}

		if o.AssignedByName != "" {
			resp.AssignedByName = &o.AssignedByName
		}

		data = append(data, resp)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"data":  data,
		"total": len(data),
	})
}

// AddOwner handles POST /api/v1/assets/{id}/owners
func (h *AssetOwnerHandler) AddOwner(w http.ResponseWriter, r *http.Request) {
	assetID := r.PathValue("id")
	if assetID == "" {
		apierror.BadRequest("Asset ID is required").WriteJSON(w)
		return
	}

	var req AddAssetOwnerRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}

	// Validate: must have either user_id or group_id
	if req.UserID == nil && req.GroupID == nil {
		apierror.BadRequest("Either user_id or group_id is required").WriteJSON(w)
		return
	}
	if req.UserID != nil && req.GroupID != nil {
		apierror.BadRequest("Cannot specify both user_id and group_id").WriteJSON(w)
		return
	}

	// Validate ownership type
	ownershipType := accesscontrol.OwnershipType(req.OwnershipType)
	if !ownershipType.IsValid() {
		apierror.BadRequest("Invalid ownership_type. Must be one of: primary, secondary, stakeholder, informed, regulatory").WriteJSON(w)
		return
	}

	parsedAssetID, err := shared.IDFromString(assetID)
	if err != nil {
		apierror.BadRequest("Invalid asset ID").WriteJSON(w)
		return
	}

	// Get acting user for assigned_by
	actingUserID := middleware.GetUserID(r.Context())
	var assignedBy *shared.ID
	if actingUserID != "" {
		uid, err := shared.IDFromString(actingUserID)
		if err == nil {
			assignedBy = &uid
		}
	}

	var ao *accesscontrol.AssetOwner

	if req.UserID != nil {
		userID, err := shared.IDFromString(*req.UserID)
		if err != nil {
			apierror.BadRequest("Invalid user_id").WriteJSON(w)
			return
		}
		ao, err = accesscontrol.NewAssetOwnerForUser(parsedAssetID, userID, ownershipType, assignedBy)
		if err != nil {
			apierror.BadRequest(err.Error()).WriteJSON(w)
			return
		}
	} else {
		groupID, err := shared.IDFromString(*req.GroupID)
		if err != nil {
			apierror.BadRequest("Invalid group_id").WriteJSON(w)
			return
		}
		ao, err = accesscontrol.NewAssetOwnerForGroup(parsedAssetID, groupID, ownershipType, assignedBy)
		if err != nil {
			apierror.BadRequest(err.Error()).WriteJSON(w)
			return
		}
	}

	if err := h.repo.CreateAssetOwner(r.Context(), ao); err != nil {
		if errors.Is(err, accesscontrol.ErrAssetOwnerExists) {
			apierror.Conflict("This owner is already assigned to the asset").WriteJSON(w)
			return
		}
		h.logger.Error("failed to create asset owner", "error", err)
		apierror.InternalError(err).WriteJSON(w)
		return
	}

	// Refresh access for direct user ownership
	if req.UserID != nil {
		userID, _ := shared.IDFromString(*req.UserID)
		if refreshErr := h.repo.RefreshAccessForDirectOwnerAdd(r.Context(), parsedAssetID, userID, req.OwnershipType); refreshErr != nil {
			h.logger.Warn("failed to refresh access for direct owner add", "error", refreshErr)
		}
	}

	// Refresh access for group ownership
	if req.GroupID != nil {
		groupID, _ := shared.IDFromString(*req.GroupID)
		if refreshErr := h.repo.RefreshAccessForAssetAssign(r.Context(), groupID, parsedAssetID, req.OwnershipType); refreshErr != nil {
			h.logger.Warn("failed to refresh access for group owner add", "error", refreshErr)
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"id":             ao.ID().String(),
		"ownership_type": ao.OwnershipType().String(),
	})
}

// UpdateOwner handles PUT /api/v1/assets/{id}/owners/{ownerID}
func (h *AssetOwnerHandler) UpdateOwner(w http.ResponseWriter, r *http.Request) {
	ownerID := r.PathValue("ownerID")
	if ownerID == "" {
		apierror.BadRequest("Owner ID is required").WriteJSON(w)
		return
	}

	var req UpdateAssetOwnerRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}

	ownershipType := accesscontrol.OwnershipType(req.OwnershipType)
	if !ownershipType.IsValid() {
		apierror.BadRequest("Invalid ownership_type").WriteJSON(w)
		return
	}

	parsedOwnerID, err := shared.IDFromString(ownerID)
	if err != nil {
		apierror.BadRequest("Invalid owner ID").WriteJSON(w)
		return
	}

	ao, err := h.repo.GetAssetOwnerByID(r.Context(), parsedOwnerID)
	if err != nil {
		if errors.Is(err, accesscontrol.ErrAssetOwnerNotFound) {
			apierror.NotFound("Asset owner").WriteJSON(w)
			return
		}
		h.logger.Error("failed to get asset owner", "error", err)
		apierror.InternalError(err).WriteJSON(w)
		return
	}

	if err := ao.UpdateOwnershipType(ownershipType); err != nil {
		apierror.BadRequest(err.Error()).WriteJSON(w)
		return
	}

	if err := h.repo.UpdateAssetOwner(r.Context(), ao); err != nil {
		h.logger.Error("failed to update asset owner", "error", err)
		apierror.InternalError(err).WriteJSON(w)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// RemoveOwner handles DELETE /api/v1/assets/{id}/owners/{ownerID}
func (h *AssetOwnerHandler) RemoveOwner(w http.ResponseWriter, r *http.Request) {
	ownerID := r.PathValue("ownerID")
	if ownerID == "" {
		apierror.BadRequest("Owner ID is required").WriteJSON(w)
		return
	}

	parsedOwnerID, err := shared.IDFromString(ownerID)
	if err != nil {
		apierror.BadRequest("Invalid owner ID").WriteJSON(w)
		return
	}

	// Get owner first to know if it's a user or group (for access refresh)
	ao, err := h.repo.GetAssetOwnerByID(r.Context(), parsedOwnerID)
	if err != nil {
		if errors.Is(err, accesscontrol.ErrAssetOwnerNotFound) {
			apierror.NotFound("Asset owner").WriteJSON(w)
			return
		}
		h.logger.Error("failed to get asset owner", "error", err)
		apierror.InternalError(err).WriteJSON(w)
		return
	}

	if err := h.repo.DeleteAssetOwnerByID(r.Context(), parsedOwnerID); err != nil {
		if errors.Is(err, accesscontrol.ErrAssetOwnerNotFound) {
			apierror.NotFound("Asset owner").WriteJSON(w)
			return
		}
		h.logger.Error("failed to delete asset owner", "error", err)
		apierror.InternalError(err).WriteJSON(w)
		return
	}

	// Refresh access after removal
	if ao.UserID() != nil {
		if refreshErr := h.repo.RefreshAccessForDirectOwnerRemove(r.Context(), ao.AssetID(), *ao.UserID()); refreshErr != nil {
			h.logger.Warn("failed to refresh access for direct owner remove", "error", refreshErr)
		}
	}
	if ao.GroupID() != nil {
		if refreshErr := h.repo.RefreshAccessForAssetUnassign(r.Context(), *ao.GroupID(), ao.AssetID()); refreshErr != nil {
			h.logger.Warn("failed to refresh access for group owner remove", "error", refreshErr)
		}
	}

	w.WriteHeader(http.StatusNoContent)
}
